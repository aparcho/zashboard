#!/usr/bin/env python3
"""Zashboard 采样统计服务；仅使用 Python 标准库。"""
import argparse
from datetime import datetime, timedelta, timezone
import re
import hmac
import ipaddress
import json
import os
from pathlib import Path
import signal
import sqlite3
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen, build_opener, ProxyHandler
from uuid import uuid4

MONTH_ZONE = timezone(timedelta(hours=8))

def month_key(at=None):
    return datetime.fromtimestamp(time.time() if at is None else at, MONTH_ZONE).strftime('%Y-%m')

def month_start(month):
    if not re.fullmatch(r'\d{4}-(?:0[1-9]|1[0-2])', month):
        raise ValueError('月份格式无效')
    return datetime.strptime(month, '%Y-%m').replace(tzinfo=MONTH_ZONE).timestamp()

UNKNOWN = '未映射'
DIMENSIONS = {'device': 'device', 'source_ip': 'source_ip', 'policy': 'policy',
              'node': 'node', 'entry_vps': 'entry_vps', 'exit_vps': 'exit_vps',
              'target_ip': 'target_ip', 'host': 'host'}


def ip(value):
    try:
        address = ipaddress.ip_address(str(value).split('%')[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(address)
    except ValueError:
        raise ValueError('请输入有效的 IPv4 或 IPv6 地址') from None


def text(value, limit=256):
    if not isinstance(value, str) or len(value) > limit or '\x00' in value:
        raise ValueError('文本格式或长度不正确')
    return value.strip()


class Store:
    def __init__(self, path, retention_days=90):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.retention = retention_days
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bindings(ip TEXT NOT NULL, device TEXT NOT NULL REFERENCES devices(id),
          since REAL NOT NULL, until REAL, PRIMARY KEY(ip,since));
        CREATE UNIQUE INDEX IF NOT EXISTS active_binding ON bindings(ip) WHERE until IS NULL;
        CREATE TABLE IF NOT EXISTS nodes(node TEXT PRIMARY KEY, entry_vps TEXT NOT NULL, exit_vps TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, upload INTEGER NOT NULL, download INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS buckets(minute INTEGER NOT NULL, device TEXT NOT NULL,
          source_ip TEXT NOT NULL, policy TEXT NOT NULL, node TEXT NOT NULL,
          entry_vps TEXT NOT NULL, exit_vps TEXT NOT NULL, target_ip TEXT NOT NULL, host TEXT NOT NULL,
          upload INTEGER NOT NULL, download INTEGER NOT NULL,
          PRIMARY KEY(minute,device,source_ip,policy,node,entry_vps,exit_vps,target_ip,host));
        CREATE TABLE IF NOT EXISTS coverage(minute INTEGER PRIMARY KEY, upload INTEGER NOT NULL,
          download INTEGER NOT NULL, observed_upload INTEGER NOT NULL, observed_download INTEGER NOT NULL,
          samples INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS events(at REAL NOT NULL, kind TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS chain_totals(name TEXT PRIMARY KEY, upload INTEGER NOT NULL,
          download INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS chain_monthly(month TEXT NOT NULL, name TEXT NOT NULL,
          upload INTEGER NOT NULL, download INTEGER NOT NULL, PRIMARY KEY(month,name));
        CREATE TABLE IF NOT EXISTS source_monthly(month TEXT NOT NULL, device TEXT NOT NULL,
          source_ip TEXT NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL,
          PRIMARY KEY(month,device,source_ip));
        CREATE TABLE IF NOT EXISTS device_origins(device TEXT PRIMARY KEY, origin TEXT NOT NULL);
        PRAGMA user_version=3;
        ''')

        with self.db:
            if not self.meta('monthly_migrated'):
                # Lifetime chain totals are exact only when the entire interval is in one month.
                since = self.meta('chain_since')
                checkpoint = self.meta('checkpoint')
                if since is not None and checkpoint and month_key(since) == month_key(checkpoint['at']):
                    self.db.execute('INSERT INTO chain_monthly SELECT ?,name,upload,download FROM chain_totals', (month_key(since),))
                self.db.execute("""INSERT INTO source_monthly SELECT strftime('%Y-%m',minute,'unixepoch','+8 hours'),
                    device,source_ip,SUM(upload),SUM(download) FROM buckets GROUP BY 1,2,3""")
                self.set_meta('monthly_migrated', True)

    def meta(self, key, default=None):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value)))

    def sample(self, payload, policies=None, now=None, interval=1):
        now = time.time() if now is None else now
        # Reject malformed samples before changing any checkpoints.
        for key in ('uploadTotal', 'downloadTotal'):
            if type(payload.get(key)) is not int or payload[key] < 0:
                raise ValueError('连接总计数无效')
        connections = payload.get('connections')
        if not isinstance(connections, list):
            raise ValueError('连接数组无效')
        for c in connections:
            if not isinstance(c.get('id'), str) or any(type(c.get(k)) is not int or c[k] < 0 for k in ('upload', 'download')):
                raise ValueError('连接计数无效')
        with self.lock, self.db:
            if self.meta('chain_since') is None:
                self.set_meta('chain_since', now)
            previous = self.meta('checkpoint')
            cold = previous is None
            gap = previous is not None and (now - previous['at'] > max(interval * 3, 5) or now < previous['at'])
            reset = previous is not None and any(payload[k] < previous[k] for k in ('uploadTotal', 'downloadTotal'))
            recovery = bool(self.meta('interrupted', False))
            baseline = cold or gap or reset or recovery
            if baseline:
                self.db.execute('INSERT INTO events VALUES (?,?)', (now, 'baseline' if cold else 'reset' if reset else 'gap'))
            snapshots = {r['id']: r for r in self.db.execute('SELECT * FROM snapshots')}
            bindings = {r['ip']: r['device'] for r in self.db.execute('SELECT * FROM bindings WHERE until IS NULL')}
            nodes = {r['node']: r for r in self.db.execute('SELECT * FROM nodes')}
            minute = int(now // 60) * 60
            observed_up = observed_down = 0
            seen = set()
            for c in connections:
                if c['id'] in seen:
                    continue
                seen.add(c['id'])
                old = snapshots.get(c['id'])
                up = down = 0
                if not baseline:
                    up = max(0, c['upload'] - old['upload']) if old else c['upload']
                    down = max(0, c['download'] - old['download']) if old else c['download']
                observed_up += up
                observed_down += down
                if up or down:
                    m = c.get('metadata') or {}
                    try:
                        source = ip(m.get('sourceIP', ''))
                    except ValueError:
                        source = str(m.get('sourceIP') or '本机/未知')[:128]
                    chain = c.get('chains') or []
                    # Each connection contributes once to every actual chain member.
                    # Nested groups overlap; never sum these counters into global totals.
                    for member in set(str(n) for n in chain if isinstance(n, str) and n):
                        self.db.execute('''INSERT INTO chain_totals VALUES (?,?,?) ON CONFLICT(name)
                          DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''',
                                        (member, up, down))
                        self.db.execute('''INSERT INTO chain_monthly VALUES (?,?,?,?) ON CONFLICT(month,name)
                          DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''',
                                        (month_key(now), member, up, down))
                    node = str(chain[0]) if chain else '未知节点'
                    policy = (policies or {}).get((c.get('rule'), c.get('rulePayload')))
                    policy = policy or (str(chain[-1]) if chain else str(c.get('rule') or '未知策略'))
                    mapping = nodes.get(node)
                    direct = node.upper() in ('DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE')
                    entry = mapping['entry_vps'] if mapping else ('不适用' if direct else UNKNOWN)
                    exit_ = mapping['exit_vps'] if mapping else ('不适用' if direct else UNKNOWN)
                    values = (minute, bindings.get(source, ''), source, policy, node, entry, exit_,
                              str(m.get('destinationIP') or '未知')[:128], str(m.get('host') or '')[:512], up, down)
                    self.db.execute('''INSERT INTO source_monthly VALUES (?,?,?,?,?) ON CONFLICT(month,device,source_ip)
                      DO UPDATE SET upload=upload+excluded.upload,download=download+excluded.download''',
                                    (month_key(now), bindings.get(source, ''), source, up, down))
                    self.db.execute('''INSERT INTO buckets VALUES (?,?,?,?,?,?,?,?,?,?,?)
                      ON CONFLICT DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''', values)
            self.db.execute('DELETE FROM snapshots')
            self.db.executemany('INSERT INTO snapshots VALUES (?,?,?)',
                                [(c['id'], c['upload'], c['download']) for c in {c['id']: c for c in connections}.values()])
            # Global deltas and attributed deltas are independent: never manufacture per-device traffic.
            total_up = 0 if baseline else payload['uploadTotal'] - previous['uploadTotal']
            total_down = 0 if baseline else payload['downloadTotal'] - previous['downloadTotal']
            self.db.execute('''INSERT INTO coverage VALUES (?,?,?,?,?,1) ON CONFLICT(minute) DO UPDATE SET
              upload=upload+excluded.upload, download=download+excluded.download,
              observed_upload=observed_upload+excluded.observed_upload,
              observed_download=observed_download+excluded.observed_download, samples=samples+1''',
                            (minute, total_up, total_down, observed_up, observed_down))
            self.set_meta('checkpoint', {'at': now, 'uploadTotal': payload['uploadTotal'], 'downloadTotal': payload['downloadTotal']})
            self.set_meta('interrupted', False)
            self.set_meta('last_error_at', None)
            if self.meta('last_prune', 0) < now - 3600:
                cutoff = int((now - self.retention * 86400) // 60) * 60
                for table, column in [('buckets', 'minute'), ('coverage', 'minute'), ('events', 'at')]:
                    self.db.execute(f'DELETE FROM {table} WHERE {column} < ?', (cutoff,))
                self.set_meta('last_prune', now)

    def failure(self, now=None):
        with self.lock, self.db:
            at = time.time() if now is None else now
            if not self.meta('interrupted', False):
                self.db.execute('INSERT INTO events VALUES (?,?)', (at, 'fetch_error'))
            self.set_meta('interrupted', True)
            self.set_meta('last_error_at', at)

    def devices(self):
        with self.lock:
            return [dict(r, ips=[a[0] for a in self.db.execute(
                'SELECT ip FROM bindings WHERE device=? AND until IS NULL ORDER BY ip', (r['id'],))])
                for r in self.db.execute('SELECT * FROM devices ORDER BY name')]

    def save_device(self, data, now=None):
        name = text(data.get('name', ''), 100)
        if not name:
            raise ValueError('请输入设备名称')
        addresses = data.get('ips', [])
        if not isinstance(addresses, list) or len(addresses) > 100:
            raise ValueError('每台设备最多绑定 100 个 IP')
        addresses = sorted(set(ip(a) for a in addresses))
        device_id = text(data.get('id', ''), 100) or str(uuid4())
        now = time.time() if now is None else now
        with self.lock, self.db:
            for address in addresses:
                other = self.db.execute('SELECT device FROM bindings WHERE ip=? AND until IS NULL', (address,)).fetchone()
                if other and other[0] != device_id:
                    raise ValueError(f'{address} 已绑定其他设备，请先解除原绑定')
            self.db.execute('INSERT OR REPLACE INTO devices VALUES (?,?)', (device_id, name))
            self.db.execute('INSERT OR REPLACE INTO device_origins VALUES (?,?)', (device_id, 'manual'))
            current = {r[0] for r in self.db.execute('SELECT ip FROM bindings WHERE device=? AND until IS NULL', (device_id,))}
            for address in current - set(addresses):
                self.db.execute('UPDATE bindings SET until=? WHERE ip=? AND until IS NULL', (now, address))
            for address in set(addresses) - current:
                self.db.execute('INSERT INTO bindings VALUES (?,?,?,NULL)', (address, device_id, now))
        return device_id

    def discover_hosts(self, records, links, now=None):
        now = time.time() if now is None else now
        found = {r['ip']: r for r in records}
        with self.lock, self.db:
            for address in set(links) | set(found):
                current = self.db.execute('SELECT device FROM bindings WHERE ip=? AND until IS NULL', (address,)).fetchone()
                current_id = current[0] if current else None
                origin = self.db.execute('SELECT origin FROM device_origins WHERE device=?', (current_id,)).fetchone()
                if current_id and (not origin or origin[0] == 'manual') and not str(found.get(address,{}).get('source','')).startswith('主路由 DHCP'):
                    continue
                record = found.get(address)
                mac = links.get(address, '')
                desired = 'auto:' + (mac or address)
                if current_id and mac and current_id != desired:
                    self.db.execute('UPDATE bindings SET until=? WHERE ip=? AND until IS NULL', (now,address))
                    current_id = None
                if not record:
                    if current_id and origin and origin[0].startswith('主路由 DHCP'):
                        self.db.execute('UPDATE bindings SET until=? WHERE ip=? AND until IS NULL',(now,address))
                    continue
                name = text(record['name'],100)
                if not name:
                    continue
                device = current_id or desired
                self.db.execute('INSERT OR REPLACE INTO devices VALUES (?,?)',(device,name))
                self.db.execute('INSERT OR REPLACE INTO device_origins VALUES (?,?)',(device,record['source']))
                if not current_id:
                    self.db.execute('INSERT INTO bindings VALUES (?,?,?,NULL)',(address,device,now))

    def group_totals(self, month=None):
        month = month or month_key()
        start = month_start(month)
        checkpoint = self.meta('checkpoint')
        return dict(month=month, since=max(start,self.meta('chain_since',start)),
            last_sample=checkpoint['at'] if checkpoint else None,
            healthy=bool(checkpoint and time.time()-checkpoint['at'] < 5 and not self.meta('interrupted',False)),
            rows=[dict(r) for r in self.db.execute('SELECT name,upload,download FROM chain_monthly WHERE month=? ORDER BY name',(month,))])

    def device_usage(self, month=None):
        month = month or month_key()
        month_start(month)
        rows = [dict(r) for r in self.db.execute("""SELECT s.source_ip,COALESCE(d.name,'') AS name,
            SUM(s.upload) AS upload,SUM(s.download) AS download FROM source_monthly s
            LEFT JOIN bindings b ON b.ip=s.source_ip AND b.until IS NULL
            LEFT JOIN devices d ON d.id=b.device WHERE s.month=? GROUP BY s.source_ip
            ORDER BY SUM(s.upload+s.download) DESC,s.source_ip""",(month,))]
        return dict(month=month, rows=rows,
            months=[r[0] for r in self.db.execute('SELECT DISTINCT month FROM source_monthly ORDER BY month DESC')])

    def save_node(self, data):
        node = text(data.get('node', ''))
        if not node:
            raise ValueError('请输入完整节点名称')
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO nodes VALUES (?,?,?)', (
                node, text(data.get('entry_vps', '')) or UNKNOWN, text(data.get('exit_vps', '')) or UNKNOWN))

    def query(self, params):
        dimension = params.get('dimension', ['device'])[0]
        if dimension not in DIMENSIONS:
            raise ValueError('统计维度无效')
        now = time.time()
        start = int(params.get('start', [int(now - 86400)])[0])
        end = int(params.get('end', [int(now) + 60])[0])
        if start < 0 or end <= start or end - start > 366 * 86400:
            raise ValueError('时间范围必须为 1 秒至 366 天')
        # Bucket boundaries are returned so clients do not imply sub-minute precision.
        start = start // 60 * 60
        end = (end + 59) // 60 * 60
        where = ['minute>=?', 'minute<?']
        args = [start, end]
        for key in ('device', 'source_ip', 'policy', 'node', 'entry_vps', 'exit_vps'):
            value = params.get(key, [''])[0]
            if value:
                where.append(f'{key}=?')
                args.append(value)
        condition = ' AND '.join(where)
        column = DIMENSIONS[dimension]
        with self.lock:
            names = {r['id']: r['name'] for r in self.db.execute('SELECT * FROM devices')}
            if dimension == 'device':
                # 没有历史设备 ID 的记录按当时的来源 IP 独立汇总，不回写归属。
                rows = [dict(r) for r in self.db.execute(f"""SELECT device AS key,
                  CASE WHEN device='' THEN source_ip ELSE '' END AS source_ip,
                  SUM(upload) AS upload,SUM(download) AS download FROM buckets WHERE {condition}
                  GROUP BY device,CASE WHEN device='' THEN source_ip ELSE '' END
                  ORDER BY SUM(upload+download) DESC LIMIT 500""",args)]
                current_names = {r['ip']:r['name'] for r in self.db.execute(
                    'SELECT b.ip,d.name FROM bindings b JOIN devices d ON d.id=b.device WHERE b.until IS NULL')}
                for row in rows:
                    if row['key']:
                        row['label'] = names.get(row['key'],row['key'])
                    else:
                        source=row['source_ip'] or '本机/未知'
                        row['key']='unbound:'+source
                        row['label']=source
                        row['current_name']=current_names.get(source,'')
            else:
                rows = [dict(r) for r in self.db.execute(f"""SELECT {column} AS key,
                  SUM(upload) AS upload,SUM(download) AS download FROM buckets WHERE {condition}
                  GROUP BY {column} ORDER BY SUM(upload+download) DESC LIMIT 500""", args)]
                for row in rows:
                    row['label'] = row['key'] or '未知'
            total = dict(self.db.execute(f'SELECT COALESCE(SUM(upload),0) upload,COALESCE(SUM(download),0) download FROM buckets WHERE {condition}', args).fetchone())
            series = [dict(r) for r in self.db.execute(f'''SELECT CAST(minute/3600 AS INTEGER)*3600 AS at,
              SUM(upload) upload,SUM(download) download FROM buckets WHERE {condition} GROUP BY at ORDER BY at''', args)]
            coverage = dict(self.db.execute('''SELECT COALESCE(SUM(upload),0) upload,COALESCE(SUM(download),0) download,
              COALESCE(SUM(observed_upload),0) observed_upload,COALESCE(SUM(observed_download),0) observed_download,
              COALESCE(SUM(samples),0) samples FROM coverage WHERE minute>=? AND minute<?''', (start, end)).fetchone())
            events = [dict(r) for r in self.db.execute('SELECT kind,COUNT(*) count FROM events WHERE at>=? AND at<? GROUP BY kind', (start, end))]
            return dict(rows=rows, total=total, series=series, coverage=coverage, events=events,
                        start=start, end=end, truncated=len(rows) == 500)


class Collector(threading.Thread):
    def __init__(self, store, config, stop):
        super().__init__(daemon=True)
        self.store, self.config, self.stop = store, config, stop
        self.policies = {}
        self.rules_at = 0
        # Do not send LAN credentials through environment HTTP proxies.
        self.opener = build_opener(ProxyHandler({}))

    def fetch(self, path):
        req = Request(self.config['controller'].rstrip('/') + path,
                      headers={'Authorization': 'Bearer ' + self.config.get('controller_secret', '')})
        try:
            with self.opener.open(req, timeout=self.config.get('timeout', 5)) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
                if len(raw) > 32 * 1024 * 1024:
                    raise ValueError('连接快照过大')
                return json.loads(raw)
        except HTTPError as error:
            error.close()
            raise

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                if time.time() - self.rules_at > 60:
                    try:
                        self.policies = {(r.get('type'), r.get('payload')): r.get('proxy') for r in self.fetch('/rules').get('rules', [])}
                        self.rules_at = time.time()
                    except Exception:
                        # Rule lookup is supplemental; chain fallback remains available.
                        pass
                self.store.sample(self.fetch('/connections'), self.policies, interval=self.config['interval'])
            except Exception:
                self.store.failure()
            self.stop.wait(max(.05, self.config['interval'] - (time.monotonic() - started)))


def make_handler(store, config):
    class Handler(SimpleHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=config.get('static_dir', 'dist'), **kwargs)

        def log_message(self, *_):
            pass  # Never log request paths, query strings or credentials.

        def origin_allowed(self):
            origin = self.headers.get('Origin')
            return not origin or origin in config.get('allowed_origins', []) or origin == f'http://{self.headers.get("Host")}' or origin == f'https://{self.headers.get("Host")}'

        def end_headers(self):
            origin = self.headers.get('Origin')
            if origin and self.origin_allowed():
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Vary', 'Origin')
            self.send_header('X-Content-Type-Options', 'nosniff')
            super().end_headers()

        def reply(self, status, data):
            body = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            token = self.headers.get('Authorization', '')
            if not self.origin_allowed() or (config.get('require_auth', False) and not hmac.compare_digest(token.encode(), ('Bearer ' + config['api_token']).encode())):
                self.reply(401, {'error': '统计服务认证失败或来源不受允许'})
                return False
            return True

        def do_OPTIONS(self):
            if not self.origin_allowed():
                self.reply(403, {'error': '来源不受允许'})
                return
            self.send_response(204)
            self.send_header('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
            self.end_headers()

        def do_GET(self):
            path = urlsplit(self.path).path
            if not path.startswith('/api/stats/'):
                # Static UI only; do not expose database/config files or directory listings.
                if not Path(config.get('static_dir', 'dist')).is_dir():
                    self.reply(404, {'error': '尚未构建前端'})
                    return
                return super().do_GET()
            if not self.authorized():
                return
            try:
                with store.lock:
                    if path == '/api/stats/status':
                        checkpoint = store.meta('checkpoint')
                        last = checkpoint['at'] if checkpoint else None
                        self.reply(200, dict(source_id=config['source_id'], controller_label=config.get('controller_label', ''),
                            auth_required=config.get('require_auth', False),
                            hostname_source='router-dhcp-mdns' if config.get('router_dhcp') else 'local-mdns',
                            host_refresh_interval=config.get('host_refresh_interval',60),
                            router_dhcp_synced_at=store.meta('router_dhcp_synced_at'),
                            router_dhcp_error_at=store.meta('router_dhcp_error_at'),
                            last_sample=last, last_error_at=store.meta('last_error_at'), interval=config['interval'],
                            healthy=bool(last and time.time()-last < max(5, config['interval']*3) and not store.meta('interrupted', False)),
                            retention_days=store.retention, sampling=True))
                    elif path == '/api/stats/group-totals':
                        params = parse_qs(urlsplit(self.path).query)
                        result = store.group_totals(params.get('month',[None])[0])
                        checkpoint = store.meta('checkpoint')
                        result['healthy'] = bool(checkpoint and time.time()-checkpoint['at'] < max(5,config['interval']*3) and not store.meta('interrupted',False))
                        self.reply(200, result)
                    elif path == '/api/stats/device-usage':
                        self.reply(200, store.device_usage(parse_qs(urlsplit(self.path).query).get('month',[None])[0]))
                    elif path == '/api/stats/summary':
                        self.reply(200, store.query(parse_qs(urlsplit(self.path).query)))
                    elif path == '/api/stats/devices':
                        self.reply(200, store.devices())
                    elif path == '/api/stats/nodes':
                        self.reply(200, [dict(r) for r in store.db.execute('SELECT * FROM nodes ORDER BY node')])
                    else:
                        self.reply(404, {'error': '接口不存在'})
            except (ValueError, TypeError):
                self.reply(400, {'error': '查询参数无效'})

        def do_PUT(self):
            if not self.authorized():
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    raise ValueError('请求体为空或过大')
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError('请求体必须是对象')
                path = urlsplit(self.path).path
                if path == '/api/stats/devices':
                    self.reply(200, {'id': store.save_device(data)})
                elif path == '/api/stats/nodes':
                    store.save_node(data)
                    self.reply(200, {'ok': True})
                else:
                    self.reply(404, {'error': '接口不存在'})
            except (ValueError, TypeError) as error:
                self.reply(400, {'error': str(error)})

        def list_directory(self, _):
            self.reply(404, {'error': '文件不存在'})

        def translate_path(self, path):
            root = Path(config.get('static_dir', 'dist')).resolve()
            translated = Path(super().translate_path(path)).resolve()
            if not translated.is_relative_to(root):
                return str(root / '__not_found__')
            return str(translated)

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    config['api_token'] = os.environ.get('STATS_API_TOKEN', config.get('api_token', ''))
    config['controller_secret'] = os.environ.get('MIHOMO_SECRET', config.get('controller_secret', ''))
    if config.get('require_auth', False) and len(config['api_token']) < 24:
        parser.error('api_token 至少需要 24 个字符，可通过 STATS_API_TOKEN 设置')
    controller = urlsplit(config.get('controller', ''))
    if controller.scheme not in ('http', 'https') or not controller.hostname or controller.username or controller.query or controller.fragment:
        parser.error('controller 必须是有效的 HTTP(S) 地址，密钥请单独设置')
    if not config.get('source_id'):
        parser.error('请设置稳定的 source_id，以便前端明确绑定采集源')
    config['interval'] = float(config.get('interval', 1))
    if not .2 <= config['interval'] <= 60:
        parser.error('interval 必须在 0.2 至 60 秒之间')
    os.umask(0o077)
    db_path = Path(config.get('database', 'stats-service/data/stats.sqlite3')).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = Store(str(db_path), max(1, int(config.get('retention_days', 90))))
    with store.lock, store.db:
        identity = {'source_id': config['source_id'], 'controller': config['controller'].rstrip('/')}
        if store.meta('identity', identity) != identity:
            parser.error('数据库已绑定其他采集源或 controller；请使用独立数据库，防止混合统计')
        store.set_meta('identity', identity)
    stop = threading.Event()
    server = ThreadingHTTPServer((config.get('listen', '127.0.0.1'), int(config.get('port', 9099))), make_handler(store, config))
    server.daemon_threads = True
    collector = Collector(store, config, stop)
    collector.start()
    discovery = None
    if config.get('discover_hosts', Path('/etc/config/dhcp').exists()):
        from discovery import HostDiscovery
        discovery = HostDiscovery(store, config, stop)
        discovery.start()
    # Signal handlers only set an event; shutdown must run outside serve_forever's thread.
    server.timeout = .5
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print('Zashboard 统计服务已启动（连接采样统计）', flush=True)
    try:
        while not stop.is_set():
            server.handle_request()
    finally:
        stop.set()
        collector.join(timeout=12)
        if discovery:
            discovery.join(timeout=10)
        server.server_close()
        with store.lock:
            store.db.close()


if __name__ == '__main__':
    main()
