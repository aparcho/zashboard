#!/usr/bin/env python3
"""Zashboard 采样统计服务；仅使用 Python 标准库。"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hmac
import ipaddress
import json
import mimetypes
import os
from pathlib import Path
import re
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
BUILTIN_NODES = frozenset(('DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'TAILNET'))
PROTOCOL_TOKENS = frozenset((
    'REALITY', 'SS', 'SHADOWSOCKS', 'HY2', 'HYSTERIA2', 'ANYTLS', 'XHTTP',
    'TUIC', 'VMESS', 'VLESS', 'TROJAN', 'WG', 'WIREGUARD', 'WS', 'GRPC',
))
IP_SUFFIX_TOKENS = frozenset(('V4', 'V6', 'IPV4', 'IPV6', 'PREFER', 'EXIT', 'IEPL', 'CMIN2'))
DIMENSIONS = {
    'device': 'device', 'source_ip': 'source_ip', 'policy': 'policy',
    'node': 'node', 'entry_vps': 'entry_vps', 'exit_vps': 'exit_vps',
    'target_ip': 'target_ip', 'host': 'host', 'vps': 'node',
}


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


def resolve_vps_path(node, exact_paths, entry_vps='', exit_vps='', vps_rules=None, auto_parse=True, canonical_map=None):
    canonical_map = canonical_map or {}
    path = exact_paths.get(node)
    if path is not None:
        return list(dict.fromkeys(path))
    mapped = [v for v in (entry_vps, exit_vps) if v and v not in (UNKNOWN, '不适用')]
    if mapped:
        return list(dict.fromkeys(mapped))
    for rule in vps_rules or ():
        try:
            if re.search(rule['pattern'], node):
                return list(dict.fromkeys(rule['vps']))
        except re.error:
            continue
    if not auto_parse:
        return []
    # 模式 1：落地-via-中转-协议（例如 SV-via-SVCN2-Reality、HKT-原生-HKN-via-HKG）；中转在前、落地在后。
    parts = re.split(r'-via-', node, maxsplit=1, flags=re.IGNORECASE)
    if len(parts) == 2:
        resolved = _segment_vps(parts[1], canonical_map) + _segment_vps(parts[0], canonical_map)
        return list(dict.fromkeys(resolved))
    # 模式 2：普通节点，协议标记之前的 VPS 代码（例如 HKL-HKG-v4-XHTTP、HKN-v6-HKS-SS-v6、Legend-LAX-HY2）
    return list(dict.fromkeys(_segment_vps(node, canonical_map)))


VPS_CODE = re.compile(r'^[A-Z][A-Z0-9]{1,7}$')
NON_VPS_TOKENS = frozenset(('DIRECT', 'WARP', 'MO', 'RESIDENTIAL', 'NATIVE'))


def _segment_vps(segment, canonical_map):
    """把节点名片段切成 VPS 代码：优先贪婪匹配已知多段名称（如 LEGEND-LAX），其余只认大写代码。"""
    tokens = [t for t in segment.split('-') if t]
    proto_idx = next((i for i, tok in enumerate(tokens) if tok.upper() in PROTOCOL_TOKENS), len(tokens))
    tokens = tokens[:proto_idx]
    result = []
    i = 0
    while i < len(tokens):
        matched = False
        for j in range(len(tokens), i + 1, -1):
            joined = '-'.join(tokens[i:j]).upper()
            if joined in canonical_map:
                result.append(canonical_map[joined])
                i = j
                matched = True
                break
        if matched:
            continue
        tok = tokens[i]
        upper = tok.upper()
        if upper in canonical_map:
            result.append(canonical_map[upper])
        elif tok.isascii() and VPS_CODE.match(tok) and upper not in IP_SUFFIX_TOKENS and upper not in NON_VPS_TOKENS:
            result.append(tok)
        i += 1
    return result


class Store:
    def __init__(self, path, retention_days=90, detail_retention_days=None):
        self.path = str(path)
        self._is_memory = self.path == ':memory:' or self.path.startswith('file::memory:')
        self.lock = threading.RLock()
        self._local = threading.local()
        self._read_conns = []
        self._read_conns_lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.retention = max(1, int(retention_days))
        self.detail_retention = max(1, min(self.retention, int(detail_retention_days))) if detail_retention_days else min(self.retention, 30)
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA foreign_keys=ON;
        PRAGMA busy_timeout=5000;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=-8000;
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
        CREATE TABLE IF NOT EXISTS buckets_hourly(hour INTEGER NOT NULL, device TEXT NOT NULL,
          source_ip TEXT NOT NULL, policy TEXT NOT NULL, node TEXT NOT NULL,
          entry_vps TEXT NOT NULL, exit_vps TEXT NOT NULL,
          upload INTEGER NOT NULL, download INTEGER NOT NULL,
          PRIMARY KEY(hour,device,source_ip,policy,node,entry_vps,exit_vps));
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
        PRAGMA user_version=4;
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
            if not self.meta('hourly_migrated'):
                self.db.execute("""INSERT OR REPLACE INTO buckets_hourly
                    SELECT CAST(minute/3600 AS INTEGER)*3600,device,source_ip,policy,node,entry_vps,exit_vps,
                    SUM(upload),SUM(download) FROM buckets GROUP BY 1,2,3,4,5,6,7""")
                self.set_meta('hourly_migrated', True)

        # 内存快照与批量落盘缓冲；避免每秒全量删插 snapshots 表和频繁 fsync。
        self._snapshots = {
            r['id']: (r['upload'], r['download'])
            for r in self.db.execute('SELECT id,upload,download FROM snapshots')
        }
        self._pending_chain = {}
        self._pending_chain_monthly = {}
        self._pending_source_monthly = {}
        self._pending_buckets = {}
        self._pending_hourly = {}
        self._pending_coverage = {}
        self._pending_events = []
        self._checkpoint = self.meta('checkpoint')
        self._chain_since = self.meta('chain_since')
        self._interrupted = bool(self.meta('interrupted', False))
        self._last_error_at = self.meta('last_error_at')
        self._dirty = False

    @contextmanager
    def read_conn(self):
        if self._is_memory:
            with self.lock:
                yield self.db
            return
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(f'file:{self.path}?mode=ro', uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            conn.executescript('PRAGMA query_only=ON; PRAGMA busy_timeout=5000; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-8000;')
            self._local.conn = conn
            with self._read_conns_lock:
                self._read_conns.append(conn)
        yield conn

    def close(self):
        self.flush()
        with self._read_conns_lock:
            for conn in self._read_conns:
                try:
                    conn.close()
                except Exception:
                    pass
            self._read_conns.clear()
        with self.lock:
            self.db.close()

    def meta(self, key, default=None, conn=None):
        db = conn if conn is not None else self.db
        row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value)))

    def flush(self):
        with self.lock:
            if not self._dirty:
                return
            with self.db:
                if self._chain_since is not None:
                    self.set_meta('chain_since', self._chain_since)
                if self._pending_events:
                    self.db.executemany('INSERT INTO events VALUES (?,?)', self._pending_events)
                    self._pending_events.clear()
                if self._pending_chain:
                    self.db.executemany(
                        '''INSERT INTO chain_totals VALUES (?,?,?) ON CONFLICT(name)
                          DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''',
                        [(k, v[0], v[1]) for k, v in self._pending_chain.items()],
                    )
                    self._pending_chain.clear()
                if self._pending_chain_monthly:
                    self.db.executemany(
                        '''INSERT INTO chain_monthly VALUES (?,?,?,?) ON CONFLICT(month,name)
                          DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''',
                        [(k[0], k[1], v[0], v[1]) for k, v in self._pending_chain_monthly.items()],
                    )
                    self._pending_chain_monthly.clear()
                if self._pending_source_monthly:
                    self.db.executemany(
                        '''INSERT INTO source_monthly VALUES (?,?,?,?,?) ON CONFLICT(month,device,source_ip)
                          DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''',
                        [(k[0], k[1], k[2], v[0], v[1]) for k, v in self._pending_source_monthly.items()],
                    )
                    self._pending_source_monthly.clear()
                if self._pending_buckets:
                    self.db.executemany(
                        '''INSERT INTO buckets VALUES (?,?,?,?,?,?,?,?,?,?,?)
                          ON CONFLICT DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''',
                        [(*k, v[0], v[1]) for k, v in self._pending_buckets.items()],
                    )
                    self._pending_buckets.clear()
                if self._pending_hourly:
                    self.db.executemany(
                        '''INSERT INTO buckets_hourly VALUES (?,?,?,?,?,?,?,?,?)
                          ON CONFLICT DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download''',
                        [(*k, v[0], v[1]) for k, v in self._pending_hourly.items()],
                    )
                    self._pending_hourly.clear()
                if self._pending_coverage:
                    self.db.executemany(
                        '''INSERT INTO coverage VALUES (?,?,?,?,?,?) ON CONFLICT(minute) DO UPDATE SET
                          upload=upload+excluded.upload, download=download+excluded.download,
                          observed_upload=observed_upload+excluded.observed_upload,
                          observed_download=observed_download+excluded.observed_download, samples=samples+excluded.samples''',
                        [(k, v[0], v[1], v[2], v[3], v[4]) for k, v in self._pending_coverage.items()],
                    )
                    self._pending_coverage.clear()
                if self._checkpoint is not None:
                    self.set_meta('checkpoint', self._checkpoint)
                    self.db.execute('DELETE FROM snapshots')
                    if self._snapshots:
                        self.db.executemany(
                            'INSERT INTO snapshots VALUES (?,?,?)',
                            [(cid, vals[0], vals[1]) for cid, vals in self._snapshots.items()],
                        )
                self.set_meta('interrupted', self._interrupted)
                self.set_meta('last_error_at', self._last_error_at)
                now = self._checkpoint['at'] if self._checkpoint else time.time()
                if self.meta('last_prune', 0) < now - 3600:
                    detail_cutoff = int((now - self.detail_retention * 86400) // 60) * 60
                    summary_cutoff = int((now - self.retention * 86400) // 3600) * 3600
                    self.db.execute('DELETE FROM buckets WHERE minute < ?', (detail_cutoff,))
                    self.db.execute('DELETE FROM buckets_hourly WHERE hour < ?', (summary_cutoff,))
                    self.db.execute('DELETE FROM coverage WHERE minute < ?', (summary_cutoff,))
                    self.db.execute('DELETE FROM events WHERE at < ?', (summary_cutoff,))
                    self.set_meta('last_prune', now)
            self._dirty = False

    def sample(self, payload, policies=None, now=None, interval=1, commit=True):
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
        with self.lock:
            if self._chain_since is None:
                self._chain_since = now
            previous = self._checkpoint
            cold = previous is None
            gap = previous is not None and (now - previous['at'] > max(interval * 3, 5) or now < previous['at'])
            reset = previous is not None and any(payload[k] < previous[k] for k in ('uploadTotal', 'downloadTotal'))
            recovery = bool(self._interrupted)
            baseline = cold or gap or reset or recovery
            if baseline:
                self._pending_events.append((now, 'baseline' if cold else 'reset' if reset else 'gap'))
            bindings = {r['ip']: r['device'] for r in self.db.execute('SELECT ip,device FROM bindings WHERE until IS NULL')}
            nodes = {r['node']: (r['entry_vps'], r['exit_vps']) for r in self.db.execute('SELECT node,entry_vps,exit_vps FROM nodes')}
            minute = int(now // 60) * 60
            hour = int(now // 3600) * 3600
            mkey = month_key(now)
            observed_up = observed_down = 0
            next_snapshots = {}
            for c in connections:
                cid = c['id']
                if cid in next_snapshots:
                    continue
                cur_up, cur_down = c['upload'], c['download']
                next_snapshots[cid] = (cur_up, cur_down)
                old = self._snapshots.get(cid)
                up = down = 0
                if not baseline:
                    up = max(0, cur_up - old[0]) if old else cur_up
                    down = max(0, cur_down - old[1]) if old else cur_down
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
                        prev_c = self._pending_chain.get(member)
                        self._pending_chain[member] = (prev_c[0] + up, prev_c[1] + down) if prev_c else (up, down)
                        cm_key = (mkey, member)
                        prev_cm = self._pending_chain_monthly.get(cm_key)
                        self._pending_chain_monthly[cm_key] = (prev_cm[0] + up, prev_cm[1] + down) if prev_cm else (up, down)
                    node = str(chain[0]) if chain else '未知节点'
                    policy = (policies or {}).get((c.get('rule'), c.get('rulePayload')))
                    policy = policy or (str(chain[-1]) if chain else str(c.get('rule') or '未知策略'))
                    mapping = nodes.get(node)
                    direct = node.upper() in ('DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE')
                    entry = mapping[0] if mapping else ('不适用' if direct else UNKNOWN)
                    exit_ = mapping[1] if mapping else ('不适用' if direct else UNKNOWN)
                    dev_id = bindings.get(source, '')
                    sm_key = (mkey, dev_id, source)
                    prev_sm = self._pending_source_monthly.get(sm_key)
                    self._pending_source_monthly[sm_key] = (prev_sm[0] + up, prev_sm[1] + down) if prev_sm else (up, down)
                    b_key = (minute, dev_id, source, policy, node, entry, exit_,
                             str(m.get('destinationIP') or '未知')[:128], str(m.get('host') or '')[:512])
                    prev_b = self._pending_buckets.get(b_key)
                    self._pending_buckets[b_key] = (prev_b[0] + up, prev_b[1] + down) if prev_b else (up, down)
                    h_key = (hour, dev_id, source, policy, node, entry, exit_)
                    prev_h = self._pending_hourly.get(h_key)
                    self._pending_hourly[h_key] = (prev_h[0] + up, prev_h[1] + down) if prev_h else (up, down)
            self._snapshots = next_snapshots
            # Global deltas and attributed deltas are independent: never manufacture per-device traffic.
            total_up = 0 if baseline else payload['uploadTotal'] - previous['uploadTotal']
            total_down = 0 if baseline else payload['downloadTotal'] - previous['downloadTotal']
            prev_cov = self._pending_coverage.get(minute)
            if prev_cov:
                self._pending_coverage[minute] = (
                    prev_cov[0] + total_up, prev_cov[1] + total_down,
                    prev_cov[2] + observed_up, prev_cov[3] + observed_down, prev_cov[4] + 1,
                )
            else:
                self._pending_coverage[minute] = (total_up, total_down, observed_up, observed_down, 1)
            self._checkpoint = {'at': now, 'uploadTotal': payload['uploadTotal'], 'downloadTotal': payload['downloadTotal']}
            self._interrupted = False
            self._last_error_at = None
            self._dirty = True
            if commit or baseline:
                self.flush()

    def failure(self, now=None):
        with self.lock:
            at = time.time() if now is None else now
            if not self._interrupted:
                self._pending_events.append((at, 'fetch_error'))
            self._interrupted = True
            self._last_error_at = at
            self._dirty = True
            self.flush()

    def status_snapshot(self, config):
        with self.read_conn() as db:
            checkpoint = self._checkpoint or self.meta('checkpoint', conn=db)
            last = checkpoint['at'] if checkpoint else None
            interrupted = self._interrupted if self._checkpoint is not None else bool(self.meta('interrupted', False, conn=db))
            last_error = self._last_error_at if self._checkpoint is not None else self.meta('last_error_at', conn=db)
            return dict(
                source_id=config['source_id'],
                controller_label=config.get('controller_label', ''),
                auth_required=config.get('require_auth', False),
                hostname_source='router-dhcp-mdns' if config.get('router_dhcp') else 'local-mdns',
                host_refresh_interval=config.get('host_refresh_interval', 60),
                router_dhcp_synced_at=self.meta('router_dhcp_synced_at', conn=db),
                router_dhcp_error_at=self.meta('router_dhcp_error_at', conn=db),
                last_sample=last,
                last_error_at=last_error,
                interval=config['interval'],
                healthy=bool(last and time.time() - last < max(5, config['interval'] * 3) and not interrupted),
                retention_days=self.retention,
                detail_retention_days=self.detail_retention,
                sampling=True,
            )

    def devices(self):
        with self.read_conn() as db:
            by_dev = {}
            for r in db.execute('SELECT device,ip FROM bindings WHERE until IS NULL ORDER BY ip'):
                by_dev.setdefault(r['device'], []).append(r['ip'])
            return [dict(r, ips=by_dev.get(r['id'], [])) for r in db.execute('SELECT * FROM devices ORDER BY name')]

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
                origin = self.db.execute('SELECT origin FROM device_origins WHERE device=?', (current_id,)).fetchone() if current_id else None
                # 手动绑定始终最高优先级，不得被主路由 DHCP 或 mDNS 自动覆盖。
                if current_id and (not origin or origin[0] == 'manual'):
                    continue
                record = found.get(address)
                mac = links.get(address, '')
                desired = 'auto:' + (mac or address)
                if current_id and mac and current_id != desired:
                    self.db.execute('UPDATE bindings SET until=? WHERE ip=? AND until IS NULL', (now, address))
                    current_id = None
                if not record:
                    if current_id and origin and origin[0].startswith('主路由 DHCP'):
                        self.db.execute('UPDATE bindings SET until=? WHERE ip=? AND until IS NULL', (now, address))
                    continue
                name = text(record['name'], 100)
                if not name:
                    continue
                device = current_id or desired
                self.db.execute('INSERT OR REPLACE INTO devices VALUES (?,?)', (device, name))
                self.db.execute('INSERT OR REPLACE INTO device_origins VALUES (?,?)', (device, record['source']))
                if not current_id:
                    self.db.execute('INSERT INTO bindings VALUES (?,?,?,NULL)', (address, device, now))

    def group_totals(self, month=None, interval=1):
        month = month or month_key()
        start = month_start(month)
        with self.read_conn() as db:
            checkpoint = self._checkpoint or self.meta('checkpoint', conn=db)
            chain_since = self._chain_since if self._chain_since is not None else self.meta('chain_since', start, conn=db)
            interrupted = self._interrupted if self._checkpoint is not None else bool(self.meta('interrupted', False, conn=db))
            merged = {
                r['name']: [r['upload'], r['download']]
                for r in db.execute('SELECT name,upload,download FROM chain_monthly WHERE month=?', (month,))
            }
            for (pmonth, name), (up, down) in list(self._pending_chain_monthly.items()):
                if pmonth == month:
                    cur = merged.get(name)
                    merged[name] = [cur[0] + up, cur[1] + down] if cur else [up, down]
            rows = [{'name': name, 'upload': vals[0], 'download': vals[1]} for name, vals in sorted(merged.items())]
            return dict(
                month=month,
                since=max(start, chain_since if chain_since is not None else start),
                last_sample=checkpoint['at'] if checkpoint else None,
                healthy=bool(checkpoint and time.time() - checkpoint['at'] < max(5, interval * 3) and not interrupted),
                rows=rows,
            )

    def device_usage(self, month=None):
        month = month or month_key()
        month_start(month)
        with self.read_conn() as db:
            active_names = {
                r['ip']: r['name']
                for r in db.execute('SELECT b.ip,d.name FROM bindings b JOIN devices d ON d.id=b.device WHERE b.until IS NULL')
            }
            merged = {}
            for r in db.execute('SELECT source_ip,SUM(upload) AS upload,SUM(download) AS download FROM source_monthly WHERE month=? GROUP BY source_ip', (month,)):
                merged[r['source_ip']] = [r['upload'], r['download']]
            for (pmonth, _dev, src), (up, down) in list(self._pending_source_monthly.items()):
                if pmonth == month:
                    cur = merged.get(src)
                    merged[src] = [cur[0] + up, cur[1] + down] if cur else [up, down]
            rows = [
                {'source_ip': src, 'name': active_names.get(src, ''), 'upload': vals[0], 'download': vals[1]}
                for src, vals in sorted(merged.items(), key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0]))
            ]
            months = sorted({r[0] for r in db.execute('SELECT DISTINCT month FROM source_monthly')} | {m for m, _, _ in list(self._pending_source_monthly.keys())}, reverse=True)
            return dict(month=month, rows=rows, months=months)

    def save_node(self, data):
        node = text(data.get('node', ''))
        if not node:
            raise ValueError('请输入完整节点名称')
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO nodes VALUES (?,?,?)', (
                node, text(data.get('entry_vps', '')) or UNKNOWN, text(data.get('exit_vps', '')) or UNKNOWN))

    def configure_vps(self, paths, rules=None, auto_parse=True):
        if not isinstance(paths, dict):
            raise ValueError('vps_paths 必须为节点到 VPS 列表的映射')
        checked = {}
        for node, path in paths.items():
            if not isinstance(path, list) or not path or len(path) > 16:
                raise ValueError('每个节点必须有 1 至 16 个 VPS')
            checked[text(node)] = list(dict.fromkeys(text(v) for v in path if text(v)))
            if not checked[text(node)]:
                raise ValueError('VPS 名称不能为空')
        checked_rules = []
        if rules:
            if not isinstance(rules, list):
                raise ValueError('vps_rules 必须为规则数组')
            for rule in rules:
                if not isinstance(rule, dict) or not isinstance(rule.get('pattern'), str) or not isinstance(rule.get('vps'), list):
                    raise ValueError('每条 vps_rules 必须包含 pattern 与 vps 列表')
                re.compile(rule['pattern'])
                vps_list = list(dict.fromkeys(text(v) for v in rule['vps'] if text(v)))
                if not vps_list:
                    raise ValueError('规则的 VPS 列表不能为空')
                checked_rules.append({'pattern': rule['pattern'], 'vps': vps_list})
        with self.lock, self.db:
            self.set_meta('vps_paths', checked)
            self.set_meta('vps_rules', checked_rules)
            self.set_meta('vps_auto_parse', bool(auto_parse))

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
        vps_filter = params.get('vps', [''])[0].strip()
        use_hourly = (
            dimension not in ('host', 'target_ip')
            and (end - start >= 3600)
            and (start % 3600 == 0)
        )
        table = 'buckets_hourly' if use_hourly else 'buckets'
        time_col = 'hour' if use_hourly else 'minute'
        q_end = ((end + 3599) // 3600) * 3600 if use_hourly else end
        where = [f'{time_col}>=?', f'{time_col}<?']
        args = [start, q_end]
        for key in ('device', 'source_ip', 'policy', 'node', 'entry_vps', 'exit_vps'):
            value = params.get(key, [''])[0]
            if value:
                where.append(f'{key}=?')
                args.append(value)
        condition = ' AND '.join(where)
        column = DIMENSIONS[dimension]
        if self._dirty:
            self.flush()
        with self.read_conn() as db:
            names = {r['id']: r['name'] for r in db.execute('SELECT * FROM devices')}
            paths = self.meta('vps_paths', {}, conn=db)
            rules = self.meta('vps_rules', [], conn=db)
            auto_parse = self.meta('vps_auto_parse', True, conn=db)
            known_vps = {v.upper(): v for p in paths.values() for v in p}
            for rule in rules:
                for v in rule.get('vps', []):
                    known_vps.setdefault(v.upper(), v)
            unmapped_nodes = []

            if vps_filter:
                # 若按 vps 过滤，则先在已解析路径上筛出匹配的节点集合
                cand_rows = db.execute(f'SELECT DISTINCT node,entry_vps,exit_vps FROM {table} WHERE {condition}', args)
                matched_nodes = []
                for item in cand_rows:
                    nd = item['node']
                    if nd.upper() in BUILTIN_NODES:
                        continue
                    resolved = resolve_vps_path(nd, paths, item['entry_vps'], item['exit_vps'], rules, auto_parse, known_vps)
                    if not resolved:
                        resolved = ['未识别：' + nd]
                    if vps_filter in resolved:
                        matched_nodes.append(nd)
                if not matched_nodes:
                    coverage = dict(db.execute('''SELECT COALESCE(SUM(upload),0) upload,COALESCE(SUM(download),0) download,
                      COALESCE(SUM(observed_upload),0) observed_upload,COALESCE(SUM(observed_download),0) observed_download,
                      COALESCE(SUM(samples),0) samples FROM coverage WHERE minute>=? AND minute<?''', (start, end)).fetchone())
                    events = [dict(r) for r in db.execute('SELECT kind,COUNT(*) count FROM events WHERE at>=? AND at<? GROUP BY kind', (start, end))]
                    return dict(rows=[], total={'upload': 0, 'download': 0}, series=[], coverage=coverage, events=events,
                                start=start, end=end, truncated=False, unmapped_nodes=[])
                placeholders = ','.join('?' for _ in matched_nodes)
                where.append(f'node IN ({placeholders})')
                args.extend(matched_nodes)
                condition = ' AND '.join(where)

            if dimension == 'vps':
                # 按明确配置与规则解析完整路径展开；一条路径内同一 VPS 只计一次。
                grouped = {}
                unmapped_set = set()
                raw = db.execute(f"""SELECT node,entry_vps,exit_vps,
                  SUM(upload) upload,SUM(download) download FROM {table} WHERE {condition}
                  GROUP BY node,entry_vps,exit_vps""", args)
                for item in raw:
                    node = item['node']
                    if node.upper() in BUILTIN_NODES:
                        continue
                    path = resolve_vps_path(node, paths, item['entry_vps'], item['exit_vps'], rules, auto_parse, known_vps)
                    if not path:
                        unmapped_set.add(node)
                        path = ['未识别：' + node]
                    for vps in set(path):
                        row = grouped.setdefault(vps, dict(key=vps, label=vps, upload=0, download=0))
                        row['upload'] += item['upload']
                        row['download'] += item['download']
                unmapped_nodes = sorted(unmapped_set)[:50]
                rows = sorted(grouped.values(), key=lambda r: r['upload'] + r['download'], reverse=True)[:500]
            elif dimension == 'device':
                # 没有历史设备 ID 的记录按当时的来源 IP 独立汇总，不回写归属。
                rows = [dict(r) for r in db.execute(f"""SELECT device AS key,
                  CASE WHEN device='' THEN source_ip ELSE '' END AS source_ip,
                  SUM(upload) AS upload,SUM(download) AS download FROM {table} WHERE {condition}
                  GROUP BY device,CASE WHEN device='' THEN source_ip ELSE '' END
                  ORDER BY SUM(upload+download) DESC LIMIT 500""", args)]
                current_names = {r['ip']: r['name'] for r in db.execute(
                    'SELECT b.ip,d.name FROM bindings b JOIN devices d ON d.id=b.device WHERE b.until IS NULL')}
                for row in rows:
                    if row['key']:
                        row['label'] = names.get(row['key'], row['key'])
                    else:
                        source = row['source_ip'] or '本机/未知'
                        row['key'] = 'unbound:' + source
                        row['label'] = source
                        row['current_name'] = current_names.get(source, '')
            else:
                rows = [dict(r) for r in db.execute(f"""SELECT {column} AS key,
                  SUM(upload) AS upload,SUM(download) AS download FROM {table} WHERE {condition}
                  GROUP BY {column} ORDER BY SUM(upload+download) DESC LIMIT 500""", args)]
                for row in rows:
                    row['label'] = row['key'] or '未知'
            total = dict(db.execute(f'SELECT COALESCE(SUM(upload),0) upload,COALESCE(SUM(download),0) download FROM {table} WHERE {condition}', args).fetchone())
            if use_hourly:
                series = [dict(r) for r in db.execute(f'''SELECT hour AS at,
                  SUM(upload) upload,SUM(download) download FROM {table} WHERE {condition} GROUP BY hour ORDER BY hour''', args)]
            else:
                series = [dict(r) for r in db.execute(f'''SELECT CAST(minute/3600 AS INTEGER)*3600 AS at,
                  SUM(upload) upload,SUM(download) download FROM {table} WHERE {condition} GROUP BY at ORDER BY at''', args)]
            coverage = dict(db.execute('''SELECT COALESCE(SUM(upload),0) upload,COALESCE(SUM(download),0) download,
              COALESCE(SUM(observed_upload),0) observed_upload,COALESCE(SUM(observed_download),0) observed_download,
              COALESCE(SUM(samples),0) samples FROM coverage WHERE minute>=? AND minute<?''', (start, end)).fetchone())
            events = [dict(r) for r in db.execute('SELECT kind,COUNT(*) count FROM events WHERE at>=? AND at<? GROUP BY kind', (start, end))]
            result = dict(rows=rows, total=total, series=series, coverage=coverage, events=events,
                          start=start, end=end, truncated=len(rows) == 500)
            if unmapped_nodes:
                result['unmapped_nodes'] = unmapped_nodes
            return result


class Collector(threading.Thread):
    def __init__(self, store, config, stop):
        super().__init__(daemon=True)
        self.store, self.config, self.stop = store, config, stop
        self.policies = {}
        self.rules_at = 0
        # 默认每 5 秒批量落盘一次；极短间隔（如测试 0.2s）按比例缩短。
        default_flush = min(5.0, max(1.0, float(config['interval']) * 5.0))
        self.flush_interval = max(0.0, float(config.get('flush_interval', default_flush)))
        self.last_flush = time.monotonic()
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
        try:
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
                    should_flush = self.flush_interval <= 0 or (started - self.last_flush >= self.flush_interval)
                    self.store.sample(self.fetch('/connections'), self.policies, interval=self.config['interval'], commit=should_flush)
                    if should_flush:
                        self.last_flush = time.monotonic()
                except Exception:
                    self.store.failure()
                    self.last_flush = time.monotonic()
                self.stop.wait(max(.05, self.config['interval'] - (time.monotonic() - started)))
        finally:
            self.store.flush()


def make_handler(store, config):
    class Handler(SimpleHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(30)

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
                self.send_header('Access-Control-Expose-Headers', 'X-Stats-Source-Id')
                self.send_header('Vary', 'Origin')
            self.send_header('X-Content-Type-Options', 'nosniff')
            super().end_headers()

        def reply(self, status, data):
            body = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Stats-Source-Id', config['source_id'])
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

        def serve_static(self, req_path):
            root = Path(config.get('static_dir', 'dist')).resolve()
            if not root.is_dir():
                self.reply(404, {'error': '尚未构建前端'})
                return
            rel = req_path.lstrip('/') or 'index.html'
            target = (root / rel).resolve()
            if not target.is_relative_to(root):
                self.reply(404, {'error': '文件不存在'})
                return
            if target.is_dir():
                target = target / 'index.html'
            if not target.is_file():
                self.reply(404, {'error': '文件不存在'})
                return
            accept_enc = self.headers.get('Accept-Encoding', '')
            gz_target = target.with_name(target.name + '.gz')
            use_gz = 'gzip' in accept_enc and gz_target.is_file() and gz_target.resolve().is_relative_to(root)
            serve_file = gz_target if use_gz else target
            ctype = mimetypes.guess_type(str(target))[0] or 'application/octet-stream'
            stat = serve_file.stat()
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(stat.st_size))
            if use_gz:
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Vary', 'Accept-Encoding')
            if req_path.startswith('/assets/'):
                self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
            else:
                self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            with serve_file.open('rb') as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)

        def do_GET(self):
            path = urlsplit(self.path).path
            if not path.startswith('/api/stats/'):
                # Static UI only; do not expose database/config files or directory listings.
                return self.serve_static(path)
            if not self.authorized():
                return
            try:
                if path == '/api/stats/status':
                    self.reply(200, store.status_snapshot(config))
                elif path == '/api/stats/group-totals':
                    params = parse_qs(urlsplit(self.path).query)
                    self.reply(200, store.group_totals(params.get('month', [None])[0], interval=config['interval']))
                elif path == '/api/stats/device-usage':
                    self.reply(200, store.device_usage(parse_qs(urlsplit(self.path).query).get('month', [None])[0]))
                elif path == '/api/stats/summary':
                    self.reply(200, store.query(parse_qs(urlsplit(self.path).query)))
                elif path == '/api/stats/devices':
                    self.reply(200, store.devices())
                elif path == '/api/stats/nodes':
                    with store.read_conn() as db:
                        self.reply(200, [dict(r) for r in db.execute('SELECT * FROM nodes ORDER BY node')])
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
    store = Store(
        str(db_path),
        max(1, int(config.get('retention_days', 90))),
        config.get('detail_retention_days'),
    )
    store.configure_vps(
        config.get('vps_paths', {}),
        rules=config.get('vps_rules'),
        auto_parse=config.get('vps_auto_parse', True),
    )
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
        store.close()


if __name__ == '__main__':
    main()
