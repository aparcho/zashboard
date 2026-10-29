"""从现有租约、邻居及局域网名称响应识别设备，不修改网络配置。"""
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time


def _name(data, offset, seen=None):
    seen = set() if seen is None else seen
    labels = []
    end = None
    while True:
        if offset >= len(data) or offset in seen:
            raise ValueError('DNS name')
        seen.add(offset)
        length = data[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(data): raise ValueError('DNS pointer')
            end = end or offset + 2
            tail, _ = _name(data, ((length & 0x3f) << 8) | data[offset + 1], seen)
            labels.extend(tail.split('.') if tail else [])
            return '.'.join(labels), end
        offset += 1
        if not length: return '.'.join(labels), end or offset
        if length > 63 or offset + length > len(data): raise ValueError('DNS label')
        labels.append(data[offset:offset+length].decode('utf-8', 'replace'))
        offset += length


def ptr_answers(data):
    if len(data) < 12: return {}
    try:
        _, flags, questions, answers, authority, extra = struct.unpack('!6H', data[:12])
        if not flags & 0x8000: return {}
        offset = 12
        for _ in range(questions):
            _, offset = _name(data, offset); offset += 4
        result = {}
        for _ in range(answers + authority + extra):
            owner, offset = _name(data, offset)
            kind, _, _, length = struct.unpack('!HHIH', data[offset:offset+10]);offset += 10
            if kind == 12:
                value, _ = _name(data, offset)
                result[owner.lower().rstrip('.')] = value.rstrip('.')
            offset += length
        return result
    except (ValueError, struct.error, IndexError): return {}


def question(address, multicast=False):
    reverse = ipaddress.ip_address(address.split('%')[0]).reverse_pointer
    name = b''.join(bytes([len(label)]) + label.encode() for label in reverse.split('.')) + b'\0'
    return reverse, name + struct.pack('!HH', 12, 0x8001 if multicast else 1)


def mdns_names(addresses, interface=None, timeout=1.2):
    questions = [question(address, True) for address in addresses]
    owners = {owner: address for address, (owner, _) in zip(addresses, questions)}
    result = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('', 0)); sock.settimeout(.2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        if interface:
            try:sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface))
            except OSError:pass
        for index in range(0, len(questions), 5):
            chunk = questions[index:index+5]
            packet = struct.pack('!6H', 0, 0, len(chunk), 0, 0, 0) + b''.join(q for _, q in chunk)
            sock.sendto(packet, ('224.0.0.251', 5353))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:data, _ = sock.recvfrom(65535)
            except socket.timeout:continue
            for owner, name in ptr_answers(data).items():
                if owner in owners:result[owners[owner]] = name
    return result


def dns_name(address, server, timeout=.5):
    owner, q = question(address)
    identifier = os.urandom(2)
    packet = identifier + struct.pack('!5H', 0x100, 1, 0, 0, 0) + q
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout);sock.connect((server, 53));sock.send(packet)
        data = sock.recv(65535)
        if data[:2] != identifier:return None
        return ptr_answers(data).get(owner)


def netbios_name(address, timeout=.3):
    raw = b'*' + b'\0' * 15
    encoded = b''.join(bytes([65+(b>>4), 65+(b&15)]) for b in raw)
    identifier = os.urandom(2)
    packet = identifier + struct.pack('!5H', 0, 1, 0, 0, 0) + b'\x20' + encoded + b'\0\x00\x21\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout);sock.connect((address, 137));sock.send(packet);data=sock.recv(4096)
    if data[:2] != identifier:return None
    try:
        _, offset = _name(data, 12);offset += 4
        _, offset = _name(data, offset);offset += 10
        count=data[offset];offset+=1
        for _ in range(count):
            record=data[offset:offset+18];offset+=18
            if len(record)==18 and record[15]==0 and not struct.unpack('!H', record[16:])[0] & 0x8000:
                return record[:15].decode('utf-8','replace').strip()
    except (ValueError,IndexError,struct.error):pass
    return None


def neighbors():
    try:
        data=json.loads(subprocess.check_output(['ip','-j','neigh','show'],text=True,timeout=3))
        return {row['dst'].split('%')[0]:row['lladdr'].lower() for row in data if row.get('lladdr')}
    except (OSError,ValueError,subprocess.SubprocessError):
        try:
            rows=subprocess.check_output(['ip','neigh','show'],text=True,timeout=3).splitlines()
            return {row.split()[0].split('%')[0]:row.split('lladdr ')[1].split()[0].lower() for row in rows if 'lladdr ' in row}
        except (OSError,subprocess.SubprocessError):return {}


def local_names():
    result={}
    for path in [Path('/etc/hosts'), *Path('/tmp/hosts').glob('*')]:
        try:
            for line in path.read_text().splitlines():
                fields=line.split('#',1)[0].split()
                if len(fields)>=2:
                    try:result[str(ipaddress.ip_address(fields[0]))]=fields[1]
                    except ValueError:pass
        except OSError:pass
    for path in [Path('/tmp/dhcp.leases'),Path('/var/lib/misc/dnsmasq.leases')]:
        try:
            for line in path.read_text().splitlines():
                fields=line.split()
                if len(fields)>=4 and fields[3]!='*':
                    try:result[str(ipaddress.ip_address(fields[2]))]=fields[3]
                    except ValueError:pass
        except OSError:pass
    return result


def clean_name(value):
    value=str(value or '').strip().rstrip('.')
    for suffix in ('.local','.lan'):
        if value.lower().endswith(suffix):value=value[:-len(suffix)]
    if not value or value.lower() in ('localhost','unknown','*') or len(value)>100 or any(ord(c)<32 for c in value):return ''
    return value


class HostDiscovery(threading.Thread):
    def __init__(self, store, config, stop):
        super().__init__(daemon=True);self.store=store;self.config=config;self.stop=stop

    def run(self):
        while not self.stop.is_set():
            started=time.monotonic()
            try:self.refresh()
            except Exception:
                print('源主机同步暂不可用，保留上次名称',flush=True)
            self.stop.wait(max(1,float(self.config.get('host_refresh_interval',60))-(time.monotonic()-started)))

    def refresh(self):
        links=neighbors()
        with self.store.lock:
            sources={row[0] for row in self.store.db.execute('SELECT DISTINCT source_ip FROM buckets WHERE minute>=?',(time.time()-1800,))}
        addresses=[]
        for source in sources | set(links):
            try:
                address=ipaddress.ip_address(source)
                if not address.is_loopback and (address.is_private or source in links):addresses.append(str(address))
            except ValueError:pass
        router=self.config.get('router_dhcp')
        if router:
            from router_dhcp import fetch_router_dhcp
            try:
                records=fetch_router_dhcp(router)
                if self.stop.is_set():return
                with self.store.lock,self.store.db:
                    self.store.set_meta('router_dhcp_cache',records)
                    self.store.set_meta('router_dhcp_synced_at',time.time())
                    self.store.set_meta('router_dhcp_error_at',None)
            except Exception:
                if self.stop.is_set():return
                with self.store.lock,self.store.db:
                    records=self.store.meta('router_dhcp_cache',[])
                    self.store.set_meta('router_dhcp_error_at',time.time())
            # 路由器 DHCP 的 MAC/IP 关系为名称权威来源；邻居表只补充同 MAC 的其他地址。
            links.update({r['ip']:r['mac'] for r in records})
            addresses=list(set(addresses)|{r['ip'] for r in records})
            found={r['ip']:r['name'] for r in records}
            origins={r['ip']:'主路由 DHCP' for r in records}
        else:
            found=local_names();origins={address:'租约/本地主机表' for address in found}
        pending=[address for address in addresses if address not in found]
        try:
            for address,name in mdns_names(pending,self.config.get('listen')).items():
                found[address]=name;origins[address]='mDNS'
        except OSError:pass
        def publish():
            by_mac={links[a]:n for a,n in found.items() if a in links and clean_name(n)}
            primary={r['mac']:r['name'] for r in records} if router else {}
            by_mac.update(primary)
            for address,mac in links.items():
                if mac in by_mac and (address not in found or (mac in primary and not origins.get(address,'').startswith('主路由 DHCP'))):
                    found[address]=by_mac[mac];origins[address]=('主路由 DHCP' if mac in primary else next((origins[a] for a in found if links.get(a)==mac and a in origins),'mDNS'))+'（同 MAC）'
            published=[{'ip':a,'name':clean_name(n),'mac':links.get(a,''),'source':origins.get(a,'本地主机表')} for a,n in found.items() if a in addresses and clean_name(n)]
            self.store.discover_hosts(published,links)
        publish()
