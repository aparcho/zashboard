"""通过专用受限 SSH 通道读取主路由 DHCP；不修改路由器配置。"""
import html
import ipaddress
import os
import pwd
import re
import subprocess
from urllib.parse import unquote

MAC = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$', re.I)


def valid_record(address, mac, name):
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        return None
    name = str(name).strip().rstrip('.')
    if not MAC.fullmatch(mac) or not name or name in ('*','unknown') or len(name)>100 or any(ord(c)<32 for c in name):
        return None
    return {'ip':address,'mac':mac.lower(),'name':name,'source':'主路由 DHCP'}


def parse_snapshot(raw):
    if len(raw)>1024*1024 or not raw.startswith('ZASH_DHCP_V1\n') or not raw.rstrip().endswith('ZASH_END'):
        raise ValueError('主路由 DHCP 响应不完整')
    static, marker, leases = raw[len('ZASH_DHCP_V1\n'):].partition('\nZASH_LEASES\n')
    if not marker:
        raise ValueError('主路由 DHCP 响应缺少租约段')
    leases = leases.rsplit('ZASH_END',1)[0]
    rows = {}
    for line in leases.splitlines():
        fields=line.split()
        if len(fields)>=4:
            record=valid_record(fields[2],fields[1],fields[3])
            if record:rows[record['ip']]=record
    # 显式静态名称优先于设备上报的租约名称；空静态名称不覆盖有效租约。
    for entry in html.unescape(unquote(unquote(static))).split('<'):
        fields=entry.split('>')
        if len(fields)>=4:
            record=valid_record(fields[1],fields[0],fields[3])
            if record:rows[record['ip']]=record
    return list(rows.values())


def fetch_router_dhcp(config):
    host=str(config['host']);user=str(config['user']);port=int(config.get('port',22))
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+',host) or not re.fullmatch(r'[A-Za-z0-9_.-]+',user) or not 1<=port<=65535:
        raise ValueError('主路由 SSH 配置无效')
    args=['ssh','-T','-o','BatchMode=yes','-p',str(port),'-i',str(config['identity_file']),user+'@'+host]
    # procd 默认 HOME=/，Dropbear 会因此读错 known_hosts；固定为运行账户的真实主目录。
    env={**os.environ,'HOME':pwd.getpwuid(os.geteuid()).pw_dir}
    result=subprocess.run(args,check=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,text=True,env=env)
    return parse_snapshot(result.stdout.replace('\r\n','\n'))
