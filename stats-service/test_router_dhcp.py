import threading
import unittest
from unittest.mock import patch
from router_dhcp import parse_snapshot, fetch_router_dhcp
from discovery import HostDiscovery
from service import Store

SAMPLE='''ZASH_DHCP_V1
<aa:bb:cc:dd:ee:01>192.168.1.10>>dhcp-laptop<aa:bb:cc:dd:ee:02>192.168.1.11>>
ZASH_LEASES
80000 aa:bb:cc:dd:ee:01 192.168.1.10 old-laptop *
80000 aa:bb:cc:dd:ee:02 192.168.1.11 dhcp-phone *
80000 aa:bb:cc:dd:ee:03 192.168.1.12 * *
ZASH_END
'''

class RouterDHCPTests(unittest.TestCase):
    def test_static_name_precedes_lease_and_blank_is_unknown(self):
        rows={r['ip']:r for r in parse_snapshot(SAMPLE)}
        self.assertEqual(rows['192.168.1.10']['name'],'dhcp-laptop')
        self.assertEqual(rows['192.168.1.11']['name'],'dhcp-phone')
        self.assertNotIn('192.168.1.12',rows)
        for bad in ['login required',SAMPLE.replace('ZASH_END',''),SAMPLE.replace('ZASH_LEASES','')]:
            with self.assertRaises(ValueError):parse_snapshot(bad)

    def test_dhcp_then_mdns_and_same_mac_ipv6_use_dhcp_name(self):
        s=Store(':memory:');stop=threading.Event()
        config={'router_dhcp':{'host':'router','user':'admin','identity_file':'key'},'listen':'192.168.1.2'}
        d=HostDiscovery(s,config,stop)
        links={'192.168.1.10':'aa:bb:cc:dd:ee:01','2001:db8::10':'aa:bb:cc:dd:ee:01','192.168.1.12':'aa:bb:cc:dd:ee:03'}
        with patch('discovery.neighbors',return_value=links),patch('router_dhcp.fetch_router_dhcp',return_value=parse_snapshot(SAMPLE)),patch('discovery.mdns_names',return_value={'2001:db8::10':'mDNS-laptop.local','192.168.1.12':'mDNS-tablet.local'}) as mdns:
            d.refresh()
            self.assertNotIn('192.168.1.10',mdns.call_args.args[0])
        labels={ip:r['name'] for r in s.devices() for ip in r['ips']}
        self.assertEqual(labels['192.168.1.10'],'dhcp-laptop')
        self.assertEqual(labels['2001:db8::10'],'dhcp-laptop')
        self.assertEqual(labels['192.168.1.12'],'mDNS-tablet')
        with patch('discovery.neighbors',return_value=links),patch('router_dhcp.fetch_router_dhcp',side_effect=OSError('offline')),patch('discovery.mdns_names',return_value={}):
            d.refresh()
        self.assertIsNotNone(s.meta('router_dhcp_error_at'))
        labels={ip:r['name'] for r in s.devices() for ip in r['ips']}
        self.assertEqual(labels['192.168.1.10'],'dhcp-laptop')
        s.db.close()

    def test_deleted_dhcp_name_falls_back_to_mdns(self):
        s=Store(':memory:');mac='aa:bb:cc:dd:ee:01';address='192.168.1.10'
        s.discover_hosts([{'ip':address,'mac':mac,'name':'dhcp-name','source':'主路由 DHCP'}],{address:mac},now=100)
        s.discover_hosts([{'ip':address,'mac':mac,'name':'mdns-name','source':'mDNS'}],{address:mac},now=101)
        self.assertEqual(s.devices()[0]['name'],'mdns-name')
        s.discover_hosts([{'ip':address,'mac':mac,'name':'new-name','source':'主路由 DHCP'}],{address:mac},now=102)
        s.discover_hosts([],{address:mac},now=103)
        self.assertFalse(any(address in d['ips'] for d in s.devices()))
        s.db.close()

    def test_background_service_home_does_not_change_known_hosts_location(self):
        import subprocess
        with patch.dict('os.environ', {'HOME':'/'}), patch('router_dhcp.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=SAMPLE)) as run:
            rows=fetch_router_dhcp({'host':'192.168.1.1','user':'admin','identity_file':'/private/key'})
            self.assertEqual(rows[0]['name'],'dhcp-laptop')
            self.assertNotEqual(run.call_args.kwargs['env']['HOME'],'/')
