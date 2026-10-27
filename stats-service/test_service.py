import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer

from service import Store, make_handler, Collector


def connection(upload=100, download=200, id='a', source='192.168.50.10', node='HK-HKG', policy='YouTube'):
    return dict(id=id, upload=upload, download=download, metadata={'sourceIP': source, 'destinationIP': '1.1.1.1', 'host': 'example.com'}, chains=[node, policy], rule='RuleSet', rulePayload='youtube')


def payload(up, down, *connections):
    return dict(uploadTotal=up, downloadTotal=down, connections=list(connections))


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.device = self.store.save_device({'name': 'MacBook', 'ips': ['192.168.50.10', '2001:db8::1']}, now=99)
        self.store.save_node({'node': 'HK-HKG', 'entry_vps': 'HK', 'exit_vps': 'HKG'})

    def tearDown(self):
        self.store.db.close()

    def query(self, dimension='device', **filters):
        return self.store.query({k: [str(v)] for k, v in dict(start=60, end=300, dimension=dimension, **filters).items()})

    def test_baseline_delta_new_connection_and_no_double_count(self):
        s = self.store
        s.sample(payload(100, 200, connection()), now=100)
        s.sample(payload(160, 300, connection(140, 270), connection(20, 30, id='b', source='2001:db8::1')), now=101)
        s.sample(payload(160, 300, connection(140, 270), connection(20, 30, id='b', source='2001:db8::1')), now=102)
        q = self.query()
        self.assertEqual(q['total'], {'upload': 60, 'download': 100})
        self.assertEqual(q['rows'][0]['key'], self.device)
        self.assertEqual(self.query('entry_vps')['rows'][0]['key'], 'HK')
        self.assertEqual(self.query('exit_vps')['rows'][0]['key'], 'HKG')
        self.assertEqual(self.query('policy')['rows'][0]['key'], 'YouTube')
        self.assertEqual(self.query(device='other')['rows'], [])
        self.assertEqual(self.query(source_ip='2001:db8::1')['total']['download'], 30)

    def test_close_short_connections_coverage_difference(self):
        self.store.sample(payload(0, 0), now=100)
        self.store.sample(payload(500, 900, connection(100, 200)), now=101)
        q = self.query()
        self.assertEqual(q['coverage']['download'], 900)
        self.assertEqual(q['total']['download'], 200)
        self.assertEqual(q['coverage']['observed_download'], 200)
        self.assertEqual(q['series'][0]['download'], 200)

    def test_reset_failure_and_gap_rebaseline(self):
        s = self.store
        s.sample(payload(100, 200, connection()), now=100)
        s.sample(payload(1, 2, connection(1, 2)), now=101)
        s.sample(payload(2, 4, connection(2, 4)), now=102)
        s.failure(now=103)
        s.sample(payload(20, 40, connection(20, 40)), now=104)
        s.sample(payload(30, 60, connection(30, 60)), now=120)
        s.sample(payload(32, 64, connection(32, 64)), now=121)
        q = self.query()
        self.assertEqual(q['total'], {'upload': 3, 'download': 6})
        self.assertEqual({e['kind']: e['count'] for e in q['events']}, {'baseline': 1, 'fetch_error': 1, 'gap': 2, 'reset': 1})

    def test_device_reassignment_retains_history(self):
        s = self.store
        s.sample(payload(0, 0), now=100)
        s.sample(payload(10, 20, connection(10, 20)), now=101)
        s.save_device({'id': self.device, 'name': '旧机器', 'ips': []}, now=101.5)
        other = s.save_device({'name': '新机器', 'ips': ['192.168.50.10']}, now=101.6)
        s.sample(payload(30, 60, connection(30, 60)), now=102)
        q = {r['key']: r for r in self.query()['rows']}
        self.assertEqual(q[self.device]['download'], 20)
        self.assertEqual(q[other]['download'], 40)
        self.assertEqual(q[self.device]['label'], '旧机器')
        self.assertEqual(s.db.execute('SELECT COUNT(*) FROM bindings WHERE until IS NOT NULL').fetchone()[0], 2)

    def test_binding_conflicts_and_ipv6_normalization(self):
        with self.assertRaises(ValueError):
            self.store.save_device({'name': 'other', 'ips': ['::ffff:192.168.50.10']})
        with self.assertRaises(ValueError):
            self.store.save_device({'name': 'other', 'ips': ['invalid']})
        self.assertEqual(len(self.store.devices()), 1)

    def test_node_mapping_changes_only_future_and_rule_lookup(self):
        s = self.store
        s.sample(payload(0, 0), now=100)
        s.sample(payload(10, 20, connection(10, 20)), {('RuleSet', 'youtube'): '视频'}, now=101)
        s.save_node({'node': 'HK-HKG', 'entry_vps': 'HK2', 'exit_vps': 'HKG'})
        s.sample(payload(20, 40, connection(20, 40)), now=102)
        self.assertEqual({r['key'] for r in self.query('entry_vps')['rows']}, {'HK', 'HK2'})
        self.assertEqual(self.query('policy', policy='视频')['total']['download'], 20)

    def test_invalid_payload_does_not_advance_checkpoint(self):
        self.store.sample(payload(0, 0), now=100)
        with self.assertRaises(ValueError):
            self.store.sample(payload(3, 4, {'id': 'a', 'upload': -1, 'download': 1}), now=101)
        self.assertEqual(self.store.meta('checkpoint')['at'], 100)
        with self.assertRaises(ValueError):
            self.query("node; DROP TABLE buckets")

    def test_database_reopen_preserves_checkpoints(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / 'stats.sqlite3')
            s = Store(path)
            s.sample(payload(100, 200, connection()), now=100)
            s.db.close()
            s = Store(path)
            s.sample(payload(130, 250, connection(130, 250)), now=101)
            q = s.query({'start': ['60'], 'end': ['300']})
            self.assertEqual(q['total'], {'upload': 30, 'download': 50})
            s.db.close()

    def test_direct_and_unmapped_nodes_and_retention(self):
        self.store.sample(payload(0, 0), now=100)
        self.store.sample(payload(2, 4, connection(1, 2, node='DIRECT'), connection(1, 2, id='b', node='new-node')), now=101)
        self.assertEqual({r['key'] for r in self.query('exit_vps')['rows']}, {'不适用', '未映射'})
        self.store.sample(payload(3, 6), now=100 + 91 * 86400)
        self.assertEqual(self.query()['rows'], [])

    def test_nested_group_counters_deduplicate_and_survive_node_switch(self):
        s = self.store
        s.sample(payload(0, 0), now=100)
        first = connection(10, 20)
        first['chains'] = ['node-a', 'HKS', 'Proxy', 'Microsoft', 'HKS']
        s.sample(payload(10, 20, first), now=101)
        second = connection(30, 60, id='b')
        second['chains'] = ['node-b', 'SG', 'Proxy', 'Microsoft']
        s.sample(payload(40, 80, first, second), now=102)
        s.sample(payload(40, 80, first, second), now=103)
        counters = {r['name']: dict(r) for r in s.db.execute('SELECT * FROM chain_totals')}
        self.assertEqual(counters['HKS']['download'], 20)
        self.assertEqual(counters['SG']['download'], 60)
        self.assertEqual(counters['Microsoft']['download'], 80)
        self.assertEqual(counters['Proxy']['download'], 80)
        self.assertEqual(self.query()['total']['download'], 80)
        self.assertEqual(s.meta('chain_since'), 100)
        # Retention removes minute history, but lifetime card counters remain.
        s.sample(payload(40, 80), now=100 + 91*86400)
        self.assertEqual(s.db.execute('SELECT download FROM chain_totals WHERE name=?', ('Microsoft',)).fetchone()[0], 80)

    def test_schema_one_migrates_without_rewriting_history(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / 'stats.sqlite3')
            s = Store(path)
            s.sample(payload(0, 0), now=100)
            s.sample(payload(10, 20, connection(10, 20)), now=101)
            s.db.execute('DROP TABLE chain_totals')
            s.db.execute("DELETE FROM meta WHERE key='chain_since'")
            s.db.execute('PRAGMA user_version=1')
            s.db.commit(); s.db.close()
            s = Store(path)
            self.assertEqual(s.db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(s.db.execute('SELECT COUNT(*) FROM chain_totals').fetchone()[0], 0)
            s.sample(payload(20, 40, connection(20, 40)), now=102)
            self.assertEqual(s.db.execute('SELECT download FROM chain_totals WHERE name=?', ('YouTube',)).fetchone()[0], 20)
            self.assertEqual(s.query({'start':['60'], 'end':['300']})['total']['download'], 40)
            s.db.close()
            s = Store(path)
            self.assertEqual(s.db.execute('SELECT download FROM chain_totals WHERE name=?', ('YouTube',)).fetchone()[0], 20)
            self.assertEqual(s.meta('chain_since'), 102)
            s.db.close()


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(':memory:')
        self.config = dict(require_auth=True, api_token='a' * 32, source_id='test', interval=1, static_dir=self.temp.name, allowed_origins=['http://localhost:5173'])
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.store, self.config))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.db.close()
        self.temp.cleanup()

    def request(self, path, data=None, token=True, origin=None):
        headers = {'Authorization': 'Bearer ' + self.config['api_token']} if token else {}
        if origin:
            headers['Origin'] = origin
        request = Request(self.url + '/api/stats/' + path, headers=headers, data=json.dumps(data).encode() if data is not None else None, method='PUT' if data is not None else 'GET')
        return urlopen(request, timeout=3)

    def test_auth_cors_and_device_crud(self):
        for token, origin in [(False, None), (True, 'https://evil.example')]:
            with self.assertRaises(HTTPError) as error:
                self.request('status', token=token, origin=origin)
            self.assertEqual(error.exception.code, 401)
        with self.request('status', origin='http://localhost:5173') as response:
            self.assertEqual(response.headers['Access-Control-Allow-Origin'], 'http://localhost:5173')
            self.assertEqual(json.load(response)['source_id'], 'test')
        with self.request('devices', {'name': '电脑', 'ips': ['192.168.1.2']}) as response:
            self.assertTrue(json.load(response)['id'])
        with self.request('devices') as response:
            self.assertEqual(json.load(response)[0]['name'], '电脑')
        with self.assertRaises(HTTPError) as error:
            self.request('devices', {'name': 'bad', 'ips': ['invalid']})
        self.assertEqual(error.exception.code, 400)

    def test_group_totals_http_requires_auth_and_returns_chain_counters(self):
        self.store.sample(payload(0, 0), now=100)
        self.store.sample(payload(10, 20, connection(10, 20)), now=101)
        with self.request('group-totals') as response:
            totals = json.load(response)
        self.assertEqual(totals['since'], 100)
        self.assertEqual({r['name']: r['download'] for r in totals['rows']}['YouTube'], 20)
        with self.assertRaises(HTTPError) as error:
            self.request('group-totals', token=False)
        self.assertEqual(error.exception.code, 401)
        error.exception.close()

    def test_lan_mode_automatically_allows_read_and_device_write(self):
        self.config['require_auth'] = False
        with self.request('status', token=False) as response:
            self.assertFalse(json.load(response)['auth_required'])
        with self.request('devices', {'name': '内网设备', 'ips': ['192.168.1.8']}, token=False) as response:
            self.assertTrue(json.load(response)['id'])
        with self.request('devices', token=False) as response:
            self.assertEqual(json.load(response)[0]['name'], '内网设备')

    def test_static_api_isolation(self):
        with self.assertRaises(HTTPError):
            urlopen(self.url + '/', timeout=3)
        with self.assertRaises(HTTPError) as error:
            self.request('missing')
        self.assertEqual(error.exception.code, 404)

    def test_real_collector_polling_and_backend_failure(self):
        # A real local HTTP Mihomo stub exercises collection separately from browser traffic.
        from http.server import BaseHTTPRequestHandler
        state = {'up': 0, 'fail': False, 'auth': ''}
        class Mock(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                state['auth'] = self.headers.get('Authorization')
                if state['fail']:
                    self.send_error(503)
                    return
                if self.path == '/rules':
                    data = {'rules': []}
                else:
                    state['up'] += 10
                    data = payload(state['up'], state['up'] * 2, connection(state['up'], state['up'] * 2))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
        import time
        mock = ThreadingHTTPServer(('127.0.0.1', 0), Mock)
        t = threading.Thread(target=mock.serve_forever, daemon=True)
        t.start()
        stop = threading.Event()
        collector = Collector(self.store, {'controller': f'http://127.0.0.1:{mock.server_port}', 'controller_secret': 'test-secret', 'interval': .2}, stop)
        collector.start()
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                with self.request('summary') as response:
                    summary = json.load(response)
                if summary['total']['upload'] >= 10: break
                time.sleep(.05)
            self.assertGreaterEqual(summary['total']['upload'], 10)
            self.assertEqual(state['auth'], 'Bearer test-secret')
            state['fail'] = True
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                with self.request('status') as response: status = json.load(response)
                if not status['healthy']: break
                time.sleep(.05)
            self.assertFalse(status['healthy'])
        finally:
            stop.set(); collector.join(3); mock.shutdown(); mock.server_close(); t.join()


if __name__ == '__main__':
    unittest.main()
