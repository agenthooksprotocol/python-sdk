from copy import deepcopy
import base64
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from agent_hooks_protocol.lifecycle import ContentStore, Lifecycle
from agent_hooks_protocol.lifecycle_client import run, http, Transport
from agent_hooks_protocol.runtime import Validator, ProtocolError
from test_interop import request, response


class LifecycleTests(unittest.TestCase):
    def test_staging_cancellation_correlation_and_atomic_publication(self):
        lifecycle = Lifecycle(Validator())
        req = request()
        ident = req['id']
        reply = response([{'type': 'message', 'text': 'private'}])
        lifecycle.send(req)
        wrong = deepcopy(reply)
        wrong['id'] = 'stale'
        self.assertFalse(lifecycle.receive(req, wrong))
        self.assertTrue(lifecycle.receive(req, reply))
        self.assertEqual(lifecycle.states, {})
        self.assertFalse(lifecycle.receive(req, response([{'type': 'message', 'text': 'replacement'}])))
        self.assertTrue(lifecycle.cancel(ident))
        self.assertFalse(lifecycle.receive(req, reply))
        lifecycle.send(req)
        self.assertIsNone(lifecycle.accept(ident, fallback=True))
        self.assertIsNone(lifecycle.accept(ident))
        self.assertEqual(lifecycle.states, {})
        settled = Lifecycle(Validator())
        settled.send(req)
        self.assertTrue(settled.receive(req, reply))
        self.assertEqual(settled.accept(ident)['messages'], ['private'])
        self.assertIsNone(settled.accept(ident))
        self.assertFalse(settled.receive(req, reply))
        self.assertTrue(settled.cancel(ident))
        self.assertIsNone(settled.accept(ident, fallback=True))

    def test_immutable_receiver_and_authorization(self):
        validator = Validator()
        store = ContentStore(validator, lambda subscription: subscription == 'body')
        value = {'scope': 'body', 'data': 'é'.encode(), 'size': 2,
                 'sha256': sha256('é'.encode()).hexdigest()}
        status, descriptor = store.upload(value)
        self.assertEqual(status, 201)
        self.assertNotEqual(store.upload(value)[1]['ref'], descriptor['ref'])
        self.assertEqual(store.upload({**value, 'scope': 'metadata'}), (403, None))
        self.assertEqual(store.upload({**value, 'size': 1}), (400, None))
        self.assertEqual(store.upload({**value, 'data': b'ab', 'sha256': sha256(b'ab').hexdigest()})[0], 201)
        self.assertEqual(store.blobs['body', descriptor['ref']], value['data'])
        lifecycle = Lifecycle(validator)
        req = request()
        lifecycle.send(req)
        with self.assertRaises(ProtocolError):
            lifecycle.observe(req, 'body')
        lifecycle.accept(req['id'], fallback=True)
        item = {'id': 'content-1', 'kind': 'text', 'mediaType': 'text/plain', 'selection': 'body',
                'body': descriptor}
        note = lifecycle.observe(req, 'body', [item])
        store.verify(note, 'body')
        self.assertNotIn('subscriptionId', note['params'])
        with self.assertRaises(ProtocolError):
            store.verify(note, 'metadata')
        note['params']['event']['items'][0]['body']['ref'] = 'missing'
        with self.assertRaises(ProtocolError):
            store.verify(note, 'body')

    def test_stdio_reverse_order_and_unmatched_frames_leave_pending_usable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = request()
            b = deepcopy(a)
            b['id'] = b['params']['event']['id'] = 'reverse-b'
            ra = response([{'type': 'message', 'text': 'belongs-to-a'}])
            rb = {'jsonrpc': '2.0', 'id': b['id'], 'result': {'protocolVersion': 'draft',
                  'effects': [{'type': 'message', 'text': 'belongs-to-b'}]}}
            fixture = root / 'fixture.json'
            fixture.write_text(json.dumps({'version': 1, 'scenarios': [{
                'requests': {'a': a, 'b': b}, 'responses': {'a': ra, 'b': rb}}]}))
            config_path = root / 'server.json'
            config_path.write_text(json.dumps({'transport': 'stdio', 'scenarioFile': str(fixture),
                'readinessFile': str(root / 'ready.json'), 'auth': {'mode': 'none', 'scope': 'body'},
                                 'stdioScope': 'body', 'uploadSubscriptions': {'body': None}}))
            transport = Transport({'transport': 'stdio', 'serverConfig': str(config_path),
                'serverCommand': [sys.executable, '-m', 'agent_hooks_protocol.lifecycle_server'],
                'childPidFile': str(root / 'child.json')})
            try:
                lifecycle = Lifecycle(Validator())
                lifecycle.send(a)
                lifecycle.send(b)
                fa, fb = transport.send(a), transport.send(b)
                for req in (a, b):
                    transport.control('/wait', {'id': req['id']})
                unknown = deepcopy(ra)
                unknown['id'] = 'never-requested'
                transport.emit(unknown)
                self.assertFalse(fa.done())
                self.assertFalse(fb.done())
                transport.control('/release', {'id': b['id']})
                self.assertTrue(lifecycle.receive(b, fb.result(timeout=5)))
                # An already-drained ID must not consume the still-live A attempt.
                transport.emit(rb)
                self.assertFalse(fa.done())
                transport.control('/release', {'id': a['id']})
                self.assertTrue(lifecycle.receive(a, fa.result(timeout=5)))
                self.assertEqual(lifecycle.accept(a['id'])['messages'], ['belongs-to-a'])
                self.assertEqual(lifecycle.accept(b['id'])['messages'], ['belongs-to-b'])
                entries = transport.control('/receipts')['entries']
                self.assertEqual([e['id'] for e in entries if e['kind'] == 'replied'],
                                 [b['id'], a['id']])
                self.assertEqual(transport.discarded['never-requested'], 1)
                self.assertEqual(transport.discarded[b['id']], 1)
            finally:
                transport.close()
            self.assertEqual(transport.process.returncode, 0)

    def test_real_http_and_stdio_lifecycle(self):
        for transport in ('http', 'stdio'):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                a = request()
                b = deepcopy(a)
                b['id'] = b['params']['event']['id'] = 'lifecycle-b'
                c = deepcopy(a)
                c['id'] = c['params']['event']['id'] = 'lifecycle-c'
                rc = {'jsonrpc': '2.0', 'id': c['id'], 'result': {'protocolVersion': 'draft', 'effects': [
                    {'type': 'modify', 'target': 'input', 'operation': 'replace', 'value': {'task': 3}}]}}
                ra = response([{'type': 'message', 'text': 'cancelled-private'}])
                rb = {'jsonrpc': '2.0', 'id': b['id'], 'result': {'protocolVersion': 'draft', 'effects': [
                    {'type': 'modify', 'target': 'input', 'operation': 'replace', 'value': {'task': 2}}]}}
                blob = {'subscription': 'body', 'ref': 'blob', 'bodyBase64': base64.b64encode(b'hello').decode(), 'size': 5,
                        'sha256': sha256(b'hello').hexdigest()}
                item = {'id': 'content-1', 'kind': 'text', 'mediaType': 'text/plain', 'selection': 'body',
                        'body': {k: blob[k] for k in ('ref', 'size', 'sha256')}}
                steps = [
                    {'op': 'send', 'key': 'a', 'slot': 'a1'}, {'op': 'wait', 'key': 'a'},
                    {'op': 'send', 'key': 'b', 'slot': 'b1'}, {'op': 'wait', 'key': 'b'},
                    {'op': 'release', 'key': 'b'}, {'op': 'receive', 'slot': 'b1'},
                    {'op': 'cancel', 'key': 'a'},
                    {'op': 'send', 'key': 'b', 'slot': 'b2'}, {'op': 'receive', 'slot': 'b2'},
                    {'op': 'accept', 'key': 'b'},
                    {'op': 'release', 'key': 'a'}, {'op': 'receive', 'slot': 'a1'},
                    {'op': 'failOpen', 'key': 'a'}, {'op': 'accept', 'key': 'a'},
                    {'op': 'send', 'key': 'b', 'slot': 'b3'}, {'op': 'receive', 'slot': 'b3'},
                    {'op': 'accept', 'key': 'b'},
                    {'op': 'send', 'key': 'c', 'slot': 'c1'}, {'op': 'wait', 'key': 'c'},
                    {'op': 'release', 'key': 'c'}, {'op': 'receive', 'slot': 'c1'},
                    {'op': 'accept', 'key': 'c'}, {'op': 'cancel', 'key': 'c'},
                    {'op': 'failOpen', 'key': 'c'}, {'op': 'accept', 'key': 'c'},
                    {'op': 'observe', 'key': 'c', 'subscription': 'metadata', 'items': []},
                    {'op': 'upload', **blob},
                    {'op': 'upload', **blob}, {'op': 'upload', **blob, 'subscription': 'metadata'},
                    {'op': 'upload', **blob, 'subscription': 'metadata'},
                    {'op': 'upload', **blob, 'bodyBase64': base64.b64encode(b'world').decode(), 'sha256': sha256(b'world').hexdigest()},
                    {'op': 'observe', 'key': 'b', 'subscription': 'body', 'items': [item]},
                    {'op': 'observe', 'key': 'b', 'subscription': 'metadata', 'items': []},
                    {'op': 'observe', 'key': 'a', 'subscription': 'metadata', 'items': []},
                ]
                emitted = {'jsonrpc': '2.0', 'id': 'stray-frame',
                           'result': {'protocolVersion': 'draft', 'effects': []}}
                if transport == 'stdio':
                    steps.insert(4, {'op': 'emit', 'response': emitted})
                duplicate = deepcopy(rb)
                duplicate['result']['effects'][0]['value'] = {'task': 999}
                fixture = {'version': 1, 'scenarios': [{'id': 'local', 'requests': {'a': a, 'b': b, 'c': c},
                    'responses': {'a': ra, 'b': rb, 'c': rc}, 'responseSequences': {'b': [rb, duplicate]}, 'steps': steps, 'expected': {'deliberately': 'not used'}}]}
                scenario = root / 'fixture.json'
                scenario.write_text(json.dumps(fixture))
                server_config = {'transport': transport, 'scenarioFile': str(scenario),
                                 'readinessFile': str(root / 'ready.json'), 'auth': {'mode': 'none', 'scope': 'body'},
                                 'stdioScope': 'body', 'uploadSubscriptions': {'body': None}}
                sc = root / 'server.json'
                sc.write_text(json.dumps(server_config))
                command = [sys.executable, '-m', 'agent_hooks_protocol.lifecycle_server']
                config = {'transport': transport, 'scenarioFile': str(scenario),
                          'reportFile': str(root / 'report.json'), 'serverConfig': str(sc),
                          'serverCommand': command, 'childPidFile': str(root / 'child.json'), 'auth': {'mode': 'none'}}
                process = None
                try:
                    if transport == 'http':
                        process = subprocess.Popen(command + ['--config', str(sc)])
                        deadline = time.monotonic() + 10
                        ready = root / 'ready.json'
                        while not ready.exists():
                            self.assertIsNone(process.poll())
                            self.assertLess(time.monotonic(), deadline)
                            threading.Event().wait(.01)
                        config.update(json.loads(ready.read_text()))
                    run(config)
                    report = json.loads((root / 'report.json').read_text())
                    self.assertEqual([r['id'] for r in report['results']], ['local'])
                    actual = report['results'][0]['actual']
                    entries = report['receipts']['entries']
                    acquired = [e['id'] for e in entries if e['kind'] == 'acquired']
                    self.assertEqual(acquired, [b['id'], c['id']])
                    observed = [e for e in entries if e['kind'] == 'observed']
                    self.assertEqual([e['event']['tool']['input'] for e in observed],
                                     [{'task': 3}, {'task': 2}, {'task': 2}, a['params']['event']['tool']['input']])
                    self.assertTrue(all('disposition' not in e['message']['params'] for e in observed))
                    if transport == 'stdio':
                        pid = json.loads((root / 'child.json').read_text())['pid']
                        self.assertGreater(pid, 0)
                        import os
                        with self.assertRaises(ProcessLookupError):
                            os.kill(pid, 0)
                    self.assertEqual(actual['published'], [b['id'], c['id']])
                    self.assertEqual(actual['cancelled'], [a['id'], c['id']])
                    self.assertEqual(actual['ignored'],
                                     (['unsolicited:stray-frame'] if transport == 'stdio' else []) + ['b2', 'a1', 'b3'])
                    self.assertEqual(actual['states'][b['id']]['input'], {'task': 2})
                    self.assertEqual(actual['states'][b['id']]['decision'], 'allow')
                    self.assertEqual(actual['uploadStatuses'], [201, 201, 201, 201, 201])
                    self.assertEqual(actual['observations'], [
                        {'eventId': c['id'], 'subscription': 'metadata', 'input': {'task': 3}},
                        {'eventId': b['id'], 'subscription': 'body', 'input': {'task': 2}},
                        {'eventId': b['id'], 'subscription': 'metadata', 'input': {'task': 2}},
                        {'eventId': a['id'], 'subscription': 'metadata', 'input': a['params']['event']['tool']['input']}])
                finally:
                    if process:
                        if config.get('controlEndpoint'):
                            http(config['controlEndpoint'] + '/shutdown', {})
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                        self.assertEqual(process.returncode, 0)


if __name__ == '__main__':
    unittest.main()
