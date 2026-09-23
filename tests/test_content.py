import hashlib
import base64
import json
import tempfile
from pathlib import Path
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from agent_hooks_protocol.content import upload, receive
from agent_hooks_protocol.lifecycle import ContentStore
from agent_hooks_protocol.runtime import Validator, ProtocolError


class ContentTests(unittest.TestCase):
    def test_binary_binding_and_independent_auth(self):
        store = ContentStore(Validator(), lambda subscription: subscription == 'body')
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                calls.append((self.path, self.headers.get('Authorization')))
                data = self.rfile.read(int(self.headers['Content-Length']))
                assert self.headers.get('AHP-Subscription') is None
                assert self.headers.get('AHP-Content-Ref') is None
                status, descriptor = receive(store, self.headers, data, lambda auth:
                    (201, 'body') if auth == 'Bearer upload-only' else (401, None))
                body = json.dumps(descriptor).encode() if descriptor else b''
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        config = {'endpoint': f'http://127.0.0.1:{server.server_port}/exact?query=1',
                  'auth': {'type': 'bearer', 'tokenEnv': 'AHP_TEST_UPLOAD'}}
        data = b'\x00\xff\xfe\x80hello'
        try:
            with patch.dict(os.environ, {'AHP_TEST_UPLOAD': 'upload-only'}):
                refs = []
                for _ in range(2):
                    status, ref = upload(config, data, loopback=True)
                    self.assertEqual(status, 201)
                    self.assertEqual(ref['size'], len(data))
                    self.assertEqual(store.blobs['body', ref['ref']], data)
                    refs.append(ref['ref'])
                self.assertNotEqual(*refs)
                self.assertEqual(upload(config, b'changed', loopback=True)[0], 201)
                self.assertEqual(upload({'endpoint': config['endpoint']}, data, loopback=True), (401, None))
                self.assertEqual(upload(config, b'', loopback=True)[0], 201)
            self.assertTrue(all(path == '/exact?query=1' for path, _ in calls))
            self.assertIsNone(calls[-2][1])
        finally:
            server.shutdown(); server.server_close(); worker.join()

    def test_configured_event_credentials_are_not_inherited_by_upload(self):
        from agent_hooks_protocol.lifecycle_server import Server
        from agent_hooks_protocol.lifecycle_client import run
        from test_interop import request, response
        calls = []
        class Receiver(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                calls.append({'path': self.path, 'authorization': self.headers.get('Authorization'), 'body': body})
                descriptor = json.dumps({'ref': 'allocated', 'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}).encode()
                self.send_response(201)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(descriptor)))
                self.end_headers()
                self.wfile.write(descriptor)
        upload_server = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        worker = threading.Thread(target=upload_server.serve_forever)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                req = request()
                data = b'\xff\x00isolation'
                steps = [
                    {'op': 'upload', 'subscription': 'body', 'ref': 'isolated',
                     'bodyBase64': base64.b64encode(data).decode()},
                    {'op': 'send', 'key': 'a', 'slot': 'request'}, {'op': 'wait', 'key': 'a'},
                    {'op': 'release', 'key': 'a'}, {'op': 'receive', 'slot': 'request'}, {'op': 'accept', 'key': 'a'},
                ]
                scenario = root / 'scenario.json'
                scenario.write_text(json.dumps({'scenarios': [{'id': 'credentials-independent', 'requests': {'a': req},
                    'responses': {'a': response([{'type': 'allow'}])}, 'steps': steps}]}))
                auth = {'mode': 'bearer', 'token': 'TEST-event-only-credential'}
                config = {'transport': 'http', 'scenarioFile': str(scenario), 'auth': auth}
                server = Server(config)
                try:
                    config.update(endpoint=server.listener(False), controlEndpoint=server.listener(True),
                                  reportFile=str(root / 'report.json'), upload={
                                      'endpoint': f'http://127.0.0.1:{upload_server.server_port}/raw?exact=1',
                                      'timeoutMs': 2000, 'maxBytes': 1024})
                    run(config)
                    report = json.loads((root / 'report.json').read_text())
                    self.assertEqual(report['results'][0]['actual']['uploadStatuses'], [201])
                    self.assertEqual(calls, [{'path': '/raw?exact=1', 'authorization': None, 'body': data}])
                    received = [e for e in server.entries if e['kind'] == 'received']
                    self.assertEqual(received[0]['message'], req)  # Event receiver required the configured bearer.
                finally:
                    server.stop()
                    for listener in server.listeners:
                        listener.shutdown(); listener.server_close()
        finally:
            upload_server.shutdown(); upload_server.server_close(); worker.join()

    def test_bad_framing_hash_and_size(self):
        store = ContentStore(Validator(), lambda _: True)
        headers = {'Content-Type': 'application/octet-stream', 'Content-Length': '1',
                   'AHP-Content-SHA256': hashlib.sha256(b'x').hexdigest()}
        grant = lambda *_: (201, 'scope')
        self.assertEqual(receive(store, headers, b'x', grant)[0], 201)
        for changes in [{'Content-Length': '2'}, {'Transfer-Encoding': 'chunked'},
                        {'Content-Encoding': 'gzip'}, {'Content-Type': 'application/json'},
                        {'AHP-Content-SHA256': '0' * 64}, {'AHP-Subscription': '===='}]:
            self.assertEqual(receive(store, {**headers, **changes}, b'x', grant), (400, None))
        self.assertEqual(receive(store, headers, b'x', grant, limit=0), (413, None))

    def test_sender_rejects_unconfirmed_and_mismatched_descriptors(self):
        from io import BytesIO
        from types import SimpleNamespace
        from agent_hooks_protocol.interop import validate_descriptor
        data = b'abc'
        correct = {'ref': 'allocated', 'size': 3, 'sha256': hashlib.sha256(data).hexdigest()}
        for status, kind, descriptor in [
                (204, 'application/json', correct), (202, 'application/json', correct),
                (201, 'text/plain', correct), (201, 'application/json', {}),
                (201, 'application/json', {**correct, 'size': 2}),
                (201, 'application/json', {**correct, 'sha256': '0' * 64}),
                (201, 'application/json', {**correct, 'ref': ''})]:
            with self.subTest(status=status, descriptor=descriptor):
                response = SimpleNamespace(status=status, headers={'Content-Type': kind},
                                           read=BytesIO(json.dumps(descriptor).encode()).read)
                with self.assertRaises(ProtocolError):
                    validate_descriptor(response, data, Validator())

    def test_credential_scope_not_correlation_and_explicit_anonymous_grants(self):
        from agent_hooks_protocol.lifecycle_server import Server
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'fixture.json'
            fixture.write_text('{"scenarios": []}')
            server = Server({'transport': 'http', 'scenarioFile': str(fixture),
                             'uploadSubscriptions': {'alice': 'AHP_ALICE', 'bob': 'AHP_BOB'},
                             'future': {}, 'auth': {'mode': 'none', 'future': True}})
            with patch.dict(os.environ, {'AHP_ALICE': 'alice-token', 'AHP_BOB': 'bob-token'}):
                self.assertEqual(server.authorize_upload('Bearer alice-token'), (201, 'alice'))
                self.assertEqual(server.authorize_upload('Bearer bob-token'), (201, 'bob'))
                self.assertEqual(server.authorize_upload(None), (401, None))
            server.upload_subscriptions = {}
            self.assertEqual(server.authorize_upload(None), (401, None))
            server.upload_subscriptions = {'anonymous': None}
            self.assertEqual(server.authorize_upload(None), (201, 'anonymous'))
            server.upload_subscriptions['other'] = None
            self.assertEqual(server.authorize_upload(None), (403, None))

    def test_upload_config_extensions_and_known_validation(self):
        validator = Validator()
        config = {'endpoint': 'https://example.test/content', 'timeoutMs': 1000, 'maxBytes': 100,
                  'future': {}, 'auth': {'type': 'bearer', 'tokenEnv': 'TOKEN', 'future': []}}
        validator.validate('content-upload', config)
        for key, value in [('timeoutMs', False), ('maxBytes', -1), ('endpoint', 3)]:
            with self.assertRaises(ProtocolError):
                upload({**config, key: value}, b'abc')
        with patch.dict(os.environ, {'TOKEN': 'bad\r\ntoken'}):
            with self.assertRaises(ProtocolError):
                upload(config, b'abc')

    def test_single_receiver_context_defaults_and_explicit_scope_validation(self):
        from agent_hooks_protocol.lifecycle_server import Server
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'fixture.json'
            fixture.write_text('{"scenarios": []}')
            for transport in ('http', 'stdio'):
                config = {'transport': transport, 'scenarioFile': str(fixture),
                          'uploadAuth': {'token': 'upload-token'}}
                server = Server(config)
                self.assertEqual(server.authorize_upload('Bearer upload-token'), (201, server.event_scope))
                self.assertNotEqual(server.event_scope, Server(config).event_scope)
                self.assertEqual(server.authorize_upload('Bearer event-token'), (401, None))
                for scope in (None, '', 3, False):
                    with self.assertRaises(ProtocolError):
                        Server({**config, 'uploadAuth': {'token': 'upload-token', 'scope': scope}})
