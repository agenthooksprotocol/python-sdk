"""Real lifecycle HTTP authentication and independent binary-upload coverage."""
import base64
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from agent_hooks_protocol.lifecycle_server import Server
from agent_hooks_protocol.lifecycle_client import Transport, run, http
from agent_hooks_protocol.content import upload
from agent_hooks_protocol.runtime import ProtocolError
from test_interop import request, response, jwt, FIXTURES


class LifecycleAuthTests(unittest.TestCase):
    def exercise(self, mode):
        issuer = None
        common = {'mode': mode, 'scope': 'body'}
        if mode == 'bearer':
            common['token'] = 'TEST-event-token'
        server_auth, client_auth = dict(common), dict(common)
        if mode in ('oauth', 'workload'):
            server_auth.update(signingKey='TEST-signing-key', issuer='urn:test:issuer',
                               audience='urn:test:audience', purpose=mode, clock=1893456000)
            if mode == 'workload':
                client_auth['assertion'] = jwt(server_auth)
            else:
                class Issuer(BaseHTTPRequestHandler):
                    def log_message(self, *_): pass
                    def do_POST(self):
                        self.rfile.read(int(self.headers['Content-Length']))
                        body = json.dumps({'access_token': jwt(server_auth)}).encode()
                        self.send_response(200); self.end_headers(); self.wfile.write(body)
                issuer = ThreadingHTTPServer(('127.0.0.1', 0), Issuer)
                threading.Thread(target=issuer.serve_forever, daemon=True).start()
                client_auth.update(tokenEndpoint=f'http://127.0.0.1:{issuer.server_port}/token',
                                   clientId='test', clientSecret='TEST-secret', audience=server_auth['audience'])
        if mode == 'mtls':
            for auth, identity in [(server_auth, 'server'), (client_auth, 'client')]:
                auth.update(caFile=str(FIXTURES / 'ca.pem'), certFile=str(FIXTURES / f'{identity}.pem'),
                            keyFile=str(FIXTURES / f'{identity}-key.pem'))
        try:
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'TEST_UPLOAD_TOKEN': 'TEST-upload-token'}):
                root = Path(directory)
                req = request()
                reply = response([{'type': 'allow'}])
                data = b'\x00\xff\x80upload'
                from hashlib import sha256
                blob = {'ref': 'ref', 'size': len(data), 'sha256': sha256(data).hexdigest()}
                item = {'id': 'binary', 'kind': 'text', 'mediaType': 'application/octet-stream', 'selection': 'body', 'body': blob}
                fixture = {'scenarios': [{'id': 'auth', 'requests': {'a': req}, 'responses': {'a': reply}, 'steps': [
                    {'op': 'upload', 'subscription': 'body', 'bodyBase64': base64.b64encode(data).decode(), **blob},
                    {'op': 'upload', 'subscription': 'body', 'bodyBase64': base64.b64encode(data).decode(), **blob, 'size': 99},
                    {'op': 'upload', 'subscription': 'body', 'bodyBase64': base64.b64encode(data).decode(), **blob, 'sha256': '0'*64},
                    {'op': 'send', 'key': 'a', 'slot': 'first'}, {'op': 'wait', 'key': 'a'},
                    {'op': 'release', 'key': 'a'}, {'op': 'receive', 'slot': 'first'}, {'op': 'accept', 'key': 'a'},
                    {'op': 'observe', 'key': 'a', 'subscription': 'body', 'items': [item]}]}]}
                scenario = root / 'scenarios.json'; scenario.write_text(json.dumps(fixture))
                config = {'transport': 'http', 'scenarioFile': str(scenario), 'auth': server_auth,
                          'uploadAuth': {'token': 'TEST-upload-token', 'scope': 'body'}}
                server = Server(config)
                try:
                    control = server.listener(True)
                    endpoint = server.listener(False)
                    upload_endpoint = server.listener(False, upload_only=True) + '/content'
                    upload_config = {'endpoint': upload_endpoint, 'timeoutMs': 2000, 'maxBytes': 1024,
                                     'auth': {'type': 'bearer', 'tokenEnv': 'TEST_UPLOAD_TOKEN'}}
                    self.assertEqual(upload({'endpoint': upload_endpoint}, data, loopback=True)[0], 401)
                    if mode not in ('none', 'mtls'):
                        self.assertEqual(http(endpoint + '/intercept', req)[0], 401)
                        self.assertFalse(any(e['kind'] == 'received' for e in server.entries))
                    client = {'transport': 'http', 'scenarioFile': str(scenario), 'reportFile': str(root / 'report.json'),
                              'auth': client_auth, 'endpoint': endpoint, 'controlEndpoint': control, 'upload': upload_config}
                    run(client)
                    report = json.loads((root / 'report.json').read_text())
                    self.assertEqual(report['results'][0]['actual']['uploadStatuses'], [201, 400, 400])
                    received = next(e for e in server.entries if e['kind'] == 'received')
                    observed = next(e for e in server.entries if e['kind'] == 'observed')
                    self.assertEqual(received['message'], req)
                    self.assertEqual(observed['message']['params']['event'], observed['event'])
                    self.assertNotIn('disposition', observed['message']['params'])
                    self.assertEqual(server.content.blobs['body', observed['event']['items'][0]['body']['ref']], data)
                finally:
                    server.stop()
                    for listener in server.listeners:
                        listener.shutdown(); listener.server_close()
        finally:
            if issuer:
                issuer.shutdown(); issuer.server_close()

    def test_none(self): self.exercise('none')
    def test_bearer(self): self.exercise('bearer')
    def test_oauth(self): self.exercise('oauth')
    def test_workload(self): self.exercise('workload')
    def test_mtls(self): self.exercise('mtls')
    def test_stdio_rejects_event_auth(self):
        with self.assertRaises(ProtocolError):
            Transport({'transport': 'stdio', 'auth': {'mode': 'bearer', 'token': 'test'}})
