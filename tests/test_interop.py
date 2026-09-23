from copy import deepcopy
import base64
import hashlib
import hmac
import json
import io
import os
from contextlib import contextmanager
from unittest.mock import patch
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
from urllib.error import HTTPError, URLError
from agent_hooks_protocol.runtime import Validator, ProtocolError, apply_response
from agent_hooks_protocol.interop import AdapterServer, http_json, tls_context, run_client, verify_token, loads, client_headers, validate_descriptor, upload_blob, replace_references, validate_adapter_config, wire_request

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'agent-hooks-protocol/interop/fixtures'


def request():
    value = json.loads((ROOT / 'agent-hooks-protocol/fixtures/draft/http/intercept-request.valid.json').read_text())
    value['params']['event']['call'] = {'id': value['params']['event']['tool'].pop('callId', 'call-test')}
    value['params']['event']['path'] = 'native'
    value['params']['event']['tool']['origin'] = 'native'
    value['params']['event']['tool']['input'] = {'task': 1, 'nested': {'a': 1}, 'keep': True}
    value['params']['capabilities'] = {'effects': ['deny', 'allow', 'ask', 'modify', 'return', 'message'], 'modify': {'input': {'replace': True, 'merge': True}}}
    return value


def response(effects):
    return {'jsonrpc': '2.0', 'id': request()['id'], 'result': {'protocolVersion': 'draft', 'effects': effects}}


def jwt(auth, **overrides):
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=').decode()
    claims = {'iss': auth['issuer'], 'aud': auth['audience'], 'purpose': auth['purpose'], 'exp': auth['clock'] + 100}
    claims.update(overrides)
    payload = encode({'alg': 'HS256'}) + '.' + encode(claims)
    signature = base64.urlsafe_b64encode(hmac.new(auth['signingKey'].encode(), payload.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
    return payload + '.' + signature


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.validator = Validator()

    def apply(self, effects, req=None):
        return apply_response(req or request(), response(effects), self.validator)

    def test_shallow_merge_null_and_return_binding(self):
        actual = self.apply([{'type': 'return', 'value': {'cached': True}}, {'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'nested': {'b': 2}, 'keep': None}}, {'type': 'message', 'text': 'accepted'}, {'type': 'allow'}])
        self.assertEqual(actual, {'decision': 'allow', 'executed': False, 'input': {'task': 1, 'nested': {'b': 2}, 'keep': None}, 'messages': ['accepted'], 'result': {'cached': True}})

    def test_deny_and_ask_precedence(self):
        for effects, decision in [([{'type': 'ask'}, {'type': 'allow'}], 'ask'), ([{'type': 'allow'}, {'type': 'ask'}], 'ask'), ([{'type': 'deny', 'reason': 'policy'}, {'type': 'return', 'value': 42}, {'type': 'allow'}], 'deny')]:
            actual = self.apply(effects)
            self.assertEqual(actual['decision'], decision)
            self.assertFalse(actual['executed'])
            self.assertNotIn('result', actual)

    def test_invalidation_and_noop_preservation(self):
        req = request()
        req['params']['state'] = {'permission': 'allow', 'candidate': {'value': 'old', 'provenance': {'subscriptionId': 'cache'}}}
        self.assertEqual(self.apply([], req)['result'], 'old')
        actual = self.apply([{'type': 'modify', 'target': 'input', 'operation': 'replace', 'value': {'task': 2}}], req)
        self.assertFalse(actual['executed'])  # Changed work needs renewed native authorization.
        self.assertNotIn('result', actual)

    def test_failure_atomicity(self):
        req = request()
        original = deepcopy(req)
        for invalid in [{'type': 'unknown'}, {'type': 'message', 'text': 3}, {'type': 'modify', 'target': 'input', 'operation': 'replace', 'value': []}]:
            with self.assertRaises(ProtocolError):
                self.apply([{'type': 'message', 'text': 'must not leak'}, invalid], req)
            self.assertEqual(req, original)

    def test_capability_and_correlation(self):
        req = request()
        req['params']['capabilities']['effects'] = ['deny']
        with self.assertRaises(ProtocolError):
            self.apply([{'type': 'allow'}], req)
        bad = response([])
        bad['id'] = 'wrong'
        with self.assertRaises(ProtocolError):
            apply_response(request(), bad, self.validator)

    def test_strict_json(self):
        for text in ['{"a":1,"a":2}', '{"a":NaN}']:
            with self.assertRaises(ProtocolError):
                loads(text)

    def test_continuation_instructions_and_budget(self):
        req = request()
        req['params']['event'].pop('tool')
        req['params']['event']['type'] = 'turn.finish.before'
        req['params']['event']['turn'] = {'id': 'turn-test'}
        req['params']['event']['continuationCount'] = 0
        req['params']['event']['outcome'] = 'completed'
        req['params']['event']['items'] = []
        req['params']['capabilities'] = {'effects': ['flow'], 'flow': {'operations': ['continue', 'stop'], 'remainingContinuations': 2, 'continuationCount': 0, 'maxContinuations': 2}}
        effects = [{'type': 'flow', 'operation': 'continue', 'instruction': text} for text in ['Check tests', 'Check logs']]
        original = deepcopy(req)
        actual = self.apply(effects, req)
        self.assertEqual(actual['continuationInstructions'], ['Check tests', 'Check logs'])
        self.assertEqual(actual['continuationRemaining'], 1)
        self.assertEqual(req, original)
        stop = {'type': 'flow', 'operation': 'stop', 'reason': 'finished'}
        for combined in [effects + [stop], [stop] + effects]:
            actual = self.apply(combined, req)
            self.assertEqual(actual['continuationInstructions'], ['Check tests', 'Check logs'])
            self.assertEqual(actual['continuationRemaining'], 2)
        req['params']['capabilities']['flow']['remainingContinuations'] = 0
        with self.assertRaises(ProtocolError):
            self.apply(effects, req)

    def test_signed_claims(self):
        auth = {'mode': 'workload', 'signingKey': 'TEST-ONLY-key', 'issuer': 'issuer', 'audience': 'audience', 'purpose': 'workload', 'clock': 1893456000}
        self.assertTrue(verify_token(jwt(auth), auth))
        for overrides in [{'exp': auth['clock']}, {'aud': 'other'}, {'iss': 'other'}, {'purpose': 'oauth'}, {'nbf': auth['clock'] + 1}]:
            self.assertFalse(verify_token(jwt(auth, **overrides), auth))
        self.assertFalse(verify_token(jwt(auth) + 'tampered', auth))


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.scenarios = self.directory / 'scenarios.json'
        req = request()
        self.scenarios.write_text(json.dumps({'version': 1, 'scenarios': [
            {'id': req['id'], 'request': req, 'response': response([{'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'task': 2}}, {'type': 'message', 'text': 'real transport'}]), 'expected': {'decision': 'allow', 'executed': True, 'input': {'task': 2, 'nested': {'a': 1}, 'keep': True}, 'messages': ['real transport']}},
            # Distinct event IDs keep server scenario lookup deterministic.
            {'id': 'invalid', 'request': {**req, 'id': 'invalid', 'params': {**req['params'], 'event': {**req['params']['event'], 'id': 'invalid'}}}, 'response': {'jsonrpc': '2.0', 'id': 'invalid', 'result': {'protocolVersion': 'draft', 'effects': [{'type': 'unknown'}]}}, 'expectError': True}
        ]}))

    def tearDown(self):
        self.temp.cleanup()

    def exercise(self, mode, server_auth, client_auth):
        readiness = self.directory / 'ready.json'
        config = {'transport': mode, 'readinessFile': str(readiness), 'scenarioFile': str(self.scenarios), 'auth': server_auth}
        report = self.directory / 'report.json'
        client = {'transport': mode, 'scenarioFile': str(self.scenarios), 'reportFile': str(report), 'auth': client_auth}
        if mode == 'stdio':
            server_file = self.directory / 'server.json'
            server_file.write_text(json.dumps(config))
            client.update(serverCommand=[sys.executable, '-m', 'agent_hooks_protocol.interop', 'server'], serverConfig=str(server_file))
            self.assertEqual(run_client(client), 0, [r for r in json.loads(report.read_text())['results'] if r['status'] != 'passed'])
        else:
            server = AdapterServer(config)
            ready = threading.Event()
            # Observe atomic readiness without sleep-based ordering.
            import agent_hooks_protocol.interop as module
            original = module.atomic_json
            def write(path, value):
                original(path, value)
                if str(path) == str(readiness):
                    ready.set()
            from unittest.mock import patch
            with patch.object(module, 'atomic_json', write):
                thread = threading.Thread(target=server.serve)
                thread.start()
                self.assertTrue(ready.wait(5))
                try:
                    state = json.loads(readiness.read_text())
                    client['endpoint'] = state['endpoint']
                    if server_auth.get('mode') in ('bearer', 'oauth', 'workload'):
                        with self.assertRaises(HTTPError) as caught:
                            http_json(state['endpoint'], request())
                        self.assertEqual(caught.exception.code, 401)
                        self.assertEqual(http_json(state['controlEndpoint'] + '/receipts')['requests'], [])
                    if server_auth.get('mode') == 'bearer':
                        from urllib.parse import urlsplit
                        endpoint = urlsplit(state['endpoint'])
                        for method, path in [('GET', '/capabilities'), ('POST', '/intercept')]:
                            connection = HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
                            try:
                                body = json.dumps(request()).encode() if method == 'POST' else b''
                                connection.putrequest(method, path)
                                connection.putheader('Authorization', 'Bearer ' + server_auth['token'])
                                connection.putheader('authorization', 'Bearer wrong-token')
                                connection.putheader('Content-Length', str(len(body)))
                                connection.endheaders(body)
                                reply = connection.getresponse()
                                self.assertEqual(reply.status, 401)
                                reply.read()
                            finally:
                                connection.close()
                        self.assertEqual(http_json(state['controlEndpoint'] + '/receipts')['requests'], [])
                    if server_auth.get('mode') == 'mtls':
                        untrusted = {**client_auth, 'certFile': str(FIXTURES / 'untrusted-client.pem'), 'keyFile': str(FIXTURES / 'untrusted-client-key.pem')}
                        with self.assertRaises((URLError, OSError)):
                            http_json(state['endpoint'], request(), context=tls_context(untrusted))
                        self.assertEqual(http_json(state['controlEndpoint'] + '/receipts')['requests'], [])
                    if server_auth.get('mode') in ('oauth', 'workload'):
                        with self.assertRaises(HTTPError) as caught:
                            http_json(state['endpoint'], request(), {'Authorization': 'Bearer ' + jwt(server_auth, exp=server_auth['clock'])})
                        self.assertEqual(caught.exception.code, 401)
                        self.assertEqual(http_json(state['controlEndpoint'] + '/receipts')['requests'], [])
                    self.assertEqual(run_client(client), 0, [r for r in json.loads(report.read_text())['results'] if r['status'] != 'passed'])
                    receipts = http_json(state['controlEndpoint'] + '/receipts')['requests']
                    self.assertEqual(len(receipts), len(json.loads(self.scenarios.read_text())['scenarios']))
                    self.assertEqual(set(receipts[0]), {'id', 'method', 'message'})
                    self.assertEqual(receipts[0]['message'], wire_request(json.loads(self.scenarios.read_text())['scenarios'][0]['request']))
                finally:
                    server.stop()
                    thread.join(5)
                    self.assertFalse(thread.is_alive())
        self.assertTrue(all(r['status'] == 'passed' for r in json.loads(report.read_text())['results']))

    def test_stdio(self):
        self.exercise('stdio', {'mode': 'none'}, {'mode': 'none'})

    def test_canonical_discovery(self):
        server = AdapterServer({'scenarioFile': str(self.scenarios)})
        req = {'jsonrpc': '2.0', 'id': 'discover', 'method': 'hooks/capabilities', 'params': {'protocolVersion': 'draft'}}
        actual = server.discovery(req)
        Validator().validate('capabilities-response', actual)
        self.assertIn('manifest', actual['result'])
        self.assertNotIn('effects', actual['result'])
        req['params'] = {}
        with self.assertRaises(ProtocolError):
            server.discovery(req)
        req['method'] = 'capabilities'
        req['params'] = {'protocolVersion': 'draft'}
        with self.assertRaises(ProtocolError):
            server.discovery(req)

    def test_redirects_never_forward_credentials(self):
        received = []
        class Destination(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                received.append(self.headers.get('Authorization'))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')
            do_POST = do_GET
        destination = ThreadingHTTPServer(('127.0.0.1', 0), Destination)
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.send_response(int(self.path[1:]))
                self.send_header('Location', 'http://127.0.0.1:' + str(destination.server_port) + '/stolen')
                self.end_headers()
            do_POST = do_GET
        source = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        threads = [threading.Thread(target=server.serve_forever) for server in [destination, source]]
        for thread in threads:
            thread.start()
        try:
            for code in [301, 302, 303, 307, 308]:
                endpoint = 'http://127.0.0.1:' + str(source.server_port) + '/' + str(code)
                for body in [None, request()]:
                    with self.assertRaises(HTTPError) as caught:
                        http_json(endpoint, body, {'Authorization': 'Bearer TEST-ONLY-secret'})
                    self.assertEqual(caught.exception.code, code)
                with self.assertRaises(HTTPError) as caught:
                    client_headers({'mode': 'oauth', 'tokenEndpoint': endpoint, 'clientId': 'client', 'clientSecret': 'TEST-ONLY-secret', 'audience': 'audience'})
                self.assertEqual(caught.exception.code, code)
            self.assertEqual(received, [])
        finally:
            for server in [source, destination]:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(5)
                self.assertFalse(thread.is_alive())

    def test_explicit_barrier(self):
        config = {'transport': 'http', 'scenarioFile': str(self.scenarios), 'readinessFile': str(self.directory / 'ready.json')}
        server = AdapterServer(config)
        server.scenarios[request()['id']]['barrier'] = 'release-test'
        waiting = threading.Event()
        class Barrier(threading.Event):
            def wait(self, timeout=None):
                waiting.set()
                return super().wait(timeout)
        server.barriers['release-test'] = Barrier()
        outcome = []
        worker = threading.Thread(target=lambda: outcome.append(server.intercept(request())))
        worker.start()
        try:
            self.assertTrue(waiting.wait(3))
            self.assertEqual(outcome, [])
            self.assertEqual(len(server.receipts), 1)
        finally:
            server.barriers['release-test'].set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome[0]['id'], request()['id'])

    def test_central_stdio(self):
        self.scenarios = ROOT / 'agent-hooks-protocol/interop/scenarios.json'
        self.exercise('stdio', {'mode': 'none'}, {'mode': 'none'})

    def test_central_http_auth_modes(self):
        self.scenarios = ROOT / 'agent-hooks-protocol/interop/scenarios.json'
        self.test_bearer()
        self.test_workload()
        self.test_mtls()
        self.test_oauth()

    def test_bearer(self):
        auth = {'mode': 'bearer', 'token': 'TEST-ONLY-token'}
        self.exercise('http', auth, auth)

    def test_workload(self):
        auth = {'mode': 'workload', 'signingKey': 'TEST-ONLY-ahp-interop-workload-signing-key', 'issuer': 'urn:ahp:interop:local-issuer', 'audience': 'urn:ahp:interop:local-server', 'purpose': 'workload', 'clock': 1893456000}
        self.exercise('http', auth, {'mode': 'workload', 'assertion': jwt(auth)})

    def test_mtls(self):
        common = {'mode': 'mtls', 'caFile': str(FIXTURES / 'ca.pem')}
        self.exercise('http', {**common, 'certFile': str(FIXTURES / 'server.pem'), 'keyFile': str(FIXTURES / 'server-key.pem')}, {**common, 'certFile': str(FIXTURES / 'client.pem'), 'keyFile': str(FIXTURES / 'client-key.pem')})

    def test_oauth(self):
        auth = {'mode': 'oauth', 'signingKey': 'TEST-ONLY-ahp-interop-oauth-signing-key', 'issuer': 'urn:ahp:interop:local-issuer', 'audience': 'urn:ahp:interop:local-server', 'purpose': 'oauth', 'clock': 1893456000}
        received = []
        class Issuer(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers['Content-Length'])).decode())
                body = json.dumps({'access_token': jwt(auth), 'token_type': 'Bearer'}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
        issuer = ThreadingHTTPServer(('127.0.0.1', 0), Issuer)
        thread = threading.Thread(target=issuer.serve_forever)
        thread.start()
        try:
            self.exercise('http', auth, {'mode': 'oauth', 'tokenEndpoint': 'http://127.0.0.1:' + str(issuer.server_port) + '/token', 'clientId': 'ahp-interop-client', 'clientSecret': 'TEST-ONLY-ahp-interop-client-secret', 'audience': auth['audience']})
            self.assertIn('grant_type=client_credentials', received[0])
            self.assertIn('client_secret=TEST-ONLY-ahp-interop-client-secret', received[0])
        finally:
            issuer.shutdown()
            issuer.server_close()
            thread.join(5)


class UploadContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / 'scenarios.json'
        path.write_text(json.dumps({'scenarios': [{'id': request()['id'], 'response': response([])}]}))
        self.config = {'transport': 'http', 'scenarioFile': str(path),
                       'auth': {'mode': 'bearer', 'token': 'event-only', 'scope': 'allowed'},
                       'uploadSubscriptions': {'allowed': 'AHP_TEST_UPLOAD'}}
        self.environment = patch.dict(os.environ, {'AHP_TEST_UPLOAD': 'upload-only'})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @contextmanager
    def listener(self, adapter, upload=True):
        server = ThreadingHTTPServer(('127.0.0.1', 0), adapter.handler(False, upload_only=upload))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield 'http://localhost:' + str(server.server_port)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
            self.assertFalse(thread.is_alive())

    def config_for(self, endpoint):
        return {'endpoint': endpoint + '/content', 'maxBytes': 1024, 'timeoutMs': 1000,
                'future': {'ignored': True},
                'auth': {'type': 'bearer', 'tokenEnv': 'AHP_TEST_UPLOAD', 'future': True}}

    def selected_request(self, descriptor):
        req = request()
        event = req['params']['event']
        event.pop('tool')
        event.pop('call', None)
        event.update(type='turn.finish.before', turn={'id': 'turn'}, outcome='completed',
                     continuationCount=0, items=[{'id': 'item', 'kind': 'assistant', 'role': 'assistant',
                     'mediaType': 'application/octet-stream', 'selection': 'body', 'body': descriptor}])
        req['params']['capabilities'] = {'effects': ['message']}
        return req

    def test_raw_upload_receiver_reference_and_scoped_event(self):
        adapter = AdapterServer(self.config)
        data = b'\x00\xffbinary\x00'
        with self.listener(adapter) as endpoint:
            first = upload_blob(self.config_for(endpoint), data, adapter.validator)
            second = upload_blob(self.config_for(endpoint), b'', adapter.validator)
        self.assertNotEqual(first['ref'], second['ref'])
        self.assertEqual(adapter.blobs[('allowed', first['ref'])], data)
        req = self.selected_request(first)
        with self.listener(adapter, upload=False) as endpoint:
            with self.assertRaises(HTTPError) as caught:
                http_json(endpoint + '/intercept', req, {'Authorization': 'Bearer upload-only'})
            self.assertEqual(caught.exception.code, 401)
            self.assertEqual(adapter.receipts, [])
            http_json(endpoint + '/intercept', req, {'Authorization': 'Bearer event-only'})
        adapter.config['auth']['scope'] = 'other'
        with self.assertRaises(ProtocolError):
            adapter.intercept(req)
        self.assertEqual(len(adapter.receipts), 1)
        req['params']['subscriptionId'] = 'allowed'
        with self.assertRaises(ProtocolError):
            adapter.intercept(req)

    def test_upload_never_inherits_event_auth_and_rejects_wire_identity(self):
        adapter = AdapterServer(self.config)
        with self.listener(adapter) as endpoint:
            config = self.config_for(endpoint)
            config.pop('auth')
            with self.assertRaises(HTTPError) as caught:
                upload_blob(config, b'data', adapter.validator)
            self.assertEqual(caught.exception.code, 401)
            from urllib.parse import urlsplit
            url = urlsplit(endpoint)
            for extra in ({'AHP-Subscription': 'allowed'}, {'AHP-Content-Ref': 'chosen'},
                          {'Content-Encoding': 'gzip'}, {'AHP-Content-SHA256': '0' * 64}):
                connection = HTTPConnection(url.hostname, url.port, timeout=3)
                try:
                    headers = {'Authorization': 'Bearer upload-only', 'Content-Type': 'application/octet-stream',
                               'AHP-Content-SHA256': hashlib.sha256(b'data').hexdigest(), **extra}
                    connection.request('POST', '/content', b'data', headers)
                    result = connection.getresponse()
                    self.assertEqual(result.status, 400)
                    result.read()
                finally:
                    connection.close()
        self.assertEqual(adapter.blobs, {})

    def test_upload_descriptor_must_be_confirmed_and_match_bytes(self):
        descriptor = {'ref': 'opaque-receiver-ref', 'size': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}
        cases = [(201, 'application/json', descriptor)]
        cases += [(status, 'application/json', descriptor) for status in (200, 202, 204)]
        cases += [(201, 'text/plain', descriptor), (201, 'application/json', {}),
                  (201, 'application/json', {**descriptor, 'size': 4}),
                  (201, 'application/json', {**descriptor, 'sha256': '0' * 64}),
                  (201, 'application/json', {**descriptor, 'ref': ''}),
                  (201, 'application/json', {**descriptor, 'extra': True})]
        for index, (status, media, value) in enumerate(cases):
            with self.subTest(index=index):
                reply = io.BytesIO(json.dumps(value).encode())
                reply.status = status
                reply.headers = {'Content-Type': media}
                if index == 0:
                    self.assertEqual(validate_descriptor(reply, b'abc', Validator()), descriptor)
                else:
                    with self.assertRaises(ProtocolError):
                        validate_descriptor(reply, b'abc', Validator())
        original = self.selected_request(descriptor)
        returned = {**descriptor, 'ref': 'different-receiver-ref'}
        rewritten = replace_references(original, {descriptor['ref']: returned})
        self.assertEqual(rewritten['params']['event']['items'][0]['body'], returned)
        self.assertEqual(original['params']['event']['items'][0]['body'], descriptor)

    def test_unknown_configuration_accepted_recognized_fields_validated(self):
        validate_adapter_config({**self.config, 'future': True})
        for patch_value in ({'transport': 'unknown'}, {'auth': []}, {'auth': {'mode': 'bearer', 'token': 2}},
                            {'auth': {'mode': 'none', 'scope': []}}, {'uploadSubscriptions': []}):
            with self.subTest(config=patch_value), self.assertRaises(ProtocolError):
                validate_adapter_config({**self.config, **patch_value})
        valid = self.config_for('https://example.invalid')
        Validator().validate('content-upload', valid)
        for patch_value in ({'timeoutMs': True}, {'maxBytes': -1}, {'auth': {'type': 'unknown', 'tokenEnv': 'TOKEN'}}):
            with self.subTest(config=patch_value), self.assertRaises(ProtocolError):
                upload_blob({**valid, **patch_value}, b'', Validator())

    def test_failed_upload_suppresses_dependent_event(self):
        scenario_file = Path(self.config['scenarioFile'])
        descriptor = {'ref': 'fixture-placeholder', 'size': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}
        req = self.selected_request(descriptor)
        scenario_file.write_text(json.dumps({'scenarios': [{'id': req['id'], 'request': req,
            'uploads': [{'ref': descriptor['ref'], 'bodyBase64': 'YWJj',
                         'upload': self.config_for('https://example.invalid')}], 'expected': {}}]}))
        report = Path(self.temp.name) / 'report.json'
        with patch('agent_hooks_protocol.interop.http_json', return_value={'effects': ['message']}) as exchange, \
             patch('agent_hooks_protocol.interop.upload_blob', side_effect=ProtocolError('bad descriptor')):
            code = run_client({**self.config, 'endpoint': 'https://example.invalid/intercept', 'reportFile': str(report)})
        self.assertEqual(code, 1)
        self.assertEqual(exchange.call_count, 1)  # Discovery only, never the referring event.
        self.assertEqual(json.loads(report.read_text())['results'][0]['status'], 'failed')

    def test_specialized_wire_receivers_allocate_refs_with_separate_upload_auth(self):
        directory = Path(self.temp.name)
        config = directory / 'hooks.json'
        config.write_text(json.dumps({'hook': {'kind': 'append', 'target': 'instructions', 'suffix': ':one'},
                                      'second': {'kind': 'append', 'target': 'instructions', 'suffix': ':two'}}))
        schema = str(ROOT / 'agent-hooks-protocol/schema/draft')
        sdk = Path(__file__).resolve().parents[1]
        for name, args, event_env, upload_env in [
            ('compaction_wire.py', ['server', schema, str(directory), str(config)], 'AHP_COMPACTION_TOKENS', 'AHP_COMPACTION_UPLOAD_TOKENS'),
            ('elicitation.py', ['server', schema, 'local-principal'], 'AHP_ELICITATION_TOKEN', 'AHP_ELICITATION_UPLOAD_TOKEN'),
        ]:
            with self.subTest(adapter=name):
                env = {**os.environ, event_env: 'event-only', upload_env: 'upload-only'}
                if name == 'compaction_wire.py':
                    env.update({event_env: json.dumps({'event-only': 'hook', 'second-event': 'second'}),
                                upload_env: json.dumps({'upload-only': 'hook', 'second-upload': 'second'})})
                child = subprocess.Popen([sys.executable, str(sdk / 'interop' / name), *args], env=env,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(5), 'Receiver startup timeout')
                        ready = json.loads(child.stdout.readline())
                    endpoint = ready['endpoint'].replace('127.0.0.1', 'localhost')
                    upload = {**self.config_for(endpoint), 'endpoint': endpoint + '/upload'}
                    first = upload_blob(upload, b'\xff\x00', Validator())
                    second = upload_blob(upload, b'\xff\x00', Validator())
                    self.assertNotEqual(first['ref'], second['ref'])
                    if name == 'compaction_wire.py':
                        import importlib.util
                        from agent_hooks_protocol.compaction import run_compaction
                        spec = importlib.util.spec_from_file_location('compaction_wire_fixture', sdk / 'interop' / name)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        plan = {'transport': 'http', 'endpoint': endpoint, 'credentials': {
                            'hook': {'token': 'event-only', 'uploadToken': 'upload-only'},
                            'second': {'token': 'second-event', 'uploadToken': 'second-upload'}}}
                        trace = []
                        hooks = [(scope, 'fail-closed', lambda snapshot, scope=scope:
                                  module.exchange(plan, scope, 'chain', snapshot, Validator(), trace))
                                 for scope in ('hook', 'second')]
                        outcome = run_compaction('base', hooks)
                        self.assertEqual(outcome['instructions'], 'base:one:two')
                        self.assertEqual(outcome['failures'], [])
                        denied = http_json(endpoint + '/hooks/intercept', trace[0]['request'],
                                           {'Authorization': 'Bearer second-event'})
                        self.assertEqual(denied['error']['code'], -32602)
                        self.assertEqual(len((directory / 'receipts.jsonl').read_text().splitlines()), 2)
                    with patch.dict(os.environ, {'AHP_TEST_UPLOAD': 'event-only'}):
                        with self.assertRaises(HTTPError) as caught:
                            upload_blob(upload, b'abc', Validator())
                    self.assertEqual(caught.exception.code, 401)
                finally:
                    child.terminate()
                    child.communicate(timeout=5)

    def test_elicitation_negative_upload_probe_and_dependent_suppression(self):
        adapter = AdapterServer(self.config)
        script = Path(__file__).resolve().parents[1] / 'interop/elicitation.py'
        with self.listener(adapter) as endpoint:
            plan = {'endpoint': endpoint, 'token': 'event-only', 'steps': [{'path': '/upload', 'bytes': ''}]}
            result = subprocess.run([sys.executable, str(script), 'client'], input=json.dumps(plan),
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)[0]['status'], 404)
            plan['steps'].append({'path': '/hooks/intercept', 'bytes': base64.b64encode(json.dumps(request()).encode()).decode()})
            result = subprocess.run([sys.executable, str(script), 'client'], input=json.dumps(plan),
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Dependent event suppressed', result.stderr)
        self.assertEqual(adapter.receipts, [])

    def test_no_wire_subscription_identity_including_execution(self):
        req = request()
        req['params']['subscriptionId'] = 'local'
        req['params']['event']['execution'] = {'status': 'skipped', 'reason': 'supplied_result', 'subscriptionId': 'local'}
        req['params']['state'] = {'candidate': {'value': 'result', 'provenance': {'subscriptionId': 'local'}}}
        encoded = wire_request(req)
        self.assertNotIn('subscriptionId', json.dumps(encoded))
        self.assertIn('subscriptionId', req['params'])  # Caller state stays local and unchanged.


if __name__ == '__main__':
    unittest.main()
