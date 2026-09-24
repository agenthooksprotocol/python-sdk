"""Local cross-SDK adapter. Not a production HTTP deployment server."""
from __future__ import annotations
import argparse
from copy import deepcopy
import base64
import hashlib
import hmac
import json
import os
import re
import uuid
from pathlib import Path
import selectors
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler
from urllib.parse import urlencode, urlsplit
from .runtime import Validator, ProtocolError, apply_response, json_equal
from .lifecycle import content_items
from .lineage import TaskLineage

LIMIT = 4 * 1024 * 1024
TIMEOUT = 10


def loads(data):
    def reject(_):
        raise ProtocolError('Non-JSON number')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProtocolError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, parse_constant=reject, object_pairs_hook=pairs)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + str(os.getpid()) + '.tmp')
    temporary.write_text(json.dumps(value, allow_nan=False) + '\n')
    os.replace(temporary, path)


def tls_context(auth, server=False):
    if auth.get('mode') != 'mtls':
        return None
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH, cafile=auth['caFile'])
    # Shared synthetic fixtures omit AKI; keep normal chain/hostname/expiry
    # verification while accepting that legacy X.509 profile (Python 3.13).
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    context.load_cert_chain(auth['certFile'], auth['keyFile'])
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def verify_token(token, auth):
    try:
        head, body, signature = token.split('.')
        decode = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
        header, claims = loads(decode(head)), loads(decode(body))
        expected = hmac.new(auth['signingKey'].encode(), (head + '.' + body).encode(), hashlib.sha256).digest()
        if header.get('alg') != 'HS256' or not hmac.compare_digest(expected, decode(signature)):
            return False
        now = auth.get('clock', time.time())
        audience = claims.get('aud')
        return (claims.get('iss') == auth['issuer'] and (audience == auth['audience'] or isinstance(audience, list) and auth['audience'] in audience)
                and claims.get('purpose') == auth.get('purpose', auth['mode'])
                and type(claims.get('exp')) in (int, float) and claims['exp'] > now
                and claims.get('nbf', 0) <= now)
    except (ValueError, KeyError, TypeError, UnicodeError):
        return False


def authenticated(headers, connection, auth):
    values = headers.get_all('Authorization', [])
    if len(values) > 1:
        return False
    value = values[0] if values else ''
    token = value[7:] if value.startswith('Bearer ') else ''
    mode = auth.get('mode', 'none')
    if mode == 'none':
        return True
    if mode == 'mtls':
        return bool(connection.getpeercert())
    if mode == 'bearer':
        return bool(token) and hmac.compare_digest(token, auth['token'])
    return mode in ('oauth', 'workload') and verify_token(token, auth)


def synthetic_native_policy(event):
    """Test host policy on the effective operation, never a wire approval."""
    return True


def synthetic_input_validator(event):
    if event.get('tool', {}).get('name') == 'task':
        task = event['tool']['input'].get('task')
        if type(task) not in (int, float) or task <= 0 or task != int(task):
            raise ProtocolError('Invalid task application input')


class NoRedirect(HTTPRedirectHandler):
    """Never forward endpoint credentials or OAuth client secrets to a redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_local(request, context=None):
    return build_opener(NoRedirect(), HTTPSHandler(context=context)).open(request, timeout=TIMEOUT)


def client_headers(auth):
    mode = auth.get('mode', 'none')
    if mode in ('none', 'mtls'):
        return {}
    if mode == 'bearer':
        token = auth['token']
    elif mode == 'workload':
        token = auth['assertion']
    elif mode == 'oauth':
        data = urlencode({'grant_type': 'client_credentials', 'client_id': auth['clientId'], 'client_secret': auth['clientSecret'], 'audience': auth['audience']}).encode()
        req = Request(auth['tokenEndpoint'], data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        with open_local(req) as response:
            token = loads(response.read(LIMIT))['access_token']
    else:
        raise ProtocolError('Unsupported authentication mode')
    return {'Authorization': 'Bearer ' + token}


def http_json(url, data=None, headers=None, context=None):
    request = Request(url, data=None if data is None else json.dumps(data, allow_nan=False).encode(), headers={'Content-Type': 'application/json', **(headers or {})})
    with open_local(request, context=context) as response:
        body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ProtocolError('Response too large')
        return loads(body)


def wire_request(request):
    """Keep fixture-local subscription identities out of canonical envelopes."""
    result = deepcopy(request)
    params = result.get('params', {})
    params.pop('subscriptionId', None)
    params.get('event', {}).get('execution', {}).pop('subscriptionId', None)
    candidate = params.get('state', {}).get('candidate')
    if isinstance(candidate, dict):
        candidate.get('provenance', {}).pop('subscriptionId', None)
    return result


def validate_upload_framing(headers, data):
    """Validate octets before allocating an immutable receiver reference."""
    for name in ('Content-Type', 'Content-Length', 'AHP-Content-SHA256', 'Authorization'):
        if hasattr(headers, 'get_all') and len(headers.get_all(name, [])) > 1:
            raise ProtocolError('Duplicate upload framing')
    if (headers.get('Content-Type') != 'application/octet-stream' or
            headers.get('Content-Encoding') is not None or headers.get('Transfer-Encoding') is not None or
            headers.get('AHP-Subscription') is not None or headers.get('AHP-Content-Ref') is not None or
            not re.fullmatch(r'0|[1-9][0-9]*', headers.get('Content-Length', '')) or
            int(headers['Content-Length']) != len(data) or
            headers.get('AHP-Content-SHA256') != hashlib.sha256(data).hexdigest()):
        raise ProtocolError('Invalid upload framing')


def validate_descriptor(response, data, validator):
    if response.status != 201 or response.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
        raise ProtocolError('Upload not confirmed')
    raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ProtocolError('Upload response too large')
    descriptor = loads(raw)
    validator.validate('content-reference', descriptor)
    if descriptor['size'] != len(data) or descriptor['sha256'] != hashlib.sha256(data).hexdigest():
        raise ProtocolError('Upload descriptor mismatch')
    return descriptor


def upload_blob(config, data, validator):
    # Unknown configuration members are extensions; recognized members stay strict.
    validator.validate('content-upload', config)
    url = urlsplit(config['endpoint'])
    if (url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('localhost', '127.0.0.1', '::1'))
            or url.username or url.password or url.fragment):
        raise ProtocolError('Invalid upload endpoint')
    if len(data) > config['maxBytes']:
        raise ProtocolError('Upload exceeds configured limit')
    headers = {'Content-Type': 'application/octet-stream', 'Content-Length': str(len(data)),
               'AHP-Content-SHA256': hashlib.sha256(data).hexdigest()}
    if 'auth' in config:
        token = os.environ.get(config['auth']['tokenEnv'])
        if not token or '\r' in token or '\n' in token:
            raise ProtocolError('Upload credential unavailable')
        headers['Authorization'] = 'Bearer ' + token
    with build_opener(NoRedirect()).open(Request(config['endpoint'], data=data, headers=headers),
                                         timeout=config['timeoutMs'] / 1000) as response:
        return validate_descriptor(response, data, validator)


def replace_references(value, references):
    """Rewrite fixture-local placeholders only after every upload is confirmed."""
    if isinstance(value, dict):
        if set(value) == {'ref', 'size', 'sha256'} and value['ref'] in references:
            return deepcopy(references[value['ref']])
        return {key: replace_references(child, references) for key, child in value.items()}
    if isinstance(value, list):
        return [replace_references(child, references) for child in value]
    return value


def validate_adapter_config(config):
    if not isinstance(config, dict):
        raise ProtocolError('Invalid adapter config')
    if 'transport' in config and config['transport'] not in ('http', 'stdio'):
        raise ProtocolError('Invalid transport')
    auth = config.get('auth', {})
    if not isinstance(auth, dict) or auth.get('mode', 'none') not in ('none', 'bearer', 'oauth', 'workload', 'mtls'):
        raise ProtocolError('Invalid auth configuration')
    for key in ('token', 'scope', 'assertion', 'signingKey', 'issuer', 'audience', 'purpose',
                'tokenEndpoint', 'clientId', 'clientSecret', 'caFile', 'certFile', 'keyFile'):
        if key in auth and (not isinstance(auth[key], str) or not auth[key]):
            raise ProtocolError('Invalid auth field')
    if auth.get('mode') == 'bearer' and 'token' not in auth:
        raise ProtocolError('Missing bearer token')
    if 'clock' in auth and type(auth['clock']) not in (int, float):
        raise ProtocolError('Invalid auth clock')
    scopes = config.get('uploadSubscriptions', {})
    if not isinstance(scopes, dict) or any(not isinstance(scope, str) or not scope or
            token is not None and (not isinstance(token, str) or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', token))
            for scope, token in scopes.items()):
        raise ProtocolError('Invalid upload scopes')
    if 'stdioScope' in config and (not isinstance(config['stdioScope'], str) or not config['stdioScope']):
        raise ProtocolError('Invalid process scope')


class AdapterServer:
    def __init__(self, config):
        validate_adapter_config(config)
        self.config, self.validator = config, Validator()
        self.upload_subscriptions = config.get('uploadSubscriptions', {})
        self.blobs = {}
        self.lineage = TaskLineage(self.validator)
        self.scenarios = {s['id']: s for s in loads(Path(config['scenarioFile']).read_text())['scenarios']}
        self.receipts, self.barriers = [], {}
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.http_servers = []

    def authorize_upload(self, authorization):
        # This map is trusted receiver configuration, never a wire identity.
        scopes = []
        for scope, token_env in self.upload_subscriptions.items():
            token = os.environ.get(token_env) if token_env is not None else None
            if (token_env is None and authorization is None or
                    token and authorization == 'Bearer ' + token):
                scopes.append(scope)
        # Ambiguous credentials cannot select a scope via correlation metadata.
        return (201, scopes[0]) if len(scopes) == 1 else (403 if scopes else 401, None)

    def verify_content(self, request):
        self.validator.validate('intercept-request', request)
        scope = self.config.get('auth', {}).get('scope')
        if self.config.get('transport', 'stdio') == 'stdio':
            scope = self.config.get('stdioScope')
        with self.lock:
            for item in content_items(request['params']['event']):
                body = item['body']
                data = self.blobs.get((scope, body['ref']))
                if data is None or len(data) != body['size'] or hashlib.sha256(data).hexdigest() != body['sha256']:
                    raise ProtocolError('Unauthorized or unavailable content')
                for key in ('size', 'sha256'):
                    if key in item and item[key] != body[key]:
                        raise ProtocolError('Content metadata mismatch')

    def capabilities(self):
        result = {
            'effects': ['deny', 'allow', 'ask', 'modify', 'return', 'message', 'flow', 'inject'],
            'modify': {'input': {'replace': True, 'merge': True}},
            'flow': {'operations': ['stop']},
            'inject': {'context': {'append': True, 'deliverAt': ['now', 'next_turn']}},
        }
        self.validator.validate('capabilities', result)
        return result

    def discovery(self, request):
        self.validator.validate('capabilities-request', request)
        response = {'jsonrpc': '2.0', 'id': request['id'], 'result': {
            'protocolVersion': 'draft', 'manifest': {
                'transports': [self.config.get('transport', 'stdio')],
                'authentication': [self.config['auth']['mode']] if self.config.get('auth', {}).get('mode', 'none') != 'none' else [],
                'toolPaths': ['native'], 'contentCategories': [],
                'limits': {'maxUploadBytes': LIMIT, 'maxContinuations': 2},
                'managedPolicy': {'scopes': [], 'disableable': True},
                'correlationIdentityFields': ['event.id', 'event.source', 'call.id'],
                'events': [
                    {'event': 'tool.before', 'modes': ['intercept'], 'capabilities': self.capabilities()},
                    {'event': 'turn.finish.before', 'modes': ['intercept'], 'capabilities': {
                        'effects': ['flow', 'message'],
                        'flow': {'operations': ['stop', 'continue'], 'remainingContinuations': 2, 'continuationCount': 0}}},
                ],
                'gaps': [{'path': 'events.other', 'reason': 'Synthetic application supports tool.before and turn.finish.before only'}],
            },
        }}
        self.validator.validate('capabilities-response', response)
        return response

    def intercept(self, request):
        self.verify_content(request)
        self.lineage.accept(request['params']['event'])
        event_id = request['params']['event']['id']
        if request['id'] != event_id:
            raise ProtocolError('Correlation mismatch')
        scenario = self.scenarios[event_id]
        with self.lock:
            # Exact received canonical message evidence; never include credential headers.
            self.receipts.append({'id': event_id, 'method': request['method'], 'message': deepcopy(request)})
            barrier = self.barriers.setdefault(scenario.get('barrier'), threading.Event())
        if scenario.get('barrier') and not barrier.wait(TIMEOUT):
            raise ProtocolError('Barrier watchdog expired')
        # Negative response fixtures intentionally reach the client's validator.
        response = scenario['response']
        if not scenario.get('expectError'):
            self.validator.validate('intercept-response', response)
        return response

    def stop(self):
        self.stopping.set()
        for barrier in self.barriers.values():
            barrier.set()
        for server in self.http_servers:
            server.shutdown()

    def handler(self, control, upload_only=False):
        adapter = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_json(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def authenticated(self):
                return authenticated(self.headers, self.connection, adapter.config.get('auth', {}))

            def do_GET(self):
                if upload_only:
                    return self.send_json(404, {'error': 'Not found'})
                if control and self.path == '/health':
                    return self.send_json(200, {'ready': True})
                if control and self.path == '/receipts':
                    with adapter.lock:
                        return self.send_json(200, {'requests': list(adapter.receipts)})
                if not control and self.path == '/capabilities':
                    if not self.authenticated():
                        return self.send_json(401, {'error': 'Unauthorized'})
                    return self.send_json(200, adapter.capabilities())
                self.send_json(404, {'error': 'Not found'})

            def do_POST(self):
                if upload_only:
                    self.connection.settimeout(TIMEOUT)
                    try:
                        size = int(self.headers.get('Content-Length', '-1'))
                        status = 413 if size > LIMIT else 400 if size < 0 else None
                        if status is None:
                            data = self.rfile.read(size)
                            if self.path != '/content':
                                status = 404
                            else:
                                validate_upload_framing(self.headers, data)
                                status, scope = adapter.authorize_upload(self.headers.get('Authorization'))
                                if scope is not None:
                                    descriptor = {'ref': 'urn:uuid:' + str(uuid.uuid4()), 'size': len(data),
                                                  'sha256': hashlib.sha256(data).hexdigest()}
                                    with adapter.lock:
                                        adapter.blobs[(scope, descriptor['ref'])] = data
                                    return self.send_json(201, descriptor)
                    except (ValueError, OSError, ProtocolError):
                        status = 400
                    return self.send_json(status, {'error': 'Upload rejected'})
                if not control and not self.authenticated():
                    return self.send_json(401, {'error': 'Unauthorized'})
                try:
                    self.connection.settimeout(TIMEOUT)
                    size = int(self.headers.get('Content-Length', '0'))
                    if size < 0 or size > LIMIT:
                        raise ProtocolError('Invalid request size')
                    data = loads(self.rfile.read(size))
                    if control and self.path == '/release':
                        with adapter.lock:
                            adapter.barriers.setdefault(data['barrier'], threading.Event()).set()
                        return self.send_json(200, {'released': True})
                    if control and self.path == '/shutdown':
                        self.send_json(200, {'stopping': True})
                        threading.Thread(target=adapter.stop, daemon=True).start()
                        return
                    if not control and self.path == '/intercept':
                        return self.send_json(200, adapter.intercept(data))
                    return self.send_json(404, {'error': 'Not found'})
                except Exception:
                    self.send_json(400, {'error': 'Invalid request'})
        return Handler

    def serve(self):
        control = ThreadingHTTPServer(('127.0.0.1', 0), self.handler(True))
        self.http_servers.append(control)
        upload_server = ThreadingHTTPServer(('127.0.0.1', 0), self.handler(False, upload_only=True))
        self.http_servers.append(upload_server)
        endpoint = None
        if self.config['transport'] == 'http':
            server = ThreadingHTTPServer(('127.0.0.1', 0), self.handler(False))
            context = tls_context(self.config.get('auth', {}), True)
            if context:
                server.socket = context.wrap_socket(server.socket, server_side=True)
            self.http_servers.append(server)
            endpoint = ('https' if context else 'http') + '://127.0.0.1:' + str(server.server_port) + '/intercept'
        for server in self.http_servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        atomic_json(self.config['readinessFile'], {'endpoint': endpoint, 'uploadEndpoint': 'http://127.0.0.1:' + str(upload_server.server_port) + '/content', 'controlEndpoint': 'http://127.0.0.1:' + str(control.server_port), 'pid': os.getpid()})
        if self.config['transport'] == 'stdio':
            def stdio():
                while not self.stopping.is_set():
                    line = sys.stdin.buffer.readline(LIMIT + 1)
                    if not line:
                        self.stopping.set()
                        return
                    request = {}
                    try:
                        if len(line) > LIMIT:
                            raise ProtocolError('Request too large')
                        request = loads(line)
                        if request.get('method') == 'hooks/capabilities':
                            response = self.discovery(request)
                        else:
                            response = self.intercept(request)
                    except Exception:
                        response = {'jsonrpc': '2.0', 'id': request.get('id'), 'error': {'code': -32600, 'message': 'Invalid request'}}
                    print(json.dumps(response), flush=True)
            threading.Thread(target=stdio, daemon=True).start()
        self.stopping.wait()
        for server in self.http_servers:
            server.server_close()


def run_client(config):
    validate_adapter_config(config)
    scenarios = loads(Path(config['scenarioFile']).read_text())['scenarios']
    auth = config.get('auth', {})
    if config['transport'] == 'stdio' and auth.get('mode', 'none') != 'none':
        atomic_json(config['reportFile'], {'language': 'python', 'results': [{'id': s['id'], 'status': 'inapplicable', 'actual': None, 'error': 'Stdio uses process trust'} for s in scenarios]})
        return 0
    process = None
    results = []
    try:
        validator = Validator()
        if config['transport'] == 'stdio':
            server_config = config['serverConfig']
            process = subprocess.Popen([*config['serverCommand'], '--config', server_config], cwd=config.get('serverCwd'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            def exchange(request):
                process.stdin.write(json.dumps(request).encode() + b'\n')
                process.stdin.flush()
                if not selector.select(TIMEOUT):
                    raise ProtocolError('Stdio watchdog expired')
                # Unbuffered fd reading ensures a partial line cannot defeat timeout.
                data = bytearray()
                deadline = time.monotonic() + TIMEOUT
                while b'\n' not in data:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ProtocolError('Stdio watchdog expired')
                    chunk = os.read(process.stdout.fileno(), 1)
                    if not chunk or len(data) >= LIMIT:
                        raise ProtocolError('Invalid stdio response')
                    data.extend(chunk)
                return loads(data)
            discovery_request = {'jsonrpc': '2.0', 'id': 'capabilities', 'method': 'hooks/capabilities', 'params': {'protocolVersion': 'draft'}}
            validator.validate('capabilities-request', discovery_request)
            discovery = exchange(discovery_request)
            validator.validate('capabilities-response', discovery)
            if discovery['id'] != discovery_request['id']:
                raise ProtocolError('Invalid discovery correlation')
            entries = discovery['result']['manifest']['events']
            capabilities = next((e['capabilities'] for e in entries if e['event'] == 'tool.before' and 'intercept' in e['modes']), None)
            if capabilities is None:
                raise ProtocolError('tool.before interception not advertised')
        else:
            headers, context = client_headers(auth), tls_context(auth)
            endpoint = config['endpoint'].rstrip('/')
            base = endpoint[:-10] if endpoint.endswith('/intercept') else endpoint
            capabilities = http_json(base + '/capabilities', headers=headers, context=context)
            def exchange(request):
                return http_json(base + '/intercept', request, headers, context)
        validator.validate('capabilities', capabilities)
        for scenario in scenarios:
            result = {'id': scenario['id'], 'status': 'failed', 'actual': None}
            try:
                validator.validate('intercept-request', wire_request(scenario['request']))
                references = {}
                for blob in scenario.get('uploads', []):
                    data = base64.b64decode(blob['bodyBase64'], validate=True)
                    references[blob['ref']] = upload_blob(blob['upload'], data, validator)
                request = wire_request(replace_references(scenario['request'], references))
                validator.validate('intercept-request', request)
                response = exchange(request)
                try:
                    actual = apply_response(request, response, validator, native_authorize=synthetic_native_policy, validate_operation=synthetic_input_validator)
                except ProtocolError:
                    if not scenario.get('expectError'):
                        raise
                    result.update(status='passed', actual={'rejected': True})
                else:
                    result['actual'] = actual
                    if scenario.get('expectError'):
                        raise ProtocolError('Expected rejection')
                    if not all(key in actual and json_equal(actual[key], value) for key, value in scenario['expected'].items()):
                        raise ProtocolError('Expected outcome mismatch')
                    result['status'] = 'passed'
            except Exception as error:
                # Never include remote bodies, exception strings or credentials.
                result['error'] = type(error).__name__
            results.append(result)
    except Exception as error:
        results = [{'id': s['id'], 'status': 'failed', 'actual': None, 'error': 'Setup: ' + type(error).__name__} for s in scenarios]
    finally:
        if process is not None:
            if 'selector' in locals():
                selector.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()
        atomic_json(config['reportFile'], {'language': 'python', 'results': results})
    return int(any(r['status'] == 'failed' for r in results))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['client', 'server'])
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = loads(Path(args.config).read_text())
    if args.role == 'server':
        AdapterServer(config).serve()
        return 0
    return run_client(config)


if __name__ == '__main__':
    sys.exit(main())
