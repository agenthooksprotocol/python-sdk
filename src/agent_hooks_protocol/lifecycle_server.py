"""LIFECYCLE.md test server; stdout is exclusively stdio protocol traffic."""
import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .interop import atomic_json, loads, authenticated, tls_context, validate_adapter_config
from .lifecycle import ContentStore
from .content import receive
from .lineage import TaskLineage
from .runtime import Validator, ProtocolError

TIMEOUT = 30
MALICIOUS = {'jsonrpc': '2.0', 'id': 'unsolicited-observer', 'result': {
    'protocolVersion': 'draft', 'effects': [{'type': 'deny', 'reason': 'observer must not decide'}]}}


class CatalogueRejection(ProtocolError):
    def __init__(self, status):
        self.status = status
        super().__init__('Rejected catalogue notification')


class Server:
    def __init__(self, config):
        validate_adapter_config(config)
        if config.get('suite', 'lifecycle') not in ('lifecycle', 'catalogue'):
            raise ProtocolError('Unknown suite')
        self.config = config
        self.validator = Validator()
        self.lineage = TaskLineage(self.validator)
        if config['transport'] == 'stdio' and config.get('auth', {}).get('mode', 'none') != 'none':
            raise ProtocolError('Stdio uses process trust')
        self.upload_auth = config.get('uploadAuth')
        if self.upload_auth is not None and (not isinstance(self.upload_auth, dict) or
                not isinstance(self.upload_auth.get('token'), str) or not self.upload_auth['token'] or
                'scope' in self.upload_auth and (not isinstance(self.upload_auth['scope'], str) or not self.upload_auth['scope'])):
            raise ProtocolError('Invalid upload authorization')
        self.local_scope = object()  # One receiver-local context; never a wire claim.
        self.upload_scope = self.upload_auth.get('scope', self.local_scope) if self.upload_auth else None
        self.upload_subscriptions = ({self.upload_scope: None} if self.upload_auth else config.get('uploadSubscriptions', {}))
        self.event_scope = config.get('stdioScope', self.local_scope) if config['transport'] == 'stdio' else config.get('auth', {}).get('scope', self.local_scope)
        self.content = ContentStore(self.validator, lambda subscription: subscription in self.upload_subscriptions)
        self.condition = threading.Condition()
        self.output_lock = threading.Lock()
        self.entries = []
        self.released = set()
        self.stopping = threading.Event()
        self.responses = {}
        self.sequences = {}
        self.attempts = {}
        fixtures = loads(Path(config['scenarioFile']).read_text())
        for scenario in fixtures['scenarios']:
            if scenario.get('chain', {}).get('holdObservers'):
                self.sequences[scenario['requests']['a']['id'] + ':observers'] = []
            for key, request in scenario.get('requests', {}).items():
                self.responses[request['id']] = scenario['responses'][key]
                self.sequences[request['id']] = scenario.get('responseSequences', {}).get(key, [])
        self.listeners = []

    def authorize_upload(self, authorization):
        if self.upload_auth:
            return ((201, self.upload_scope) if authorization == 'Bearer ' + self.upload_auth['token']
                    else (401, None))
        scopes = []
        for scope, token_env in self.upload_subscriptions.items():
            token = os.environ.get(token_env) if token_env is not None else None
            if token_env is None and authorization is None or token and authorization == 'Bearer ' + token:
                scopes.append(scope)
        return (201, scopes[0]) if len(scopes) == 1 else (403 if scopes else 401, None)

    def record(self, entry):
        with self.condition:
            self.entries.append(entry)
            self.condition.notify_all()

    def wait(self, predicate):
        with self.condition:
            if not self.condition.wait_for(lambda: self.stopping.is_set() or predicate(), TIMEOUT):
                raise TimeoutError('Lifecycle barrier timed out')
            if self.stopping.is_set():
                raise ProtocolError('Server shutting down')

    def catalogue_protocol(self, request):
        from .catalogue import discovery
        if isinstance(request, dict) and request.get('method') == 'hooks/capabilities':
            response = discovery(request, self.validator)
            self.record({'kind': 'discovery', 'request': request, 'response': response})
            return response
        params = request.get('params') if isinstance(request, dict) else None
        event = params.get('event') if isinstance(params, dict) else None
        ident = event.get('id') if isinstance(event, dict) else None
        try:
            self.validator.validate('observe-notification', request)
            self.content.verify(request, self.event_scope)
        except ProtocolError:
            self.record({'kind': 'rejected', 'eventId': ident, 'message': request, 'errorKind': 'schema'})
            raise CatalogueRejection(400)
        try:
            self.lineage.accept(request['params']['event'])
        except ProtocolError:
            self.record({'kind': 'rejected', 'eventId': ident, 'message': request, 'errorKind': 'lineage'})
            raise CatalogueRejection(409)
        params = request['params']
        self.record({'kind': 'observed', 'eventId': ident,
                     'event': params['event'], 'message': request})
        return None

    def protocol(self, request):
        if self.config.get('suite') == 'catalogue':
            return self.catalogue_protocol(request)
        if request.get('method') == 'hooks/observe':
            self.content.verify(request, self.event_scope)
            params = request['params']
            self.lineage.accept(params['event'])
            gate = params['event']['id'] + ':observers'
            if gate in self.sequences:
                self.record({'kind': 'observer-blocked', 'id': params['event']['id']})
            self.record({'kind': 'observed', 'eventId': params['event']['id'],
                         'event': params['event'],
                         'message': request})
            if gate in self.sequences:
                self.wait(lambda: gate in self.released)
            self.validator.validate('intercept-response', MALICIOUS)
            return MALICIOUS
        self.content.verify(request, self.event_scope)
        self.lineage.accept(request['params']['event'])
        ident = request['id']
        if ident not in self.responses:
            raise ProtocolError('Unknown request')
        with self.condition:
            occurrence = self.attempts.get(ident, 0)
            self.attempts[ident] = occurrence + 1
            sequence = self.sequences[ident]
            response = sequence[occurrence] if occurrence < len(sequence) else self.responses[ident]
            self.record({'kind': 'received', 'id': ident, 'message': request})
        self.wait(lambda: ident in self.released)
        self.validator.validate('intercept-response', response)
        self.record({'kind': 'replied', 'id': ident})
        return response

    def control(self, path, value):
        if path == '/health':
            return 200, {'ready': True}
        if path == '/receipts':
            with self.condition:
                return 200, {'entries': list(self.entries)}
        if path in ('/wait', '/wait-observed'):
            kind, field = ('received', 'id') if path == '/wait' else ('observed', 'eventId')
            self.wait(lambda: sum((e.get('kind') == kind or kind == 'observed' and e.get('kind') == 'rejected') and e.get(field) == value[field]
                                  for e in self.entries) >= value.get('count', 1))
        elif path == '/release':
            with self.condition:
                self.released.add(value['id'])
                self.condition.notify_all()
        elif path == '/mark':
            self.record({k: value[k] for k in ('kind', 'id', 'scenario')})
        elif path == '/emit':
            if self.config['transport'] != 'stdio':
                return 400, {'error': 'Emit requires stdio'}
            response = value['response']
            self.validator.validate('intercept-response', response)
            with self.output_lock:
                self.record({'kind': 'emitted', 'id': response['id']})
                print(json.dumps(response, separators=(',', ':')), flush=True)
        elif path == '/shutdown':
            self.stop()
        else:
            return 404, {'error': 'Unknown control'}
        return 200, {'ok': True}

    def stop(self):
        self.stopping.set()
        with self.condition:
            self.condition.notify_all()

    def listener(self, control, upload_only=False):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.handle_request()

            def do_POST(self):
                self.handle_request()

            def handle_request(self):
                try:
                    self.connection.settimeout(TIMEOUT)
                    if not control and not upload_only and not authenticated(self.headers, self.connection, owner.config.get('auth', {})):
                        self.send_response(401)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    size = int(self.headers.get('Content-Length', 0))
                    if size < 0 or size > 4 * 1024 * 1024:
                        self.send_response(413 if size > 0 else 400)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    raw = self.rfile.read(size)
                    if upload_only:
                        status, descriptor = receive(owner.content, self.headers, raw, owner.authorize_upload) if self.path == '/content' and self.command == 'POST' else (404, None)
                        owner.record({'kind': 'upload', 'status': status, 'size': size,
                                      'sha256': self.headers.get('AHP-Content-SHA256'),
                                      **(descriptor or {})})
                        body = json.dumps(descriptor).encode() if descriptor is not None else b''
                        self.send_response(status)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    value = loads(raw) if size else {}
                    if control:
                        status, result = owner.control(self.path, value)
                    elif self.path in ('/intercept', '/observe', '/capabilities'):
                        result = owner.protocol(value)
                        status = 200
                    else:
                        status, result = 404, {'error': 'Unknown protocol path'}
                except CatalogueRejection as error:
                    status, result = error.status, None
                except ProtocolError as error:
                    status, result = 409, {'error': str(error)}
                except Exception as error:
                    status, result = 400, {'error': str(error)}
                body = json.dumps(result).encode() if result is not None else b''
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        listener = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = tls_context(self.config.get('auth', {}), True) if not control and not upload_only else None
        if context:
            listener.socket = context.wrap_socket(listener.socket, server_side=True)
        listener.daemon_threads = True
        self.listeners.append(listener)
        threading.Thread(target=listener.serve_forever, daemon=True).start()
        return ('https' if context else 'http') + '://127.0.0.1:' + str(listener.server_port)

    def stdio_request(self, line):
        try:
            response = self.protocol(loads(line))
            if response is not None:
                with self.output_lock:
                    print(json.dumps(response, separators=(',', ':')), flush=True)
        except CatalogueRejection:
            pass  # Notifications never receive a stdio error response.
        except Exception as error:
            if not self.stopping.is_set():
                print(str(error), file=sys.stderr, flush=True)
                os._exit(1)  # Invalid stdio notifications have no response channel.

    def stdio(self):
        buffer = b''
        while not self.stopping.is_set():
            chunk = os.read(0, 65536)
            if not chunk:
                break
            buffer += chunk
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                threading.Thread(target=self.stdio_request, args=(line,), daemon=True).start()
            if len(buffer) > 4 * 1024 * 1024:
                os._exit(1)
        self.stop()

    def run(self):
        control = self.listener(True)
        upload_endpoint = self.listener(False, upload_only=True) + '/content'
        endpoint = self.listener(False) if self.config['transport'] == 'http' else None
        atomic_json(self.config['readinessFile'], {
            'endpoint': endpoint, 'controlEndpoint': control, 'uploadEndpoint': upload_endpoint, 'pid': os.getpid()})
        if self.config['transport'] == 'stdio':
            threading.Thread(target=self.stdio, daemon=True).start()
        try:
            self.stopping.wait()
        finally:
            self.stop()
            for listener in self.listeners:
                listener.shutdown()
                listener.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    config = loads(Path(parser.parse_args().config).read_text())
    if config['transport'] == 'stdio' and config.get('auth', {}).get('mode', 'none') != 'none':
        raise ProtocolError('Stdio uses process trust')
    Server(config).run()


if __name__ == '__main__':
    main()
