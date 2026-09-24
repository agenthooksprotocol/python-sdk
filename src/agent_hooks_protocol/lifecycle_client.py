"""Lifecycle script driver. Receipts/barriers are test proofs, not AHP acks."""
import argparse
import base64
from .content import upload
from .interop import wire_request, replace_references, validate_adapter_config
from collections import defaultdict, deque
from concurrent.futures import Future, ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler
from .interop import atomic_json, loads, NoRedirect, client_headers, tls_context, synthetic_native_policy
from .lifecycle import Lifecycle, ContentStore
from .runtime import ProtocolError, Validator

TIMEOUT = 30


def http(url, value=None, headers=None, context=None):
    data = None if value is None else json.dumps(value, allow_nan=False).encode()
    request = Request(url, data=data, headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        response = build_opener(NoRedirect(), HTTPSHandler(context=context)).open(request, timeout=TIMEOUT)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        return response.code, loads(body) if body else None


class Transport:
    def __init__(self, config):
        validate_adapter_config(config)
        if config.get('suite', 'lifecycle') not in ('lifecycle', 'catalogue'):
            raise ProtocolError('Unknown suite')
        if config['transport'] == 'stdio' and config.get('auth', {}).get('mode', 'none') != 'none':
            raise ProtocolError('Stdio uses process trust')
        self.headers = client_headers(config.get('auth', {}))
        self.context = tls_context(config.get('auth', {}))
        self.config = config
        self.process = None
        self.pool = ThreadPoolExecutor(max_workers=32)
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.discarded = defaultdict(int)
        self.reader_error = None
        self.reader = None
        self.validator = Validator()
        self.references = {}
        self.confirmed = ContentStore(self.validator, lambda _: True)
        self.pending = defaultdict(deque)
        self.response_kinds = {}
        self.control_endpoint = config.get('controlEndpoint')
        try:
            if config['transport'] == 'stdio':
                server_config = loads(Path(config['serverConfig']).read_text())
                ready = Path(server_config['readinessFile'])
                ready.unlink(missing_ok=True)
                self.process = subprocess.Popen(
                    config['serverCommand'] + ['--config', config['serverConfig']],
                    cwd=config.get('serverCwd'), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, text=True, bufsize=1)
                if config.get('childPidFile'):
                    atomic_json(config['childPidFile'], {'pid': self.process.pid})
                deadline = time.monotonic() + TIMEOUT
                while not ready.exists():
                    if self.process.poll() is not None:
                        raise ProtocolError('Server exited before readiness')
                    if time.monotonic() > deadline:
                        raise TimeoutError('Server readiness timeout')
                    threading.Event().wait(0.01)  # Startup only, never race ordering.
                self.config.update(loads(ready.read_text()))
                self.control_endpoint = self.config['controlEndpoint']
                self.reader = threading.Thread(target=self.read, daemon=True)
                self.reader.start()
            if not self.control_endpoint:
                raise ProtocolError('Missing control endpoint')
        except BaseException:
            self.close()
            raise

    def control(self, path, value=None):
        status, result = http(self.control_endpoint.rstrip('/') + path, value)
        if status != 200:
            raise ProtocolError('Control failed: ' + path + ': ' + str(status))
        return result

    def read(self):
        error = ProtocolError('Server stdout closed')
        try:
            for line in self.process.stdout:
                response = loads(line)
                self.validator.validate(self.response_kinds.get(response.get('id'), 'intercept-response'), response)
                # Observe replies are unconditionally discarded, never staged.
                if response.get('id') == 'unsolicited-observer':
                    continue
                with self.lock:
                    queue = self.pending.get(response.get('id'))
                    if queue:
                        queue.popleft().set_result(response)
                    else:
                        self.discarded[response['id']] += 1
                        self.condition.notify_all()
        except Exception as caught:
            error = caught
        finally:
            with self.lock:
                self.reader_error = error
                self.condition.notify_all()
                for queue in self.pending.values():
                    for future in queue:
                        if not future.done():
                            future.set_exception(error)

    def emit(self, response):
        if self.process is None:
            raise ProtocolError('Emit requires stdio')
        ident = response['id']
        with self.condition:
            before = self.discarded[ident]
        self.control('/emit', {'response': response})
        with self.condition:
            if not self.condition.wait_for(
                    lambda: self.discarded[ident] > before or self.reader_error is not None, TIMEOUT):
                raise TimeoutError('Unsolicited frame drain timeout')
            if self.discarded[ident] <= before:
                raise self.reader_error

    def discover(self, request):
        self.validator.validate('capabilities-request', request)
        if self.process is None:
            return self.http_protocol('/capabilities', request)
        future = Future()
        with self.lock:
            self.response_kinds[request['id']] = 'capabilities-response'
            self.pending[request['id']].append(future)
            self.process.stdin.write(json.dumps(request) + '\n')
            self.process.stdin.flush()
        return future.result(timeout=TIMEOUT)

    def notify(self, notification, *, raw=False):
        notification = replace_references(wire_request(notification), self.references)
        if not raw:
            self.confirmed.verify(notification, 'confirmed')
        if self.process is not None:
            with self.lock:
                self.process.stdin.write(json.dumps(notification) + '\n')
                self.process.stdin.flush()
        else:
            endpoint = self.config['endpoint'].rstrip('/')
            if endpoint.endswith('/intercept'):
                endpoint = endpoint[:-len('/intercept')]
            status, _ = http(endpoint + '/observe', notification, self.headers, self.context)
            if status != 200 and not (raw and status in (400, 409)):
                raise ProtocolError('Notification transport failure: ' + str(status))

    def send(self, request):
        request = replace_references(wire_request(request), self.references)
        self.confirmed.verify(request, 'confirmed')
        if self.process is None:
            return self.pool.submit(self.http_protocol, '/intercept', request)
        future = Future()
        with self.lock:
            self.pending[request['id']].append(future)
            self.process.stdin.write(json.dumps(request) + '\n')
            self.process.stdin.flush()
        return future

    def http_protocol(self, path, request):
        endpoint = self.config['endpoint'].rstrip('/')
        if endpoint.endswith('/intercept'):
            endpoint = endpoint[:-len('/intercept')]
        status, response = http(endpoint + path, request, self.headers, self.context)
        if status != 200:
            raise ProtocolError('Protocol HTTP failure: ' + str(status))
        return response

    def observe(self, notification):
        notification = replace_references(wire_request(notification), self.references)
        self.confirmed.verify(notification, 'confirmed')
        if self.process is None:
            self.http_protocol('/observe', notification)  # Ignore all returned effects.
        else:
            with self.lock:
                self.process.stdin.write(json.dumps(notification) + '\n')
                self.process.stdin.flush()

    def close(self):
        if self.process is not None:
            try:
                if self.control_endpoint:
                    self.control('/shutdown', {})
            except Exception:
                pass
            if self.process.stdin:
                try:
                    self.process.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            if self.reader:
                self.reader.join(timeout=3)
            if self.process.stdout:
                self.process.stdout.close()
        self.pool.shutdown(wait=False, cancel_futures=True)


def run(config):
    validator = Validator()
    fixtures = loads(Path(config['scenarioFile']).read_text())
    transport = Transport(config)
    results = []
    observed = defaultdict(int)
    try:
        if config.get('suite') == 'catalogue':
            from .catalogue import run_catalogue
            return run_catalogue(config, fixtures, transport, validator)
        for scenario in fixtures['scenarios']:
            if 'chain' in scenario:
                from .observation_chain import run_chain
                results.append({'id': scenario['id'], 'actual': run_chain(scenario, transport, validator)})
                continue
            lifecycle = Lifecycle(validator, native_authorize=synthetic_native_policy)
            slots = {}
            actual = {'published': [], 'cancelled': [], 'ignored': [], 'states': {},
                      'observations': [], 'uploadStatuses': []}
            for step in scenario['steps']:
                op = step['op']
                request = replace_references(wire_request(scenario['requests'][step['key']]), transport.references) if 'key' in step else None
                ident = request['id'] if request else None
                if op == 'send':
                    lifecycle.send(request)
                    if step['slot'] in slots:
                        raise ProtocolError('Duplicate transport slot')
                    slots[step['slot']] = (request, transport.send(request))
                elif op in ('wait', 'release'):
                    transport.control('/' + op, {'id': ident, 'count': step.get('count', 1)})
                elif op == 'receive':
                    original, future = slots[step['slot']]
                    if lifecycle.receive(original, future.result(timeout=TIMEOUT)):
                        transport.control('/mark', {'scenario': scenario['id'],
                                          'kind': 'acquired', 'id': original['id']})
                    else:
                        actual['ignored'].append(step['slot'])
                elif op == 'cancel':
                    if lifecycle.cancel(ident):
                        actual['cancelled'].append(ident)
                        transport.control('/mark', {'scenario': scenario['id'], 'kind': 'cancelled', 'id': ident})
                elif op in ('accept', 'failOpen'):
                    # Fallback can settle a boundary with no transport attempt.
                    if op == 'failOpen':
                        lifecycle.send(request)
                    state = lifecycle.accept(ident, fallback=op == 'failOpen')
                    if state is not None:
                        actual['published'].append(ident)
                        actual['states'][ident] = state
                        transport.control('/mark', {'scenario': scenario['id'], 'kind': 'accepted', 'id': ident})
                elif op == 'emit':
                    transport.emit(step['response'])
                    emitted_id = step['response']['id']
                    actual['ignored'].append('unsolicited:' + str(emitted_id))
                    transport.control('/mark', {'scenario': scenario['id'],
                                      'kind': 'discarded', 'id': emitted_id})
                elif op == 'upload':
                    data = base64.b64decode(step['bodyBase64'], validate=True)
                    upload_config = dict(step.get('upload', config.get('upload', {})))
                    upload_config.setdefault('endpoint', transport.config.get('uploadEndpoint'))
                    status, descriptor = upload(upload_config, data, loopback=True, _declared={k: step[k] for k in ('size', 'sha256') if k in step})
                    if status == 201:
                        transport.confirmed.confirm('confirmed', descriptor, data)
                        if 'ref' in step:
                            transport.references[step['ref']] = descriptor
                    actual['uploadStatuses'].append(status)
                elif op == 'observe':
                    notification = lifecycle.observe(request, step['subscription'], replace_references(step.get('items'), transport.references))
                    transport.observe(notification)
                    event = notification['params']['event']
                    observed[event['id']] += 1
                    transport.control('/wait-observed', {'eventId': event['id'], 'count': observed[event['id']]})
                    actual['observations'].append({'eventId': event['id'], 'subscription': step['subscription'],
                                                   'input': event['tool']['input']})
                else:
                    raise ProtocolError('Unknown lifecycle operation: ' + op)
            results.append({'id': scenario['id'], 'actual': actual})
        receipts = transport.control('/receipts')
        atomic_json(config['reportFile'], {'language': 'python', 'results': results, 'receipts': receipts})
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    config = loads(Path(parser.parse_args().config).read_text())
    if config['transport'] == 'stdio' and config.get('auth', {}).get('mode', 'none') != 'none':
        raise ProtocolError('Stdio uses process trust')
    run(config)


if __name__ == '__main__':
    main()
