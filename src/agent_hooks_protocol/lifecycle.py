"""In-memory lifecycle semantics; no durable or physical cancellation claim."""
from copy import deepcopy
from hashlib import sha256
from threading import RLock
from .runtime import ProtocolError, apply_response
from .lineage import TaskLineage


class Lifecycle:
    def __init__(self, validator, *, native_authorize=None, native_approve=None):
        self.validator = validator
        self.native_authorize = native_authorize
        self.native_approve = native_approve
        self.accepting = {}
        self.lock = RLock()
        self.lineage = TaskLineage(validator)
        self.pending = {}
        self.staged = {}
        self.terminal = {}
        self.states = {}

    def send(self, request):
        self.validator.validate('intercept-request', request)
        with self.lock:
            self.lineage.accept(request['params']['event'])
            previous = self.pending.setdefault(request['id'], deepcopy(request))
            if previous != request:
                raise ProtocolError('Retry changed logical request')

    def receive(self, request, response):
        self.validator.validate('intercept-response', response)
        with self.lock:
            ident = request['id']
            if (ident not in self.pending or self.pending[ident] != request or
                    response['id'] != ident or ident in self.terminal or ident in self.staged):
                return False
            self.staged[ident] = deepcopy(response)
            return True

    def cancel(self, ident):
        with self.lock:
            if self.terminal.get(ident) == 'cancelled':
                return False
            self.terminal[ident] = 'cancelled'
            self.accepting.pop(ident, None)
            self.staged.pop(ident, None)
            return True

    def accept(self, ident, fallback=False):
        # Reserve one publication attempt, but never hold the state lock while
        # calling host authorization. Both reentrant and cross-thread cancellation
        # invalidate the attempt before any staged state can become visible.
        with self.lock:
            if ident in self.terminal or ident in self.accepting:
                return None
            response = ({'jsonrpc': '2.0', 'id': ident,
                         'result': {'protocolVersion': 'draft', 'effects': []}}
                        if fallback else self.staged.get(ident))
            if response is None:
                return None
            token = object()
            self.accepting[ident] = token
            request, response = deepcopy(self.pending[ident]), deepcopy(response)
        try:
            state = apply_response(request, response, self.validator,
                                   native_authorize=self.native_authorize,
                                   native_approve=self.native_approve)
        except BaseException:
            with self.lock:
                if self.accepting.get(ident) is token:
                    del self.accepting[ident]
            raise
        with self.lock:
            if self.accepting.get(ident) is not token or ident in self.terminal:
                return None
            del self.accepting[ident]
            self.states[ident] = state
            self.terminal[ident] = 'accepted'
            self.staged.pop(ident, None)
            return deepcopy(state)

    def observe_native(self, notification):
        """Snapshot an already-settled native occurrence, not an interception result."""
        with self.lock:
            snapshot = deepcopy(notification)
            self.validator.validate('observe-notification', snapshot)
            self.lineage.accept(snapshot['params']['event'])
            return snapshot

    def settle_native(self, event, *, decision='allow', flow=None):
        if decision not in ('allow', 'ask', 'deny') or flow not in (None, 'stop'):
            raise ProtocolError('Unknown native settlement')
        with self.lock:
            self.lineage.accept(event)
            ident = event['id']
            if ident in self.terminal:
                raise ProtocolError('Boundary already settled')
            self.states[ident] = {'decision': decision, 'flow': flow,
                                  'event': deepcopy(event),
                                  'input': deepcopy(event.get('tool', {}).get('input', {}))}
            self.terminal[ident] = 'accepted'

    def observe(self, request, subscription, items=None):
        with self.lock:
            ident = request['id']
            if ident not in self.terminal:
                raise ProtocolError('Observation before settlement')
            event = deepcopy(request['params']['event'])
            if ident in self.states:
                event = deepcopy(self.states[ident].get('event', event))
                if 'tool' in event:
                    event['tool']['input'] = deepcopy(self.states[ident]['input'])
            if items is not None:
                event['items'] = deepcopy(items)
            notification = {'jsonrpc': '2.0', 'method': 'hooks/observe', 'params': {
                'protocolVersion': 'draft', 'event': event}}
            self.validator.validate('observe-notification' if notification.get('method') == 'hooks/observe' else 'intercept-request', notification)
            return notification


class ContentStore:
    """Immutable credential-scoped bytes, with caller-supplied authorization."""
    def __init__(self, validator, authorize):
        self.validator = validator
        self.authorize = authorize
        self.lock = RLock()
        self.blobs = {}

    def upload(self, value):
        """Allocate a new immutable reference in an authorized receiver scope."""
        from uuid import uuid4
        scope = value.get('scope')
        if scope is None or not self.authorize(scope):
            return 403, None
        data = value.get('data')
        if (not isinstance(data, bytes) or type(value.get('size')) is not int or
                len(data) != value['size'] or sha256(data).hexdigest() != value.get('sha256')):
            return 400, None
        descriptor = {'ref': str(uuid4()), 'size': len(data), 'sha256': sha256(data).hexdigest()}
        self.confirm(scope, descriptor, data)
        return 201, descriptor

    def confirm(self, scope, descriptor, data):
        """Cache a validated receiver confirmation on the sending side."""
        self.validator.validate('content-reference', descriptor)
        if (not self.authorize(scope) or not isinstance(data, bytes) or
                len(data) != descriptor['size'] or sha256(data).hexdigest() != descriptor['sha256']):
            raise ProtocolError('Invalid content confirmation')
        with self.lock:
            key = (scope, descriptor['ref'])
            if key in self.blobs and self.blobs[key] != data:
                raise ProtocolError('Cannot replace immutable content')
            self.blobs[key] = data

    def verify(self, notification, scope=None):
        self.validator.validate('observe-notification' if notification.get('method') == 'hooks/observe' else 'intercept-request', notification)
        params = notification['params']
        with self.lock:
            for item in content_items(params['event']):
                self.validator.validate('content-item', item)
                if 'body' not in item:
                    continue
                body = item['body']
                for key in ('size', 'sha256'):
                    if key in item and item[key] != body[key]:
                        raise ProtocolError('Content metadata mismatch')
                data = self.blobs.get((scope, body['ref']))
                if (scope is None or not self.authorize(scope) or data is None or
                        len(data) != body['size'] or sha256(data).hexdigest() != body['sha256']):
                    raise ProtocolError('Unauthorized or uncommitted content reference')


def content_items(value):
    if isinstance(value, dict):
        if 'body' in value and isinstance(value['body'], dict) and 'ref' in value['body']:
            yield value
        for child in value.values():
            yield from content_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from content_items(child)


def dispatch_observations(event, subscriptions, called, prepare, notify):
    """Dispatch a settled boundary without waiting for observers.

    Subscriptions are the matching, authorized subscriptions. ``called`` contains
    intercept subscription IDs already invoked, not backend IDs. ``prepare``
    applies that subscription's existing permissions/selections and confirms its
    selected uploads before returning the event. Failures are best effort.
    Daemon workers must not keep interrupted execution alive.
    """
    from threading import Thread
    snapshot = deepcopy(event)
    called = set(called)
    def deliver(subscription):
        try:
            projected = prepare(deepcopy(snapshot), subscription)
            if any(projected.get(k) != snapshot.get(k) for k in ('id', 'source', 'type')):
                raise ProtocolError('Observation changed boundary identity')
            notify({'jsonrpc': '2.0', 'method': 'hooks/observe', 'params': {
                'protocolVersion': 'draft',
                'event': projected}})
        except Exception:
            pass  # Observation failure cannot reopen settlement.
    for subscription in deepcopy(subscriptions):
        if subscription['mode'] == 'observe' or (subscription['mode'] == 'intercept' and subscription['id'] not in called):
            Thread(target=deliver, args=(subscription,), daemon=True).start()
