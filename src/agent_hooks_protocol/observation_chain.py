"""Serial adapter interception followed by one-way, permission-filtered views."""
from copy import deepcopy
from .runtime import apply_response
from .interop import synthetic_native_policy


def run_chain(scenario, transport, validator):
    chain = scenario['chain']
    original = deepcopy(scenario['requests']['a'])
    event = deepcopy(original['params']['event'])
    ident = original['id']
    called, failures, remaining, pending = [], [], [], None
    halted = False
    for subscription in chain['subscriptions']:
        if subscription['mode'] == 'observe' or halted:
            remaining.append(subscription)
            continue
        request = deepcopy(original)
        request['params']['event'] = deepcopy(event)
        if subscription['content'] == 'omit': request['params']['event']['items'] = []
        validator.validate('intercept-request', request)
        called.append(subscription['id'])
        future = transport.send(request)
        transport.control('/wait', {'id': ident, 'count': len(called)})
        if chain.get('interrupt'):
            # Do not acquire this response, or wait for any observer, to stop.
            transport.control('/mark', {'scenario': scenario['id'], 'kind': 'cancelled', 'id': ident})
            pending, halted = future, True
            continue
        transport.control('/release', {'id': ident})
        try:
            response = future.result(timeout=15)
            state = apply_response(request, response, validator, native_authorize=synthetic_native_policy)
            event['tool']['input'] = deepcopy(state['input'])
            halted = state['decision'] == 'deny' or state.get('flow') == 'stop'
        except Exception:
            failures.append(subscription['id'])
            halted = subscription['failurePolicy'] == 'fail-closed'
    transport.control('/mark', {'scenario': scenario['id'], 'kind': 'chain-settled', 'id': ident})
    deliveries = []
    for subscription in remaining:
        projected = deepcopy(event)
        if subscription['content'] == 'omit':
            projected['items'] = []
        else:
            for item in projected.get('items', []):
                item.pop('body', None)
                item.pop('gap', None)
                item['selection'] = 'metadata'
        note = {'jsonrpc': '2.0', 'method': 'hooks/observe', 'params': {
            'protocolVersion': 'draft', 'event': projected}}
        validator.validate('observe-notification', note)
        deliveries.append(transport.pool.submit(transport.observe, note))
    # Test-only drain occurs after settlement and stopping, never on that path.
    if pending is not None:
        transport.control('/release', {'id': ident})
        pending.result(timeout=15)  # Discard late effects; they cannot change event.
    if remaining:
        transport.control('/wait-observed', {'eventId': ident, 'count': len(remaining)})
    if chain.get('holdObservers'):
        transport.control('/release', {'id': ident + ':observers'})
    for delivery in deliveries:
        delivery.result(timeout=15)
    return {'called': called, 'failures': failures, 'observations': [s['id'] for s in remaining], 'input': event['tool']['input']}
