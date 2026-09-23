"""Local registration enforcement against a validated, discovered host manifest.

Environment and credential resolution are trusted host inputs, not manifest identity.
This evaluator does not contact registered endpoints or expose credentials in results.
"""
from .runtime import ProtocolError


def validate_registration(registration, manifest, requirements, context, validator, *, resolve_credential=None):
    validator.validate('registration', registration)
    # The caller supplies the actual discovery result; validate its shape again.
    validator.validate('capabilities-response', {'jsonrpc': '2.0', 'id': 'registration-validation',
        'result': {'protocolVersion': registration['protocolVersion'], 'manifest': manifest}})
    environment = context.get('environment', {})
    if not isinstance(environment, dict) or type(context.get('interactive')) is not bool:
        raise ProtocolError('Invalid trusted host context')

    def credential(auth, *, event=True):
        kind = auth['type']
        if event and kind not in manifest['authentication']:
            raise ProtocolError('Unsupported authentication')
        if kind == 'bearer' and 'tokenEnv' in auth:
            value = environment.get(auth['tokenEnv'])
            if not isinstance(value, str) or not value:
                raise ProtocolError('Unresolved bearer credential')
            return
        refs = {'bearer': ['tokenRef'], 'oauth': ['clientSecretRef'],
                'mtls': ['certificateRef', 'privateKeyRef', 'trustRootsRef'],
                'workload': ['credentialRef']}.get(kind)
        if refs is None or resolve_credential is None:
            raise ProtocolError('No trusted credential resolver')
        if kind == 'oauth' and auth['flow'] != 'client_credentials' and not context['interactive']:
            raise ProtocolError('Interactive authentication unavailable')
        if not all(auth.get(key) and resolve_credential(auth[key]) for key in refs):
            raise ProtocolError('Unresolved configured credential')

    def advertised(event, mode):
        found = next((e for e in manifest['events'] if e['event'] == event and mode in e['modes']), None)
        if found is None:
            raise ProtocolError('Unsupported event or delivery mode')
        return found.get('capabilities', {'effects': []})

    ids, subscriptions = set(), set()
    policy = manifest['managedPolicy']
    for backend in registration['hooks']:
        if backend['id'] in ids:
            raise ProtocolError('Duplicate backend ID')
        ids.add(backend['id'])
        if backend['transport']['type'] not in manifest['transports']:
            raise ProtocolError('Unsupported transport')
        if 'authentication' in backend:
            credential(backend['authentication'])
        for subscription in backend['subscriptions']:
            scope = subscription.get('scope', 'user')
            if scope not in policy['scopes'] or scope == 'managed' and policy['disableable']:
                raise ProtocolError('Unenforceable subscription scope')
            if subscription.get('disableable') is False and policy['disableable']:
                raise ProtocolError('Non-disableable policy cannot be enforced')
            limits = manifest['limits']
            timeout = subscription.get('timeoutMs')
            if timeout is not None:
                if timeout < limits.get('minTimeoutMs', 0) or 'maxTimeoutMs' in limits and timeout > limits['maxTimeoutMs']:
                    raise ProtocolError('Unsupported interception timeout')
            if subscription.get('upload', {}).get('auth'):
                credential(subscription['upload']['auth'], event=False)
            for selector in subscription['events']:
                names = [entry['event'] for entry in manifest['events'] if selector == '*' or
                         selector.endswith('.*') and entry['event'].startswith(selector[:-1]) or
                         entry['event'] == selector]
                if not names:
                    raise ProtocolError('Unsupported event selector')
                for event in names:
                    advertised(event, subscription['mode'])
                    subscriptions.add((event, subscription['mode']))
    if not isinstance(requirements, list):
        raise ProtocolError('Invalid requirements')
    for requirement in requirements:
        if not isinstance(requirement, dict) or not all(k in requirement for k in ('event', 'mode')):
            raise ProtocolError('Invalid requirement')
        pair = (requirement['event'], requirement['mode'])
        if pair not in subscriptions:
            raise ProtocolError('Requirement has no matching subscription')
        caps = advertised(*pair)
        effects = requirement.get('effects', [])
        if not isinstance(effects, list) or any(e not in caps['effects'] for e in effects):
            raise ProtocolError('Unsupported required effect')
        if 'ask' in effects and not context['interactive']:
            raise ProtocolError('Cannot ask at a noninteractive boundary')
        modify = requirement.get('modify', {})
        if not isinstance(modify, dict):
            raise ProtocolError('Invalid modification requirements')
        for target, operations in modify.items():
            if not isinstance(operations, dict):
                raise ProtocolError('Invalid operation requirements')
            for operation, required in operations.items():
                if type(required) is not bool:
                    raise ProtocolError('Invalid operation requirement')
                if required and ('modify' not in caps['effects'] or caps.get('modify', {}).get(target, {}).get(operation) is not True):
                    raise ProtocolError('Unsupported required modification')
    return True
