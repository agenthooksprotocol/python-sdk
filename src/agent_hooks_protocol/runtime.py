"""Canonical validation and side-effect-free atomic boundary evaluation."""
from copy import deepcopy
import json
import os
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from . import generated


class ProtocolError(ValueError):
    pass


class Validator:
    def __init__(self, directory=None):
        directory = directory or os.environ.get('AHP_SCHEMA_DIR')
        if directory is None:
            bundle = json.loads(Path(__file__).with_name('schemas.json').read_text())
            schemas = {schema['$id'].rsplit('/', 1)[-1]: schema for schema in bundle}
        else:
            schemas = {p.name: json.loads(p.read_text()) for p in Path(directory).glob('*.schema.json')}
        if not schemas:
            raise ProtocolError('Canonical schemas unavailable')
        registry = Registry().with_resources((s['$id'], Resource.from_contents(s)) for s in schemas.values())
        self.validators = {n: Draft202012Validator(s, registry=registry, format_checker=FormatChecker()) for n, s in schemas.items()}

    def validate(self, kind, value):
        codec = getattr(generated, 'parse_' + kind.replace('-', '_'), None)
        if codec is None:
            raise ProtocolError('Generated codec unavailable: ' + kind)
        if not self.validators[kind + '.schema.json'].is_valid(value):
            error = next(self.validators[kind + '.schema.json'].iter_errors(value))
            raise ProtocolError('Canonical schema rejected ' + kind + ': ' + '/'.join(map(str, error.path)))
        if not codec(value)['ok']:
            raise ProtocolError('Generated codec rejected ' + kind)
        return value


def json_equal(left, right):
    """JSON equality: booleans are not numbers; object member order is irrelevant."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(json_equal(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(json_equal(a, b) for a, b in zip(left, right))
    return left == right


def apply_response(request, response, validator, *, native_authorize=None, native_approve=None, validate_operation=None):
    """Stage a complete response; neither argument is mutated on failure."""
    validator.validate('intercept-request', request)
    validator.validate('intercept-response', response)
    params = request['params']
    if response['id'] != request['id'] or request['id'] != params['event']['id']:
        raise ProtocolError('Correlation mismatch')
    if response['result']['protocolVersion'] != params['protocolVersion']:
        raise ProtocolError('Protocol version mismatch')
    effects, caps, event = response['result']['effects'], params['capabilities'], params['event']
    state = deepcopy(params.get('state', {}))
    original = deepcopy(event.get('tool', {}).get('input', event.get('input', {})))
    effective = deepcopy(original)
    effective_event = deepcopy(event)
    targets = {'input': ('tool', 'input')} if 'tool' in event else {}
    if event['type'] == 'workspace.change.before':
        targets['workspace'] = ('workspace', 'change')
    for target, event_type, path in [
        ('prompt', 'turn.start', ('items',)),
        ('output', 'tool.after', ('items',)),
        ('request', 'model.request.before', ('params',)),
        ('response', 'model.response.after', ('items',)),
        ('response', 'turn.finish.before', ('items',)),
        ('content', 'context.compact.before', ('items',)),
        ('instructions', 'context.compact.before', ('instructions',)),
        ('summary', 'context.compact.after', ('summary',)),
    ]:
        if event['type'] == event_type:
            targets[target] = path
    permission = state.get('permission', 'none')
    denied, candidate = permission == 'deny', state.get('candidate')
    messages = []
    injections = deepcopy(state.get('injections', []))
    flow = state.get('flow')
    if flow == 'none':
        flow = None
    continuation_instructions = deepcopy(state.get('instructions', []))
    new_continuation = False
    flow_caps = caps.get('flow', {})
    remaining = flow_caps.get('remainingContinuations', flow_caps.get('maxContinuations', 0) - flow_caps.get('continuationCount', 0))
    for effect in effects:
        kind = effect['type']
        if kind not in {'allow', 'deny', 'ask', 'modify', 'return', 'message', 'flow', 'inject'} or kind not in caps['effects']:
            raise ProtocolError('Unsupported effect')
        if kind == 'modify':
            operation = effect['operation']
            support = caps.get('modify', {}).get(effect['target'], {})
            if effect['target'] not in targets or operation not in ('replace', 'merge') or support.get(operation) is not True:
                raise ProtocolError('Unsupported modification')
        if kind == 'flow':
            support = caps.get('flow', {})
            if effect['operation'] not in ('stop', 'continue') or effect['operation'] not in support.get('operations', []):
                raise ProtocolError('Unsupported flow')
            if effect['operation'] == 'continue' and remaining <= 0:
                raise ProtocolError('Continuation budget exhausted')
        if kind == 'inject':
            support = caps.get('inject', {}).get('context', {})
            if effect.get('target') != 'context' or effect.get('operation') != 'append' or support.get('append') is not True or effect.get('deliverAt') not in support.get('deliverAt', []):
                raise ProtocolError('Unsupported injection')
    for effect in effects:
        if effect['type'] != 'modify':
            continue
        value = deepcopy(effect['value'])
        path = targets[effect['target']]
        parent = effective_event
        for key in path[:-1]:
            parent = parent[key]
        previous = parent.get(path[-1])
        if effect['operation'] == 'merge':
            if not isinstance(value, dict) or not isinstance(previous, dict):
                raise ProtocolError('Merge requires object target and value')
            value = {**previous, **value}
        parent[path[-1]] = value
        intermediate = deepcopy(request)
        intermediate['params']['event'] = effective_event
        validator.validate('intercept-request', intermediate)
        if validate_operation is not None:
            validate_operation(effective_event)
        if effect['target'] == 'input':
            effective = deepcopy(value)
    staged_request = deepcopy(request)
    staged_request['params']['event'] = effective_event
    validator.validate('intercept-request', staged_request)
    if not json_equal(effective_event, event):
        candidate = None
        if permission == 'allow':
            permission = 'none'
    for effect in effects:
        kind = effect['type']
        if kind == 'deny':
            denied = True
        elif kind == 'ask':
            permission = 'ask'
        elif kind == 'allow' and permission != 'ask':
            permission = 'allow'
        elif kind == 'return':
            candidate = {'value': deepcopy(effect['value'])}
        elif kind == 'message':
            messages.append(effect['text'])
        elif kind == 'inject':
            injections.append(deepcopy(effect))
        elif kind == 'flow':
            if effect['operation'] == 'continue':
                new_continuation = True
                if 'instruction' in effect:
                    continuation_instructions.append(effect['instruction'])
            if flow != 'stop':
                flow = effect['operation']
    # Host access policy is independent of hook prompt suppression. It gates
    # execution AND supplied-result delivery, and allow cannot bypass it.
    def host_decision(callback):
        value = callback(deepcopy(effective_event))
        if value is not None and type(value) is not bool:
            raise ProtocolError('Host authorization must return true, false, or pending (None)')
        return value

    access = True
    approved = permission == 'allow'
    if not denied and flow != 'stop':
        if native_authorize is not None:
            access = host_decision(native_authorize)
        if access is False:
            denied = True
        elif access is True and permission == 'none':
            if native_approve is not None:
                approved = host_decision(native_approve)
                if approved is False:
                    denied = True
            else:
                # A configured access guard with no approval callback represents
                # a host with no additional ordinary prompt. Without either host
                # callback, an absent hook override does not create authorization.
                approved = native_authorize is not None
    decision = 'deny' if denied else 'ask' if permission == 'ask' else 'allow'
    authorized = decision == 'allow' and access is True and approved is True and flow != 'stop'
    result = {'decision': decision, 'executed': event['type'] == 'tool.before' and authorized and candidate is None,
              'input': effective, 'messages': messages}
    if decision == 'allow' and flow != 'stop' and not authorized:
        result['authorization'] = 'pending'
    if candidate is not None and authorized:
        result['result'] = candidate['value']
    if flow is not None:
        result['flow'] = flow
        if continuation_instructions or any(k in flow_caps for k in ('remainingContinuations', 'maxContinuations', 'continuationCount')):
            result['continuationInstructions'] = continuation_instructions
            result['continuationRemaining'] = remaining - 1 if flow == 'continue' and new_continuation else remaining
    if injections:
        result['injections'] = injections
    if any(e['type'] == 'modify' and e['target'] != 'input' for e in effects) or event['type'] == 'task.change.before':
        result['event'] = effective_event
    return result
