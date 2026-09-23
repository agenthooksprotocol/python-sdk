"""Serial host-side compaction interception. Text replacement is opt-in.

Hooks get detached snapshots and return draft effect arrays. Responses stage
privately. Only `applied` permits downstream use. Upload returned immutable UTF-8
bodies before exposing references on the wire. No LLM is required.
"""
from copy import deepcopy
from threading import Thread
from .runtime import Validator


def compaction_capabilities(boundary, observe_only=False):
    if boundary not in ('before', 'after'):
        raise ValueError('unknown boundary')
    if observe_only:
        return {'effects': [], 'modify': {}}
    return {'effects': ['modify', 'message'] + (['return', 'deny'] if boundary == 'before' else []),
            'modify': {'instructions' if boundary == 'before' else 'summary': {'replace': True, 'merge': False}}}


def run_compaction(instructions, before=(), after=(), *, generate=None,
                   item_id='summary-1', observe_only=False):
    """Hooks are (supplier, fail-open|fail-closed, callback) tuples.

    Return binds to final instructions in its response; later effective input
    changes invalidate it. Observe-only after callbacks are detached daemon-thread
    notifications of settled state; return values and failures are ignored.
    """
    if not isinstance(instructions, str) or not isinstance(item_id, str) or not item_id:
        raise ValueError('instructions and nonempty item ID required')
    validator = Validator()
    before, after = list(before), list(after)
    for supplier, policy, callback in before + after:
        if not isinstance(supplier, str) or not supplier or policy not in ('fail-open', 'fail-closed') or not callable(callback):
            raise ValueError('invalid hook configuration')
    state = {'instructions': instructions, 'candidate': None, 'summary': None,
             'bodies': {}, 'messages': [], 'denied': False}
    seen, failures = [], []
    def summary(staged, body):
        ref = 'urn:ahp:compaction:utf8:' + body.encode('utf-8').hex()
        staged['bodies'][ref] = body
        return {'id': item_id, 'ref': ref}
    def pipeline(boundary, hooks):
        nonlocal state
        caps = compaction_capabilities(boundary, observe_only and boundary == 'after')
        for supplier, policy, callback in hooks:
            snapshot = dict(deepcopy(state), boundary=boundary, capabilities=caps)
            seen.append(deepcopy(snapshot))
            try:
                effects = callback(deepcopy(snapshot))
                if not isinstance(effects, list):
                    raise ValueError('effects must be an array')
                staged = deepcopy(state)
                for effect in effects:
                    validator.validate('effect', effect)
                    if effect['type'] not in caps['effects']:
                        raise ValueError('unsupported effect')
                    kind = effect['type']
                    if kind == 'modify':
                        target = 'instructions' if boundary == 'before' else 'summary'
                        if effect.get('target') != target or effect.get('operation') != 'replace' or not isinstance(effect.get('value'), str):
                            raise ValueError('invalid modification')
                        if boundary == 'before':
                            staged['instructions'] = effect['value']
                        else:
                            staged['summary'] = summary(staged, effect['value'])
                    elif kind == 'deny' and (not isinstance(effect.get('reason'), str) or not effect['reason']):
                        raise ValueError('denial requires a reason')
                    elif kind == 'return' and not isinstance(effect.get('value'), str):
                        raise ValueError('summary must be text')
                    elif kind == 'message' and not isinstance(effect.get('text'), str):
                        raise ValueError('message must be text')
                if staged['instructions'] != state['instructions']:
                    staged['candidate'] = None
                for effect in effects:
                    if effect['type'] == 'return':
                        staged['candidate'] = {'body': effect['value'], 'supplier': supplier}
                    elif effect['type'] == 'deny':
                        staged['denied'] = True
                    elif effect['type'] == 'message':
                        staged['messages'].append(effect['text'])
                state = staged
            except Exception:
                failures.append({'boundary': boundary, 'supplier': supplier})
                if policy == 'fail-closed' and not (observe_only and boundary == 'after'):
                    return False
            if state['denied']:
                return False
        return True
    generated, applied, provenance = False, False, None
    if pipeline('before', before):
        candidate = state['candidate']
        if candidate is not None:
            body = candidate['body']
            provenance = {'kind': 'supplied', 'supplier': candidate['supplier']}
        else:
            body = (generate or (lambda value: 'summary:' + value))(state['instructions'])
            if not isinstance(body, str):
                raise ValueError('generator must return text')
            generated = True
            provenance = {'kind': 'generated'}
        state['summary'] = summary(state, body)
        applied = True if observe_only else pipeline('after', after)
    result = dict(state, seen=seen, failures=failures, generated=generated,
                  provenance=provenance, applied=applied)
    if observe_only and applied:
        # Settlement is complete. Detached notifications have no effect authority
        # and never mutate result/diagnostics, even after the caller returns.
        deliveries = []
        for _, _, callback in after:
            snapshot = dict(deepcopy(state), boundary='after', applied=True,
                            generated=generated, provenance=deepcopy(provenance),
                            capabilities=compaction_capabilities('after', True))
            seen.append(deepcopy(snapshot))
            deliveries.append((callback, snapshot))
        def notify(callback, snapshot):
            try:
                callback(snapshot)  # Return values are deliberately ignored.
            except BaseException:
                pass  # Best effort, including callback SystemExit/cancellation.
        for callback, snapshot in deliveries:
            try:
                Thread(target=notify, args=(callback, snapshot), daemon=True).start()
            except RuntimeError:
                pass  # Scheduler failure cannot reopen settlement.
    return result
