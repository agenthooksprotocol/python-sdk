"""Language-owned integration tests; no fixture expected-result evaluator."""
from copy import deepcopy
import unittest
from agent_hooks_protocol.runtime import Validator, ProtocolError, apply_response
from agent_hooks_protocol.lifecycle import Lifecycle
from agent_hooks_protocol.lineage import TaskLineage
from test_interop import request, response


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.validator = Validator()

    def test_observations_are_effective_payload_only(self):
        for effects, expected in [([], 'normal'), ([{'type': 'ask'}], 'normal'),
                ([{'type': 'deny', 'reason': 'policy'}], 'denied'),
                ([{'type': 'flow', 'operation': 'stop', 'reason': 'done'}], 'stopped')]:
            with self.subTest(expected=expected):
                req = request()
                req['params']['capabilities']['effects'].append('flow')
                req['params']['capabilities']['flow'] = {'operations': ['stop']}
                state = Lifecycle(self.validator)
                state.send(req)
                with self.assertRaises(ProtocolError): state.observe(req, 'audit')
                self.assertTrue(state.receive(req, response(effects)))
                state.accept(req['id'])
                note = state.observe(req, 'audit')
                self.assertNotIn('id', note)
                self.assertNotIn('disposition', note['params'])
                self.assertEqual(note['params']['event']['id'], req['id'])
                state.cancel(req['id'])
                self.assertNotIn('disposition', state.observe(req, 'audit')['params'])

    def test_cancel_preserves_only_accepted_changes(self):
        req = request()
        effects = [{'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'task': 5}},
                   {'type': 'ask'}, {'type': 'allow'}, {'type': 'message', 'text': 'accepted'}]
        for accepted in (False, True):
            state = Lifecycle(self.validator)
            state.send(req); state.receive(req, response(effects))
            if accepted:
                self.assertEqual(state.accept(req['id'])['decision'], 'ask')
            state.cancel(req['id'])
            note = state.observe(req, 'audit')
            self.assertEqual(note['params']['event']['tool']['input']['task'], 5 if accepted else 1)
            self.assertNotIn('disposition', note['params'])

    def test_native_settlement_and_ambiguous_denial_stop(self):
        req = request()
        state = Lifecycle(self.validator)
        state.settle_native(req['params']['event'])
        self.assertNotIn('disposition', state.observe(req, 'audit')['params'])
        state = Lifecycle(self.validator)
        state.settle_native(req['params']['event'], decision='deny', flow='stop')
        self.assertNotIn('disposition', state.observe(req, 'audit')['params'])
        state.cancel(req['id'])
        self.assertNotIn('disposition', state.observe(req, 'audit')['params'])

    def test_effective_operation_requires_fresh_authorization(self):
        req = request()
        req['params']['state'] = {'permission': 'allow', 'candidate': None}
        modify = {'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'task': 2}}
        self.assertFalse(apply_response(req, response([modify]), self.validator)['executed'])
        self.assertTrue(apply_response(req, response([modify, {'type': 'allow'}]), self.validator)['executed'])
        req['params']['state'] = {'permission': 'ask', 'candidate': None}
        self.assertFalse(apply_response(req, response([modify, {'type': 'allow'}]), self.validator)['executed'])
        self.assertFalse(apply_response(request(), response([]), self.validator)['executed'])

    def task(self, ident='task-event', parent=None):
        event = {'id': ident, 'source': 'urn:test:source', 'time': '2026-01-01T00:00:00Z',
                 'type': 'task.change.before', 'task': {'id': 'task-1', 'operation': 'update',
                 'change': {'status': 'complete'}, 'prior': {'status': 'pending'}}}
        if parent is not None: event['parentEventId'] = parent
        return event

    def test_task_payload_identity_and_unsupported_modification(self):
        req = request()
        req['params']['event'] = self.task(parent='origin')
        req['id'] = 'task-event'
        req['params']['capabilities'] = {'effects': ['deny', 'message']}
        reply = response([{'type': 'message', 'text': 'task policy'}]); reply['id'] = req['id']
        actual = apply_response(req, reply, self.validator)
        self.assertEqual(actual['event']['task']['id'], 'task-1')
        self.assertEqual(actual['event']['parentEventId'], 'origin')
        malformed = deepcopy(req)
        del malformed['params']['event']['task']['operation']
        with self.assertRaises(ProtocolError): self.validator.validate('intercept-request', malformed)
        reply['result']['effects'] = [{'type': 'modify', 'target': 'input', 'operation': 'replace', 'value': {'status': 'cancelled'}}]
        with self.assertRaises(ProtocolError): apply_response(req, reply, self.validator)

    def test_task_settlement_and_atomic_effects(self):
        req = request()
        req['params']['event'] = self.task()
        req['id'] = 'task-event'
        req['params']['capabilities'] = {'effects': ['deny', 'message']}
        state = Lifecycle(self.validator)
        state.send(req)
        reply = response([{'type': 'deny', 'reason': 'task policy'}, {'type': 'message', 'text': 'not applied'}])
        reply['id'] = req['id']
        state.receive(req, reply)
        self.assertEqual(state.accept(req['id'])['decision'], 'deny')
        note = state.observe(req, 'audit')
        self.assertNotIn('disposition', note['params'])
        self.assertEqual(note['params']['event']['task']['change']['status'], 'complete')
        state.cancel(req['id'])
        note = state.observe(req, 'audit')
        self.assertNotIn('disposition', note['params'])
        self.assertEqual(note['params']['event']['task']['change']['status'], 'complete')

    def test_task_permission_capabilities_reject_unenforceable_effects(self):
        req = request()
        req['params']['event'] = self.task(); req['id'] = 'task-event'
        req['params']['capabilities'] = {'effects': ['deny', 'message']}
        for effect in ({'type': 'allow'}, {'type': 'ask'},
                {'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'status': 'changed'}}):
            reply = response([effect]); reply['id'] = req['id']
            original = deepcopy(req)
            with self.assertRaises(ProtocolError): apply_response(req, reply, self.validator)
            self.assertEqual(req, original)
        req['params']['capabilities']['effects'].append('allow')
        with self.assertRaises(ProtocolError): self.validator.validate('intercept-request', req)

    def test_workspace_effective_change_and_permission_precedence(self):
        req = request()
        event = self.task(); event.pop('task'); event['type'] = 'workspace.change.before'
        event['workspace'] = {'kind': 'cwd', 'change': {'cwd': '/old'}, 'prior': {'cwd': '/initial'}}
        req['params']['event'] = event; req['id'] = event['id']
        req['params']['capabilities'] = {'effects': ['modify', 'deny', 'message'],
            'modify': {'workspace': {'replace': True, 'merge': True}}}
        rewrite = {'type': 'modify', 'target': 'workspace', 'operation': 'replace', 'value': {'cwd': '/new'}}
        reply = response([rewrite]); reply['id'] = req['id']
        result = apply_response(req, reply, self.validator)
        self.assertEqual(result['event']['workspace']['change'], {'cwd': '/new'})
        self.assertEqual(result['event']['workspace']['prior'], {'cwd': '/initial'})
        reply['result']['effects'].append({'type': 'deny', 'reason': 'managed policy'})
        self.assertEqual(apply_response(req, reply, self.validator)['decision'], 'deny')
        reply['result']['effects'][0]['value'] = {'cwd': 42}
        with self.assertRaises(ProtocolError): apply_response(req, reply, self.validator)
        req['params']['capabilities']['modify']['workspace'] = {'replace': False, 'merge': True}
        reply['result']['effects'][0]['value'] = {'cwd': '/new'}
        with self.assertRaises(ProtocolError): apply_response(req, reply, self.validator)

    def test_deny_plus_stop_does_not_require_observation_arbitration(self):
        req = request()
        req['params']['capabilities']['effects'].append('flow')
        req['params']['capabilities']['flow'] = {'operations': ['stop']}
        state = Lifecycle(self.validator)
        state.send(req)
        state.receive(req, response([{'type': 'deny', 'reason': 'policy'},
                                    {'type': 'flow', 'operation': 'stop', 'reason': 'stop'}]))
        accepted = state.accept(req['id'])
        self.assertEqual((accepted['decision'], accepted['flow']), ('deny', 'stop'))
        self.assertNotIn('disposition', state.observe(req, 'audit')['params'])
        state.cancel(req['id'])
        self.assertNotIn('disposition', state.observe(req, 'audit')['params'])

    def test_source_scoped_late_cycle_and_unknown_ancestry(self):
        graph = TaskLineage(self.validator)
        graph.accept(self.task('child', 'parent'))
        with self.assertRaises(ProtocolError): graph.accept(self.task('parent', 'child'))
        other = self.task('parent', 'child'); other['source'] = 'urn:test:other'
        graph.accept(other)
        producer = TaskLineage(self.validator, producer=True)
        with self.assertRaises(ProtocolError): producer.accept(self.task('child', 'parent'))
        producer.accept(self.task('parent')); producer.accept(self.task('child', 'parent'))

    def test_unknown_effect_semantics_reject_atomically_before_authorization(self):
        invalid = [
            {'type': 'message', 'text': 'hello', 'futureField': True},
            {'type': 'future-effect'},
            {'type': 'modify', 'target': 'input', 'operation': 'future-operation', 'value': {}},
        ]
        for effect in invalid:
            with self.subTest(effect=effect):
                req = request()
                original = deepcopy(req)
                reply = response([
                    {'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'task': 99}},
                    {'type': 'return', 'value': 'must-not-publish'}, effect])
                before = deepcopy(reply)
                with self.assertRaises(ProtocolError):
                    apply_response(req, reply, self.validator,
                        native_authorize=lambda _: self.fail('Invalid response reached authorization'))
                self.assertEqual(req, original)
                self.assertEqual(reply, before)

    def test_unknown_capability_and_control_fields_have_no_effect(self):
        req = request()
        req['params']['state'] = {'permission': 'none', 'candidate': None}
        baseline = apply_response(req, response([]), self.validator)
        req['params']['futureField'] = {'allow': True}
        req['params']['capabilities']['futureField'] = {'allow': True}
        req['params']['capabilities']['modify']['input']['futureField'] = True
        req['params']['state']['futureField'] = {'permission': 'allow'}
        actual = apply_response(req, response([]), self.validator)
        self.assertEqual(actual, baseline)
        req['params']['state']['permission'] = 'future-permission'
        with self.assertRaises(ProtocolError):
            apply_response(req, response([]), self.validator)

    def test_elicitation_capability_extensions_do_not_grant_modes(self):
        from agent_hooks_protocol.elicitation import validate_mode
        self.assertEqual(validate_mode('form', {'form': {}, 'futureField': True}), {'form': {}})
        with self.assertRaises(ValueError):
            validate_mode('url', {'form': {}, 'futureField': {'url': {}}})
        with self.assertRaises(ValueError):
            validate_mode('form', {'form': True, 'futureField': {}})
