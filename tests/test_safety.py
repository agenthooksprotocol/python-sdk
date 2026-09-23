from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Event
import unittest
from agent_hooks_protocol.lifecycle import Lifecycle
from agent_hooks_protocol.runtime import Validator, ProtocolError, apply_response
from test_interop import request, response


class SettlementSafetyTests(unittest.TestCase):
    def setUp(self): self.validator = Validator()

    def stage(self, authorize, effects=None, approve=None):
        req = request()
        life = Lifecycle(self.validator, native_authorize=authorize, native_approve=approve)
        life.send(req)
        life.receive(req, response(effects or []))
        return life, req

    def test_reentrant_cancellation_cannot_be_overwritten(self):
        calls = []
        def authorize(event):
            calls.append(deepcopy(event))
            self.assertTrue(life.cancel(req['id']))
            return True
        effects = [{'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'task': 2}},
                   {'type': 'allow'}, {'type': 'return', 'value': 'must-not-publish'}]
        life, req = self.stage(authorize, effects)
        self.assertIsNone(life.accept(req['id']))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['tool']['input']['task'], 2)
        self.assertEqual(life.terminal[req['id']], 'cancelled')
        self.assertEqual(life.states, {})
        note = life.observe(req, 'audit')
        self.assertNotIn('disposition', note['params'])
        self.assertEqual(note['params']['event'], req['params']['event'])
        self.assertIsNone(life.accept(req['id'], fallback=True))

    def test_cross_thread_cancellation_while_authorization_is_blocked(self):
        entered, release = Event(), Event()
        def authorize(event):
            entered.set()
            if not release.wait(5): raise RuntimeError('Authorization barrier timeout')
            return True
        life, req = self.stage(authorize, [{'type': 'allow'}])
        with ThreadPoolExecutor(max_workers=2) as pool:
            accepting = pool.submit(life.accept, req['id'])
            try:
                self.assertTrue(entered.wait(5))
                self.assertTrue(pool.submit(life.cancel, req['id']).result(timeout=2))
            finally:
                release.set()
            self.assertIsNone(accepting.result(timeout=5))
        self.assertEqual(life.states, {})
        self.assertNotIn('disposition', life.observe(req, 'audit')['params'])

    def test_single_inflight_accept_and_preserved_accepted_state(self):
        entered, release = Event(), Event()
        calls = []
        def authorize(event):
            calls.append(event)
            entered.set()
            if not release.wait(5): raise RuntimeError('Authorization barrier timeout')
            return True
        effects = [{'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {'task': 3}},
                   {'type': 'return', 'value': 'accepted'}]
        life, req = self.stage(authorize, effects)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(life.accept, req['id'])
            try:
                self.assertTrue(entered.wait(5))
                self.assertIsNone(life.accept(req['id']))
            finally:
                release.set()
            state = future.result(timeout=5)
        self.assertEqual(len(calls), 1)
        self.assertEqual(state['result'], 'accepted')
        before = deepcopy(life.states)
        life.cancel(req['id'])
        self.assertEqual(life.states, before)
        note = life.observe(req, 'audit')
        self.assertEqual(note['params']['event']['tool']['input']['task'], 3)
        self.assertNotIn('disposition', note['params'])

    def test_native_refusal_gates_candidates_and_allow_cannot_bypass_it(self):
        for effects in ([{'type': 'return', 'value': 'secret'}],
                        [{'type': 'allow'}, {'type': 'return', 'value': 'secret'}],
                        [{'type': 'allow'}]):
            with self.subTest(effects=effects):
                calls = []
                def refuse(event): calls.append(event); return False
                actual = apply_response(request(), response(effects), self.validator, native_authorize=refuse)
                self.assertEqual(len(calls), 1)
                self.assertEqual(actual['decision'], 'deny')
                self.assertFalse(actual['executed'])
                self.assertNotIn('result', actual)

    def test_pending_authorization_never_exposes_candidate(self):
        for authorize in (None, lambda event: None):
            actual = apply_response(request(), response([{'type': 'return', 'value': 'secret'}]),
                                    self.validator, native_authorize=authorize)
            self.assertEqual(actual['authorization'], 'pending')
            self.assertFalse(actual['executed'])
            self.assertNotIn('result', actual)

    def test_prompt_suppression_is_separate_from_required_access_policy(self):
        calls = []
        def access(event): calls.append('access'); return True
        def prompt(event): calls.append('prompt'); return False
        effects = [{'type': 'return', 'value': 'authorized'}]
        actual = apply_response(request(), response(effects), self.validator,
                                native_authorize=access, native_approve=prompt)
        self.assertEqual(calls, ['access', 'prompt'])
        self.assertEqual(actual['decision'], 'deny')
        self.assertNotIn('result', actual)
        calls.clear()
        actual = apply_response(request(), response([{'type': 'allow'}, *effects]), self.validator,
                                native_authorize=access, native_approve=prompt)
        self.assertEqual(calls, ['access'])
        self.assertEqual(actual['result'], 'authorized')
        calls.clear()
        actual = apply_response(request(), response([{'type': 'ask'}, {'type': 'allow'}, *effects]),
                                self.validator, native_authorize=access, native_approve=prompt)
        self.assertEqual(calls, ['access'])
        self.assertEqual(actual['decision'], 'ask')
        self.assertNotIn('result', actual)

    def test_prior_stop_instructions_and_injections_survive_empty_response(self):
        req = request()
        injection = {'type': 'inject', 'target': 'context', 'operation': 'append', 'deliverAt': 'next_turn', 'value': 'retained'}
        req['params']['state'] = {'permission': 'allow', 'candidate': {'value': 'old', 'provenance': {}},
                                  'flow': 'stop', 'instructions': ['already accepted'], 'injections': [injection]}
        req['params']['capabilities']['effects'].append('flow')
        req['params']['capabilities']['flow'] = {'operations': ['stop'], 'remainingContinuations': 2}
        original = deepcopy(req)
        def must_not_run(event): self.fail('Stopped operation attempted authorization')
        actual = apply_response(req, response([]), self.validator, native_authorize=must_not_run)
        self.assertEqual(actual['flow'], 'stop')
        self.assertEqual(actual['continuationInstructions'], ['already accepted'])
        self.assertEqual(actual['continuationRemaining'], 2)
        self.assertEqual(actual['injections'], [injection])
        self.assertFalse(actual['executed'])
        self.assertNotIn('result', actual)
        self.assertEqual(req, original)
