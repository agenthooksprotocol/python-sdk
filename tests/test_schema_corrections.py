from copy import deepcopy
import unittest
from agent_hooks_protocol import generated
from agent_hooks_protocol.runtime import Validator, ProtocolError, apply_response
from test_interop import request, response


class CorrectedSchemaTests(unittest.TestCase):
    def setUp(self): self.validator = Validator()

    def test_effect_branches_reject_unknown_fields_atomically(self):
        effects = [
            {'type': 'allow'},
            {'type': 'ask'},
            {'type': 'deny', 'reason': 'policy'},
            {'type': 'modify', 'target': 'input', 'operation': 'merge', 'value': {}},
            {'type': 'message', 'text': 'hello'},
            {'type': 'return', 'value': None},
            {'type': 'flow', 'operation': 'stop', 'reason': 'budget'},
            {'type': 'flow', 'operation': 'continue', 'instruction': 'retry'},
            {'type': 'inject', 'target': 'context', 'operation': 'append',
             'deliverAt': 'now', 'value': 'context'},
        ]
        for effect in effects:
            with self.subTest(effect=effect):
                self.validator.validate('intercept-response', response([effect]))
                self.assertTrue(generated.parse_effect(effect)['ok'])
                invalid = {**effect, 'unexpected': True}
                # Generated structural codecs are permissive; canonical schemas
                # enforce the strict fields before runtime publication.
                with self.assertRaises(ProtocolError):
                    self.validator.validate('intercept-response', response([invalid]))
                req = request()
                reply = response([
                    {'type': 'modify', 'target': 'input', 'operation': 'merge',
                     'value': {'staged': True}}, invalid])
                before = deepcopy((req, reply))
                with self.assertRaises(ProtocolError):
                    apply_response(req, reply, self.validator)
                self.assertEqual((req, reply), before)

    def model_request(self):
        req = request()
        req['params']['event'] = {'id': req['id'], 'type': 'model.response.after',
            'source': 'urn:python:model', 'time': '2026-01-01T00:00:00Z', 'synthesized': True,
            'model': {'id': 'model-1', 'provider': 'test'},
            'attempt': {'id': 'attempt-1', 'number': 1, 'synthesized': True},
            'execution': {'status': 'executed'}, 'items': [], 'finishReason': 'stop'}
        req['params']['capabilities'] = {'effects': ['modify', 'flow', 'message'],
            'modify': {'response': {'replace': True, 'merge': False}}, 'flow': {'operations': ['stop']}}
        return req

    def test_model_response_interception_and_effective_items(self):
        req = self.model_request()
        item = {'id': 'output', 'kind': 'message', 'mediaType': 'text/plain', 'selection': 'metadata', 'role': 'assistant'}
        reply = response([{'type': 'modify', 'target': 'response', 'operation': 'replace', 'value': [item]},
                          {'type': 'flow', 'operation': 'stop', 'reason': 'budget'}])
        actual = apply_response(req, reply, self.validator)
        self.assertEqual(actual['event']['items'], [item])
        self.assertEqual(actual['event']['attempt'], req['params']['event']['attempt'])
        self.assertEqual(actual['flow'], 'stop')
        self.assertFalse(actual['executed'])
        supplied = deepcopy(req)
        supplied['params']['event']['execution'] = {'status': 'skipped', 'reason': 'supplied_result'}
        self.validator.validate('intercept-request', supplied)
        del reply['result']['effects'][0]['value'][0]['role']
        with self.assertRaises(ProtocolError): apply_response(req, reply, self.validator)

    def test_synthesized_markers_are_preserved_and_typed(self):
        req = request()
        req['params']['event']['synthesized'] = True
        for field in ('call', 'session'):
            req['params']['event'][field]['synthesized'] = True
        self.assertEqual(self.validator.validate('intercept-request', req), req)
        req['params']['event']['call']['synthesized'] = 'true'
        with self.assertRaises(ProtocolError): self.validator.validate('intercept-request', req)

    def test_sha256_requires_exact_lowercase_hex(self):
        reference = {'ref': 'binary', 'size': 0, 'sha256': 'a' * 64}
        self.validator.validate('content-reference', reference)
        for digest in ('a'*63, 'a'*65, 'A'*64, 'a'*64+'\n', 'a'*63+'\r', 'z'*64):
            with self.subTest(digest=repr(digest)):
                with self.assertRaises(ProtocolError): self.validator.validate('content-reference', {**reference, 'sha256': digest})

    def test_model_visible_children_require_explicit_role(self):
        req = self.model_request()
        child = {'id': 'child', 'kind': 'reasoning', 'mediaType': 'text/plain',
                 'selection': 'metadata', 'parentItemId': 'owner'}
        req['params']['event']['items'] = [child]
        with self.assertRaises(ProtocolError): self.validator.validate('intercept-request', req)
        child['role'] = 'assistant'
        self.validator.validate('intercept-request', req)
