from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from agent_hooks_protocol.catalogue import discovery, EXECUTION_EVENTS, CHANGE_EVENTS
from agent_hooks_protocol.lifecycle_client import run, Transport
from agent_hooks_protocol.lifecycle_server import Server
from agent_hooks_protocol.lineage import TaskLineage
from agent_hooks_protocol.registration import validate_registration
from agent_hooks_protocol.runtime import Validator, ProtocolError


def note(ident, *, kind='task.change.before', parent=None, task='work'):
    event = {'id': ident, 'source': 'urn:python:catalogue-test', 'time': '2026-01-01T00:00:00Z',
             'type': kind, 'task': {'id': task, 'operation': 'update', 'change': {'status': 'done'}}}
    if parent: event['parentEventId'] = parent
    return {'jsonrpc': '2.0', 'method': 'hooks/observe', 'params': {
        'protocolVersion': 'draft', 'event': event}}


def registration(mode='observe', event='task.change.before'):
    sub = {'mode': mode, 'events': [event], 'content': {'default': 'metadata'}}
    if mode == 'intercept': sub.update(timeoutMs=500, failurePolicy='fail-closed')
    return {'protocolVersion': 'draft', 'hooks': [{'id': 'org.example.python-catalogue',
        'transport': {'type': 'http', 'url': 'https://policy.example.invalid/events'}, 'subscriptions': [sub]}]}


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.validator = Validator()
        request = {'jsonrpc': '2.0', 'id': 'discover-native', 'method': 'hooks/capabilities',
                   'params': {'protocolVersion': 'draft'}}
        self.manifest = discovery(request, self.validator)['result']['manifest']
        self.context = {'interactive': True, 'environment': {}}

    def validate(self, value, requirements=None, context=None):
        return validate_registration(value, self.manifest, requirements or [], context or self.context, self.validator)

    def test_discovery_and_registration_enforceability(self):
        self.assertEqual({e['event'] for e in self.manifest['events']}, set(EXECUTION_EVENTS + CHANGE_EVENTS))
        self.assertTrue(self.validate(registration()))
        req = registration('intercept', 'tool.before')
        needs = [{'event': 'tool.before', 'mode': 'intercept', 'effects': ['modify'],
                  'modify': {'input': {'merge': True}}}]
        self.assertTrue(self.validate(req, needs))
        needs[0]['modify'] = {'workspace': {'replace': True}}
        with self.assertRaises(ProtocolError): self.validate(req, needs)
        with self.assertRaises(ProtocolError): self.validate(req, [{'event': 'tool.before', 'mode': 'intercept', 'effects': ['ask']}],
            {'interactive': False, 'environment': {}})
        for value in [registration('observe', 'hook.failure'), registration('intercept', 'task.change.after')]:
            with self.assertRaises(ProtocolError): self.validate(value)
        bad = deepcopy(req); bad['hooks'].append(deepcopy(bad['hooks'][0]))
        with self.assertRaises(ProtocolError): self.validate(bad)
        bad = deepcopy(req); bad['hooks'][0]['subscriptions'][0].update(scope='managed', disableable=False)
        with self.assertRaises(ProtocolError): self.validate(bad)
        bad = deepcopy(req); del bad['hooks'][0]['subscriptions'][0]['failurePolicy']
        with self.assertRaises(ProtocolError): self.validate(bad)
        bad = registration(); bad['hooks'][0]['subscriptions'][0]['timeoutMs'] = 500
        with self.assertRaises(ProtocolError): self.validate(bad)

    def test_credentials_are_trusted_host_inputs_not_manifest_identity(self):
        value = registration(); value['hooks'][0]['authentication'] = {'type': 'bearer', 'tokenEnv': 'PYTHON_TEST_TOKEN'}
        with self.assertRaises(ProtocolError): self.validate(value)
        self.assertTrue(self.validate(value, context={'interactive': True, 'environment': {'PYTHON_TEST_TOKEN': 'secret-test'}}))
        self.manifest['correlationIdentityFields'].append('principal.administrator')
        with self.assertRaises(ProtocolError): self.validate(value)
        value['hooks'][0]['authentication'] = {'type': 'bearer', 'tokenRef': 'host-secret'}
        with self.assertRaises(ProtocolError): self.validate(value)
        self.assertTrue(validate_registration(value, self.manifest, [], self.context, self.validator,
                                             resolve_credential=lambda ref: ref == 'host-secret'))

    def test_unknown_configuration_authentication_and_manifest_fields_are_ignored(self):
        value = registration()
        hook = value['hooks'][0]
        auth = {'type': 'bearer', 'tokenRef': 'host-secret'}
        hook['authentication'] = auth
        for obj in (value, hook, hook['transport'], hook['subscriptions'][0],
                    auth, self.manifest,
                    self.manifest['managedPolicy'], self.manifest['limits'],
                    self.manifest['events'][0], self.manifest['events'][0]['capabilities']):
            obj['futureField'] = {'arbitrary': [True, None, 7]}
        self.assertTrue(validate_registration(value, self.manifest, [], self.context, self.validator,
                                             resolve_credential=lambda ref: ref == 'host-secret'))
        auth['type'] = 'future-authentication'
        with self.assertRaises(ProtocolError):
            validate_registration(value, self.manifest, [], self.context, self.validator,
                                  resolve_credential=lambda _: True)

    def test_lineage_rejections_are_transactional_and_source_local(self):
        graph = TaskLineage(self.validator)
        before = note('before')['params']['event']; graph.accept(before)
        wrong = note('actual', kind='task.change.after', parent='before', task='wrong')['params']['event']
        with self.assertRaises(ProtocolError): graph.accept(wrong)
        self.assertNotIn((wrong['source'], wrong['id']), graph.parents)
        wrong['task']['id'] = 'work'; wrong['task']['change'] = {'status': 'blocked'}
        graph.accept(wrong)
        late = TaskLineage(self.validator)
        late.accept(note('child', kind='task.change.after', parent='parent')['params']['event'])
        parent = note('parent', task='other')['params']['event']
        with self.assertRaises(ProtocolError): late.accept(parent)
        self.assertNotIn((parent['source'], 'parent'), late.parents)
        parent['source'] = 'urn:another-source'; late.accept(parent)
        parent['source'] = before['source']; parent['task']['id'] = 'work'; late.accept(parent)

    def test_known_content_owner_role_and_late_owner_are_transactional(self):
        graph = TaskLineage(self.validator)
        owner = {'id': 'owner', 'kind': 'message', 'mediaType': 'text/plain',
                 'selection': 'metadata', 'role': 'assistant'}
        child = {**owner, 'id': 'child', 'kind': 'reasoning', 'parentItemId': 'owner'}
        first = note('with-child')['params']['event']; first['items'] = [child]
        graph.accept(first)  # A filtered/not-yet-delivered owner is not fabricated.
        late = note('with-owner')['params']['event']; late['items'] = [{**owner, 'role': 'user'}]
        with self.assertRaises(ProtocolError): graph.accept(late)
        self.assertNotIn((late['source'], late['id']), graph.parents)
        self.assertNotIn((late['source'], 'owner'), graph.roles)
        late['items'] = [owner]; graph.accept(late)
        other = note('other-source')['params']['event']; other['source'] = 'urn:python:other-source'
        other['items'] = [{**owner, 'role': 'user'}]; graph.accept(other)

    def test_wildcard_registration_uses_actual_event_modes(self):
        self.assertTrue(self.validate(registration('observe', 'model.*')))
        self.assertTrue(self.validate(registration('observe', '*')))
        with self.assertRaises(ProtocolError): self.validate(registration('intercept', 'model.*'))
        with self.assertRaises(ProtocolError): self.validate(registration('observe', 'unknown.*'))
        absent = registration(); del absent['hooks'][0]['subscriptions'][0]['content']
        with self.assertRaises(ProtocolError): self.validate(absent)

    def exercise_transport(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            messages = [note('before'), note('after', kind='task.change.after', parent='before'),
                        note('wrong', kind='task.change.after', parent='before', task='different'),
                        note('no-op', kind='task.change.after'), note('malformed'), note('healthy')]
            messages[3]['params']['event']['task']['prior'] = {'status': 'done'}
            del messages[4]['params']['event']['task']['operation']
            steps = [{'op': 'notify' if i in (0, 1, 5) else 'rawNotify', 'message': m} for i, m in enumerate(messages)]
            steps.append({'op': 'register', 'registration': registration(), 'requirements': [], 'context': self.context})
            scenarios = root / 'scenarios.json'
            scenarios.write_text(json.dumps({'version': 1, 'scenarios': [{'id': 'arbitrary-scenario-name', 'steps': steps}]}))
            server_config = {'suite': 'catalogue', 'transport': mode, 'auth': {'mode': 'none'},
                'scenarioFile': str(scenarios), 'readinessFile': str(root / 'ready.json')}
            server_path = root / 'server.json'; server_path.write_text(json.dumps(server_config))
            config = {**server_config, 'reportFile': str(root / 'report.json'), 'serverConfig': str(server_path),
                      'serverCommand': [sys.executable, '-m', 'agent_hooks_protocol.lifecycle_server']}
            server = None
            try:
                if mode == 'http':
                    server = Server(server_config)
                    config.update(controlEndpoint=server.listener(True), endpoint=server.listener(False))
                run(config)
                report = json.loads((root / 'report.json').read_text())
                self.assertEqual(report['results'][0]['actual'], {'sent': messages, 'registrations': [{'accepted': True}]})
                entries = report['receipts']['entries']
                self.assertEqual(entries[0]['kind'], 'discovery')
                self.assertEqual(entries[0]['response'], report['discovery'])
                self.assertEqual([e['message'] for e in entries if e['kind'] in ('observed', 'rejected')], messages)
                self.assertEqual([e['errorKind'] for e in entries if e['kind'] == 'rejected'], ['lineage', 'lineage', 'schema'])
                self.assertEqual(entries[-1]['eventId'], 'healthy')
            finally:
                if server:
                    server.stop()
                    for listener in server.listeners:
                        listener.shutdown(); listener.server_close()

    def test_http_catalogue_real_messages(self): self.exercise_transport('http')
    def test_stdio_catalogue_real_messages(self): self.exercise_transport('stdio')
    def test_unknown_suite_fails(self):
        with self.assertRaises(ProtocolError): Transport({'suite': 'unknown'})
        with self.assertRaises(ProtocolError): Server({'suite': 'unknown'})
