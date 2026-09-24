import unittest
from threading import Event, Thread
from agent_hooks_protocol.compaction import run_compaction, compaction_capabilities


def modify(target, value):
    return {'type': 'modify', 'target': target, 'operation': 'replace', 'value': value}


class CompactionTests(unittest.TestCase):
    def test_callbacks_receive_effective_input_and_result(self):
        generated = []
        def edit(snapshot):
            snapshot['instructions'] = 'malicious snapshot mutation'
            return [modify('instructions', 'new')]
        def generate(instructions):
            generated.append(instructions)
            return 'generated:' + instructions
        def redact(snapshot):
            self.assertEqual(snapshot['instructions'], 'new')
            return [modify('summary', snapshot['bodies'][snapshot['summary']['ref']] + ':redacted')]
        def watch(snapshot):
            self.assertEqual(snapshot['bodies'][snapshot['summary']['ref']], 'generated:new:redacted')
            return []
        r = run_compaction('old', [('edit','fail-closed',edit)], [('redact','fail-closed',redact),('watch','fail-closed',watch)], generate=generate)
        self.assertEqual(generated, ['new'])
        self.assertTrue(r['applied'])
        self.assertEqual(r['failures'], [])
        self.assertEqual(len(r['bodies']), 2)
        self.assertEqual(r['seen'][1]['summary']['id'], r['summary']['id'])
        self.assertNotEqual(r['seen'][1]['summary']['ref'], r['summary']['ref'])

    def test_atomic_rollback_preserves_candidate(self):
        r = run_compaction('old', [('cache','fail-closed',lambda _: [{'type':'return','value':'cached'}]),
            ('bad','fail-open',lambda _: [modify('instructions','leak'),{'type':'message','text':'leak'},modify('summary','invalid')])],
            [('redact','fail-closed',lambda _: [modify('summary','safe')])],
            generate=lambda _: self.fail('supplied candidate must skip generator'))
        self.assertEqual(r['instructions'], 'old')
        self.assertEqual(r['messages'], [])
        self.assertEqual(r['bodies'][r['summary']['ref']], 'safe')
        self.assertEqual(r['provenance'], {'kind':'supplied','supplier':'cache'})
        self.assertTrue(r['applied'])

    def test_after_failure_prevents_delivery(self):
        r = run_compaction('old', after=[('bad','fail-closed',lambda _: [modify('summary','leak'), modify('instructions','wrong')])])
        self.assertFalse(r['applied'])
        self.assertNotIn('leak', r['bodies'].values())
        self.assertEqual(compaction_capabilities('after', True), {'effects': [], 'modify': {}})

class DetachedCompactionTests(unittest.TestCase):
    def test_blocked_observers_do_not_gate_settlement_or_downstream(self):
        entered, release, finished, settled, raised = (Event() for _ in range(5))
        output = {}
        def blocked(snapshot):
            output['snapshot'] = snapshot
            entered.set()
            release.wait()
            snapshot['bodies'].clear()
            snapshot['instructions'] = 'observer mutation'
            finished.set()
            return [modify('summary', 'forbidden')]
        def throwing(snapshot):
            raised.set()
            raise RuntimeError('observer failure')
        def host():
            r = run_compaction('base', after=[('slow','fail-closed',blocked), ('throw','fail-closed',throwing)], observe_only=True)
            output['result'] = r
            output['downstream'] = [r['bodies'][r['summary']['ref']]] if r['applied'] else []
            settled.set()
        worker = Thread(target=host, daemon=True)
        worker.start()
        try:
            self.assertTrue(entered.wait(5), 'observer did not start')
            self.assertTrue(settled.wait(5), 'blocked observer delayed settlement')
            self.assertFalse(finished.is_set())
            self.assertTrue(raised.wait(5), 'observers were serialized behind blocked callback')
            self.assertEqual(output['downstream'], ['summary:base'])
            self.assertTrue(output['snapshot']['applied'])
            self.assertEqual(output['snapshot']['capabilities'], {'effects': [], 'modify': {}})
            before = __import__('copy').deepcopy(output['result'])
        finally:
            release.set()
            worker.join(5)
        self.assertTrue(finished.wait(5))
        self.assertEqual(output['result'], before)
        self.assertEqual(output['result']['failures'], [])

    def test_unknown_effect_fields_types_and_operations_roll_back_response(self):
        invalid = [
            {'type': 'message', 'text': 'ignored', 'futureField': True},
            {'type': 'future-effect'},
            {'type': 'modify', 'target': 'instructions', 'operation': 'future-operation', 'value': 'bad'},
        ]
        for effect in invalid:
            with self.subTest(effect=effect):
                actual = run_compaction('original', [
                    ('cache', 'fail-closed', lambda _: [{'type': 'return', 'value': 'cached'}]),
                    ('invalid', 'fail-open', lambda _: [modify('instructions', 'leaked'),
                        {'type': 'message', 'text': 'leaked'}, effect]),
                ], generate=lambda _: self.fail('Accepted candidate must survive rejection'))
                self.assertTrue(actual['applied'])
                self.assertEqual(actual['instructions'], 'original')
                self.assertEqual(actual['messages'], [])
                self.assertEqual(actual['bodies'][actual['summary']['ref']], 'cached')
                self.assertEqual(actual['failures'], [{'boundary': 'before', 'supplier': 'invalid'}])


if __name__ == '__main__': unittest.main()
