"""Fixture host policy runs after public SDK settlement."""

import unittest

from test_interop import request, response
from agenthooksprotocol.interop import fixture_hooks, fixture_notify, host_outcome
from agenthooksprotocol.runtime import ProtocolError


class FixtureSettlementTests(unittest.TestCase):
    def settle(self, effects):
        req = request()
        req["params"]["event"]["tool"]["name"] = "task"
        req["params"]["state"] = {"permission": "allow", "candidate": None}
        pending = fixture_hooks(req).begin(req)
        self.assertTrue(pending.receive(response(effects)))
        return req, pending.accept()

    def test_changed_input_preserves_new_candidate_for_host_authorization(self):
        req, settled = self.settle(
            [
                {
                    "type": "modify",
                    "target": "input",
                    "operation": "merge",
                    "value": {"task": 2},
                },
                {"type": "return", "value": {"cached": 2}},
            ]
        )
        self.assertEqual(settled.state["permission"], "none")
        self.assertEqual(settled.state["candidate"]["value"], {"cached": 2})
        actual = host_outcome(req, settled, validate_input=True)
        self.assertEqual(actual["input"]["task"], 2)
        self.assertEqual(actual["result"], {"cached": 2})
        self.assertFalse(actual["executed"])

    def test_host_rejection_retains_sdk_effective_input_and_message(self):
        req, settled = self.settle(
            [
                {
                    "type": "modify",
                    "target": "input",
                    "operation": "merge",
                    "value": {"task": 0},
                },
                {"type": "message", "text": "accepted by SDK"},
            ]
        )
        actual = host_outcome(req, settled, validate_input=True)
        self.assertEqual(actual["input"]["task"], 0)
        self.assertEqual(actual["messages"], ["accepted by SDK"])
        self.assertTrue(actual["sdkAccepted"])
        self.assertFalse(actual["hostAccepted"])
        self.assertEqual(actual["rejectionLayer"], "host-input-schema")
        self.assertFalse(actual["executed"])
        self.assertNotIn("authorization", actual)

    def test_host_rejects_non_numeric_task_values_after_sdk_acceptance(self):
        for value in ("1", None, [], {}):
            with self.subTest(value=value):
                req, settled = self.settle(
                    [
                        {
                            "type": "modify",
                            "target": "input",
                            "operation": "merge",
                            "value": {"task": value},
                        },
                        {"type": "message", "text": "accepted by SDK"},
                    ]
                )
                actual = host_outcome(req, settled, validate_input=True)
                self.assertEqual(actual["input"]["task"], value)
                self.assertEqual(actual["messages"], ["accepted by SDK"])
                self.assertTrue(actual["sdkAccepted"])
                self.assertFalse(actual["hostAccepted"])
                self.assertEqual(actual["rejectionLayer"], "host-input-schema")
                self.assertFalse(actual["executed"])

    def test_notification_failure_is_diagnostic_and_preserves_settlement(self):
        req, settled = self.settle(
            [
                {
                    "type": "modify",
                    "target": "input",
                    "operation": "merge",
                    "value": {"task": 2},
                },
            ]
        )
        before = host_outcome(req, settled)
        note = {
            "jsonrpc": "2.0",
            "method": "hooks/observe",
            "params": {"protocolVersion": "draft", "event": settled.event},
        }

        def failed_observer(message):
            self.assertEqual(message, note)
            raise ProtocolError("observer acknowledgement")

        diagnostics = fixture_notify(note, failed_observer)
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["mode"], "observe")
        self.assertEqual(host_outcome(req, settled), before)

    def test_uncorrelated_response_has_no_host_outcome(self):
        with self.assertRaises(ProtocolError):
            host_outcome(request(), None)
