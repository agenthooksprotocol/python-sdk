"""Schema-owned typed settlement and fail-closed decoding regressions."""

from copy import deepcopy
from unittest import TestCase
from unittest.mock import patch

import anyio

from agenthooksprotocol import (
    Candidate,
    HookResult,
    SettlementDecodeError,
    _models as models,
)
from agenthooksprotocol.compaction import text_parts
from agenthooksprotocol._outcomes import decode_event
from agenthooksprotocol.runtime import ProtocolError
from test_typed_contract_regressions import Replies, hooks_for, tool_input


class ConsumerOutcomeTests(TestCase):
    def test_named_boundary_typed_event_and_ordered_canonical_responses(self):
        async def run():
            payload = tool_input()
            opaque = {"future": {"parts": None, "integer": 2**60 + 1}}
            payload.update(
                extensions={"org.example.future": deepcopy(opaque)},
                native=deepcopy(opaque),
            )
            payload["tool"]["input"] = deepcopy(opaque)
            injected = {
                "id": "injected",
                "role": "user",
                "parts": text_parts("context"),
            }
            replies = Replies(
                {
                    "effects": [
                        {"type": "message", "text": "first"},
                        {
                            "type": "inject",
                            "target": "context",
                            "operation": "append",
                            "deliverAt": "next_turn",
                            "value": [injected],
                        },
                    ],
                    "extensions": {"org.example.future": opaque},
                },
                {"effects": [{"type": "return", "value": None}]},
            )
            caps = {
                "effects": ["message", "inject", "return"],
                "inject": {"context": {"append": True, "deliverAt": ["next_turn"]}},
            }
            async with hooks_for("tool.before", caps, replies, count=2) as hooks:
                outcome = await hooks.tool_before(payload)
                self.assertIsInstance(outcome.event, models.ToolBeforeEvent)
                self.assertEqual(outcome.event.tool.input, opaque)
                self.assertEqual(outcome.event.native, opaque)
                self.assertEqual(
                    outcome.event.extensions, {"org.example.future": opaque}
                )
                self.assertIsInstance(
                    outcome.accepted_responses[0], models.ToolBeforeInterceptResponse
                )
                self.assertEqual(
                    outcome.accepted_responses[0].result.extensions,
                    {"org.example.future": opaque},
                )
                self.assertEqual(outcome.messages[0].text, "first")
                self.assertIsInstance(outcome.injections[0], models.InjectEffect)
                self.assertEqual(outcome.injections[0].deliver_at, "next_turn")
                self.assertIsInstance(
                    outcome.injections[0].value[0], models.CanonicalMessage
                )
                self.assertIsInstance(outcome.candidate, Candidate)
                self.assertIsNone(outcome.candidate.value)
                self.assertIsNotNone(outcome.candidate)
                self.assertIsNone(outcome.candidate.value)
                self.assertEqual(outcome.accepted_responses, replies.responses)
                deepcopy(dict(outcome.event))["tool"]["input"]["future"] = False
                self.assertEqual(outcome.event.tool.input, opaque)

        anyio.run(run)

    def test_invalid_final_decode_is_error_even_under_fail_open(self):
        async def run():
            replies = Replies({"effects": [{"type": "return", "value": {"ok": True}}]})
            async with hooks_for(
                "tool.before", {"effects": ["return"]}, replies
            ) as hooks:
                original = HookResult._decode_settlement
                calls = 0

                def corrupt_final(outcome):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        outcome.event["tool"].pop("name")
                    original(outcome)

                with patch.object(HookResult, "_decode_settlement", corrupt_final):
                    with self.assertRaises(SettlementDecodeError) as caught:
                        await hooks.tool_before(tool_input())
                self.assertEqual(
                    caught.exception.settlement.accepted_responses,
                    replies.responses,
                )
                self.assertNotIn("executed", caught.exception.settlement._state)
                self.assertIsNotNone(caught.exception.__cause__)

        anyio.run(run)

    def test_text_candidate_and_caller_values_remain_distinct(self):
        async def run():
            parts = text_parts("summary")
            replies = Replies({"effects": [{"type": "return", "value": parts}]})
            async with hooks_for(
                "context.compact.before", {"effects": ["return"]}, replies
            ) as hooks:
                outcome = await hooks.context_compact_before(
                    {
                        "instructions": text_parts("input"),
                        "trigger": "manual",
                        "items": [],
                    }
                )
                self.assertIsInstance(outcome.candidate, Candidate)
                self.assertIsInstance(outcome.candidate.value[0], models.TextBodyPart)
                self.assertEqual(outcome.candidate.value, parts)
                opaque = {"future": {"parts": None}}
                outcome._state["candidate"]["provenance"] = opaque
                self.assertEqual(outcome.candidate.provenance, opaque)
                # The raw reducer state stays inspectable; typed result views
                # distinguish no result from an explicitly supplied null.
                self.assertFalse(outcome.has_result)
                with self.assertRaises(KeyError):
                    _ = outcome.result
            replies = Replies({"effects": [{"type": "return", "value": None}]})
            async with hooks_for(
                "tool.before", {"effects": ["return"]}, replies
            ) as hooks:
                outcome = await hooks.tool_before(tool_input())
                outcome._state["result"] = None
                self.assertTrue(outcome.has_result)
                self.assertIsNone(outcome.result)

        anyio.run(run)

    def test_invalid_known_event_never_silently_falls_back(self):
        with self.assertRaises(ProtocolError):
            decode_event({"type": "tool.before", "id": "one"})
