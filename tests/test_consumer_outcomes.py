"""Schema-owned typed settlement and fail-closed decoding regressions."""

from copy import deepcopy
from unittest import TestCase
from unittest.mock import patch

import anyio

from agenthooksprotocol import (
    Candidate,
    HookResult,
    Hooks,
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

    def test_settled_flow_keeps_inherited_instructions_and_remaining_budget(self):
        from agenthooksprotocol.state import Flow
        from agenthooksprotocol import Permission

        async def run():
            payload = {
                "turn": {"id": "turn-one"},
                "outcome": "completed",
                "continuationCount": 0,
                "items": [],
            }
            caps = {
                "effects": ["flow"],
                "flow": {
                    "operations": ["continue", "stop"],
                    "remainingContinuations": 2,
                    "continuationCount": 0,
                    "maxContinuations": 2,
                },
            }
            for operation in ("continue", "stop"):
                effect = {"type": "flow", "operation": operation}
                if operation == "continue":
                    effect["instruction"] = "new"
                else:
                    effect["reason"] = "finished"
                replies = Replies({"effects": [effect]})
                name = (
                    "turn.finish.before" if operation == "continue" else "tool.before"
                )
                operation_caps = (
                    caps
                    if operation == "continue"
                    else {
                        "effects": ["flow"],
                        "flow": {"operations": ["stop"], "remainingContinuations": 2},
                    }
                )
                async with hooks_for(name, operation_caps, replies) as hooks:
                    outcome = await hooks.dispatch(
                        name,
                        payload if operation == "continue" else tool_input(),
                        initial_state={
                            "permission": "none",
                            "candidate": None,
                            "flow": "continue",
                            "instructions": ["inherited"],
                        },
                    )
                self.assertIs(outcome.flow, Flow(operation))
                self.assertIs(outcome.permission, Permission.NONE)
                self.assertEqual(
                    outcome.instructions,
                    ["inherited", "new"] if operation == "continue" else ["inherited"],
                )
                self.assertEqual(
                    outcome.continuation_remaining, 1 if operation == "continue" else 2
                )
                self.assertEqual(
                    outcome.accepted_responses[0].result.effects[0], effect
                )
                outcome.instructions.append("detached")
                self.assertNotIn("detached", outcome.instructions)

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_initial_flow_state_without_responses_preserves_presence(self):
        from agenthooksprotocol.state import Flow

        async def run():
            for flow in (None, "none", "stop", "continue"):
                for instructions in (None, [], ["inherited"]):
                    for budget in (None, 0, 2):
                        caps = {
                            "effects": ["flow"],
                            "flow": {"operations": ["stop"]},
                        }
                        if budget is not None:
                            caps["flow"]["remainingContinuations"] = budget
                            caps["flow"]["continuationCount"] = 0
                            caps["flow"]["maxContinuations"] = budget
                        else:
                            caps["flow"]["operations"] = ["stop"]
                        initial = {"permission": "none", "candidate": None}
                        if flow is not None:
                            initial["flow"] = flow
                        if instructions is not None:
                            initial["instructions"] = instructions
                        async with Hooks(
                            {
                                "protocolVersion": "draft",
                                "hooks": [
                                    {
                                        "id": "org.example.observer",
                                        "transport": {
                                            "type": "http",
                                            "url": "https://receiver.invalid",
                                        },
                                        "subscriptions": [
                                            {
                                                "events": ["tool.before"],
                                                "mode": "observe",
                                                "content": {"default": "body"},
                                            }
                                        ],
                                    }
                                ],
                            },
                            source="urn:test:typed",
                            transport=Replies(),
                            capabilities={
                                "tool.before": {
                                    "modes": ["intercept", "observe"],
                                    "capabilities": caps,
                                }
                            },
                        ) as hooks:
                            outcome = await hooks.tool_before(
                                tool_input(), initial_state=initial
                            )
                        self.assertEqual(outcome.accepted_responses, [])
                        self.assertIs(
                            outcome.flow, None if flow is None else Flow(flow)
                        )
                        expected_instructions = instructions
                        if (
                            instructions is None
                            and flow in ("stop", "continue")
                            and budget is not None
                        ):
                            expected_instructions = []
                        self.assertEqual(outcome.instructions, expected_instructions)
                        self.assertEqual(outcome.continuation_remaining, budget)

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_invalid_later_flow_response_keeps_previous_settlement(self):
        from agenthooksprotocol.state import Flow

        async def run():
            caps = {
                "effects": ["flow"],
                "flow": {
                    "operations": ["continue"],
                    "remainingContinuations": 3,
                    "continuationCount": 0,
                    "maxContinuations": 3,
                },
            }
            replies = Replies(
                {
                    "effects": [
                        {
                            "type": "flow",
                            "operation": "continue",
                            "instruction": "accepted",
                        }
                    ]
                },
                {
                    "effects": [
                        {"type": "flow", "operation": "continue", "instruction": 42}
                    ]
                },
            )
            async with hooks_for("turn.finish.before", caps, replies, count=2) as hooks:
                outcome = await hooks.turn_finish_before(
                    {
                        "turn": {"id": "turn-one"},
                        "outcome": "completed",
                        "continuationCount": 0,
                        "items": [],
                    },
                    initial_state={
                        "permission": "none",
                        "candidate": None,
                        "instructions": ["inherited"],
                    },
                )
            self.assertIs(outcome.flow, Flow.CONTINUE)
            self.assertEqual(outcome.instructions, ["inherited", "accepted"])
            self.assertEqual(outcome.continuation_remaining, 2)
            self.assertEqual(len(outcome.accepted_responses), 1)
            self.assertTrue(outcome.diagnostics)
            self.assertEqual(
                replies.requests[1]["params"]["state"]["instructions"],
                ["inherited", "accepted"],
            )
            self.assertEqual(
                replies.requests[1]["params"]["capabilities"]["flow"][
                    "remainingContinuations"
                ],
                2,
            )

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_invalid_known_event_never_silently_falls_back(self):
        with self.assertRaises(ProtocolError):
            decode_event({"type": "tool.before", "id": "one"})
