"""Correlated generated contracts are consumed by the actual public runtime."""

from copy import deepcopy
import unittest

import anyio
from pydantic import BaseModel, Field, TypeAdapter, model_validator

from agenthooksprotocol import SessionCounters
from agenthooksprotocol.contract import Candidate, ElicitResult
from agenthooksprotocol.integrations.pydantic import PydanticFormContract
from agenthooksprotocol.runtime import ProtocolError, Validator, _apply_response
from agenthooksprotocol import _models
from test_typed_contract_regressions import Replies, hooks_for, tool_input


class CorrelatedCoreTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_real_request_event_state_and_candidate_have_generated_types(self):
        async def run():
            transport = Replies(
                {"effects": [{"type": "return", "value": {"result": 9}}]}
            )
            async with hooks_for(
                "tool.before", {"effects": ["return"]}, transport
            ) as hooks:
                result = await hooks.tool_before(tool_input())
                self.assertIsInstance(result.event, _models.ToolBeforeEvent)
                self.assertIsInstance(result.state["candidate"], _models.ToolCandidate)
                self.assertIsInstance(
                    result._contextual_response, _models.ToolBeforeInterceptResponse
                )
                self.assertIsInstance(result.decoded_candidate, Candidate)
                self.assertEqual(result.decoded_candidate.value, {"result": 9})

        self.run_async(run)

    def test_session_counters_are_exact_unbounded_nonnegative_in_full_sdk_decode(self):
        async def run():
            huge = 2**256 + 7
            payload = tool_input()
            payload["session"] = {
                "id": "session-one",
                "counters": {
                    "turns": huge,
                    "modelRequests": huge + 1,
                    "toolCalls": 0,
                    "inputTokens": huge + 2,
                    "outputTokens": huge + 3,
                    "vendorCounter": huge + 4,
                },
            }
            original = deepcopy(payload)
            transport = Replies({"effects": []})
            async with hooks_for("tool.before", {"effects": []}, transport) as hooks:
                result = await hooks.tool_before(payload)
                counters = result.event.session.counters
                self.assertIsInstance(counters, SessionCounters)
                self.assertIs(type(counters.turns), int)
                self.assertEqual(counters.turns, huge)
                self.assertEqual(counters["vendorCounter"], huge + 4)
                self.assertEqual(
                    transport.requests[0]["params"]["event"]["session"]["counters"],
                    original["session"]["counters"],
                )
            self.assertEqual(payload, original)

        self.run_async(run)
        for value in (-1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SessionCounters.from_dict({"vendorCounter": value})

    def test_known_wrong_payload_cannot_fall_back_to_opaque_response(self):
        async def run():
            name = "model.request.before"
            payload = {
                "attempt": {"id": "attempt-one", "number": 1},
                "model": {"id": "model", "provider": "example"},
                "params": {},
                "items": [],
            }
            transport = Replies(
                {
                    "effects": [
                        {"type": "return", "value": {"looksLikeToolResult": True}}
                    ]
                }
            )
            async with hooks_for(name, {"effects": ["return"]}, transport) as hooks:
                result = await hooks.model_request_before(payload)
                self.assertEqual(result.accepted_responses, [])
                self.assertIsNone(result.decoded_candidate)
                self.assertTrue(result.diagnostics)
            with self.assertRaises(ProtocolError):
                _apply_response(
                    transport.requests[0], transport.responses[0], Validator()
                )

        self.run_async(run)

    def test_opaque_application_lists_are_replaced_whole_without_identity_merging(self):
        async def run():
            payload = tool_input()
            payload["tool"]["input"] = {
                "opaque": [
                    {
                        "id": "same",
                        "hidden": 1,
                        "body": {"ref": "opaque:not-an-attachment"},
                    }
                ]
            }
            replacement = {"opaque": [{"id": "same", "other": 2}]}
            transport = Replies(
                {
                    "effects": [
                        {
                            "type": "modify",
                            "target": "input",
                            "operation": "replace",
                            "value": replacement,
                        }
                    ]
                }
            )
            caps = {
                "effects": ["modify"],
                "modify": {"input": {"replace": True, "merge": True}},
            }
            async with hooks_for("tool.before", caps, transport) as hooks:
                result = await hooks.tool_before(payload)
                self.assertEqual(result.input, replacement)
                self.assertEqual(result.event.tool.input, replacement)

        self.run_async(run)

    def test_result_boundary_form_invariant_is_checked_before_content_publication(self):
        from test_public_content import Store, elicitation
        import json

        class Answer(BaseModel):
            count: int = Field(ge=1, le=4)
            kept: bool

            @model_validator(mode="after")
            def invariant(self):
                if self.count == 3:
                    raise ValueError("Three is disallowed")
                return self

        async def run():
            form = PydanticFormContract(TypeAdapter(Answer))
            original, response = elicitation(Store())
            original["params"]["event"]["source"] = "urn:test:typed"
            response["params"]["event"]["source"] = "urn:test:typed"
            original["params"]["event"]["elicitation"]["request"]["text"] = json.dumps(
                form.request("Count")
            )
            response["params"]["event"]["elicitation"]["result"]["text"] = json.dumps(
                {"action": "accept", "content": {"count": 2, "kept": True}}
            )
            for counts, accepted in (
                ([4], True),
                ([3], False),
                ([3, 4], False),
                ([None, 4], False),
            ):
                count = counts[-1]
                transport = Replies(
                    {
                        "effects": [
                            {
                                "type": "modify",
                                "target": "content",
                                "operation": "merge",
                                "value": {"count": 1},
                            }
                        ]
                    },
                    {
                        "effects": [
                            {
                                "type": "modify",
                                "target": "content",
                                "operation": "merge",
                                "value": {"count": intermediate},
                            }
                            for intermediate in counts
                        ]
                    },
                )
                async with hooks_for(
                    "user.elicitation.result",
                    response["params"]["capabilities"],
                    transport,
                    count=2,
                ) as hooks:
                    result = await hooks.user_elicitation_result(
                        response["params"]["event"],
                        original_request=original,
                        result_codec=form.result_codec(),
                    )
                    self.assertEqual(
                        len(result.accepted_responses),
                        1 + int(accepted),
                        result.diagnostics,
                    )
                    body = json.loads(result.event.elicitation.result.text)
                    self.assertEqual(body["content"]["count"], count if accepted else 1)
                    self.assertTrue(body["content"]["kept"])

        self.run_async(run)

    def test_elicitation_atomic_adapter_serializes_exact_decimal_answers(self):
        import json
        import os
        from pathlib import Path
        import subprocess
        import sys
        from decimal import Decimal
        from test_public_content import Store, elicitation

        original, _ = elicitation(Store())
        original["params"]["event"]["elicitation"]["request"]["text"] = json.dumps(
            {
                "mode": "form",
                "message": "Score",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"score": {"type": "number"}},
                    "required": ["score"],
                },
            }
        )
        case = {
            "op": "apply",
            "request": original,
            "effects": [
                {
                    "type": "return",
                    "value": {"action": "accept", "content": {"score": 1.25}},
                }
            ],
        }
        from test_interop import ROOT

        schema = os.environ.get(
            "AHP_SCHEMA_DIR", str(ROOT / "agent-hooks-protocol/schema/draft")
        )
        self.assertTrue(
            (Path(schema) / "intercept-request.schema.json").is_file(),
            "Canonical schema fixture is missing: " + schema,
        )
        process = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "interop/elicitation.py"),
                "check",
                schema,
                "org.example.typed",
            ],
            input=json.dumps([case]),
            text=True,
            capture_output=True,
            env={**os.environ, "AHP_ELICITATION_TOKEN": "TEST-ONLY"},
            timeout=15,
        )
        self.assertEqual(process.returncode, 0, process.stderr[-1000:])
        output = json.loads(process.stdout, parse_float=Decimal)
        self.assertTrue(output[0]["accepted"], output)
        self.assertTrue(output[0]["inputUnchanged"])
        self.assertEqual(
            output[0]["summary"]["result"]["content"]["score"], Decimal("1.25")
        )

    def test_form_candidate_uses_generated_application_result_without_metadata_insertion(
        self,
    ):
        class Answer(BaseModel):
            ok: bool

        form = PydanticFormContract(TypeAdapter(Answer))
        codec = form.result_codec()
        value = {"action": "accept", "content": {"ok": True}}
        decoded = codec.decode(value)
        self.assertIsInstance(decoded, ElicitResult)
        self.assertIsInstance(decoded.content, Answer)
        self.assertNotIn("_meta", decoded.to_dict())
        self.assertEqual(codec.encode(decoded), value)
