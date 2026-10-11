"""Public façade regressions for generated contextual contracts.

Missing effects remains gated by the canonical bundle until regeneration.
No test substitutes a permissive validator for canonical admission.
"""

from copy import deepcopy
import unittest

import anyio

from agenthooksprotocol import Hooks
from agenthooksprotocol.compaction import compaction_capabilities, text_parts
from agenthooksprotocol.event import (
    ContextCompactBeforeInput,
    ContextCompactAfterInput,
    ModelRequestBeforeInput,
    WorkspaceChangeBeforeInput,
)
from agenthooksprotocol._models import InterceptResponse, TextBodyPart
from agenthooksprotocol.runtime import ProtocolError, Validator
from agenthooksprotocol.server.hooks import Handler, InterceptResult
from agenthooksprotocol.response import response_for_request


class Replies:
    def __init__(self, *results):
        self.results = list(results)
        self.requests = []
        self.responses = []

    async def request(self, request):
        self.requests.append(deepcopy(request))
        response = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"protocolVersion": "draft", **self.results.pop(0)},
        }
        self.responses.append(deepcopy(response))
        return response

    async def notify(self, request):
        pass


def hooks_for(name, caps, transport, count=1):
    return Hooks(
        {
            "protocolVersion": "draft",
            "hooks": [
                {
                    "id": "org.example.typed",
                    "transport": {"type": "http", "url": "https://receiver.invalid"},
                    "subscriptions": [
                        {
                            "events": [name],
                            "mode": "intercept",
                            "timeoutMs": 1000,
                            "failurePolicy": "fail-open",
                            "content": {"default": "body"},
                        }
                        for _ in range(count)
                    ],
                }
            ],
        },
        source="urn:test:typed",
        capabilities={name: {"modes": ["intercept"], "capabilities": caps}},
        transport=transport,
    )


def tool_input():
    return {
        "tool": {"name": "echo", "origin": "native", "input": {"n": 2**60 + 1}},
        "call": {"id": "call-one"},
        "path": "native",
    }


class TypedContractRegressions(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_effects_read_is_detached_plain_list_and_does_not_insert_absence(self):
        for result in (
            {"protocolVersion": "draft"},
            {"protocolVersion": "draft", "effects": []},
        ):
            response = {"jsonrpc": "2.0", "id": "neutral", "result": result}
            before = deepcopy(response)
            effects = response_for_request("tool.before", response)[
                "value"
            ].result.effects
            self.assertIs(type(effects), list)
            self.assertEqual(effects, [])
            effects.append({"type": "allow"})
            self.assertEqual(response, before)

    def test_explicit_empty_effects_neutral_state(self):
        async def run():
            transport = Replies({"effects": []})
            async with hooks_for("tool.before", {"effects": []}, transport) as hooks:
                result = await hooks.dispatch("tool.before", tool_input())
                self.assertEqual(len(result.accepted_responses), 1)
                self.assertEqual(result.input, tool_input()["tool"]["input"])
                self.assertIsNone(result.candidate)
                self.assertEqual(result.permission.value, "none")
                self.assertEqual(
                    response_for_request("tool.before", result.accepted_response)[
                        "value"
                    ].result.effects,
                    [],
                )

        self.run_async(run)

    def test_missing_effects_neutral_state(self):
        async def run():
            transport = Replies({})
            async with hooks_for("tool.before", {"effects": []}, transport) as hooks:
                result = await hooks.dispatch("tool.before", tool_input())
                self.assertEqual(len(result.accepted_responses), 1)
                self.assertEqual(result.input, tool_input()["tool"]["input"])
                self.assertIsNone(result.candidate)
                self.assertEqual(
                    response_for_request("tool.before", result.accepted_response)[
                        "value"
                    ].result.effects,
                    [],
                )
                self.assertNotIn("effects", result.accepted_response["result"])
                self.assertNotIn("effects", transport.responses[0]["result"])
                parsed = InterceptResponse.from_dict(result.accepted_response)
                self.assertEqual(
                    response_for_request("tool.before", parsed)["value"].result.effects,
                    [],
                )
                self.assertNotIn("effects", parsed.result)

        self.run_async(run)

    def test_backend_default_reply_is_neutral(self):
        async def run():
            transport = Replies({"effects": []})
            async with hooks_for("tool.before", {"effects": []}, transport) as hooks:
                await hooks.dispatch("tool.before", tool_input())
            request = transport.requests[0]
            before = deepcopy(request)

            async def intercept(message):
                return InterceptResult()

            response = await Handler(intercept=intercept).process(request)
            self.assertEqual(response["result"]["effects"], [])
            Validator().validate("intercept-response", response)
            self.assertEqual(request, before)

        self.run_async(run)

    def test_inline_compaction_instructions_and_summary_edits(self):
        async def run():
            for boundary, target in (("before", "instructions"), ("after", "summary")):
                name = "context.compact." + boundary
                original = text_parts("original", "original")
                replacement = [TextBodyPart(id="replacement", text="replacement")]
                opaque = {"parts": None, "body": {"ref": "opaque:not-an-attachment"}}
                payload = {target: original, "native": deepcopy(opaque)}
                if boundary == "before":
                    payload.update(trigger="manual", items=[])
                else:
                    payload.update(execution={"status": "executed"}, removed=[])
                transport = Replies(
                    {
                        "effects": [
                            {
                                "type": "modify",
                                "target": target,
                                "operation": "replace",
                                "value": replacement,
                            }
                        ]
                    }
                )
                before = deepcopy(payload)
                async with hooks_for(
                    name, compaction_capabilities(boundary), transport
                ) as hooks:
                    typed = (
                        ContextCompactBeforeInput
                        if boundary == "before"
                        else ContextCompactAfterInput
                    )(**payload)
                    result = await hooks.dispatch(name, typed)
                    self.assertEqual(
                        len(result.accepted_responses), 1, result.diagnostics
                    )
                    self.assertEqual(result.event[target], replacement)
                    self.assertNotIn("parts", result.event[target][0])
                    self.assertEqual(result.event["native"], opaque)
                self.assertEqual(payload, before)
                self.assertEqual(
                    transport.responses[0]["result"]["effects"][0]["value"], replacement
                )

        self.run_async(run)

    def test_message_edit_and_response_atomic_rollback(self):
        async def run():
            name = "turn.start"
            replacement = [
                {
                    "id": "accepted-message",
                    "role": "assistant",
                    "parts": text_parts("accepted", "accepted-part"),
                }
            ]
            transport = Replies(
                {
                    "effects": [
                        {
                            "type": "modify",
                            "target": "prompt",
                            "operation": "replace",
                            "value": replacement,
                        }
                    ]
                },
                {
                    "effects": [
                        {
                            "type": "modify",
                            "target": "prompt",
                            "operation": "replace",
                            "value": [
                                {
                                    "id": "rejected-message",
                                    "role": "user",
                                    "parts": text_parts(
                                        "must roll back", "rejected-part"
                                    ),
                                }
                            ],
                        },
                        {
                            "type": "modify",
                            "target": "prompt",
                            "operation": "replace",
                            "value": [{"kind": "text", "text": 42}],
                        },
                    ]
                },
            )
            caps = {
                "effects": ["modify"],
                "modify": {"prompt": {"replace": True, "merge": False}},
            }
            payload = {
                "trigger": "user",
                "items": [{"role": "user", "parts": text_parts("original")}],
                "turn": {"id": "turn-one"},
            }
            before = deepcopy(payload)
            async with hooks_for(name, caps, transport, count=2) as hooks:
                result = await hooks.dispatch(name, payload)
                self.assertEqual(len(result.accepted_responses), 1, result.diagnostics)
                self.assertEqual(result.event["items"], replacement)
                self.assertTrue(result.diagnostics)
                self.assertEqual(
                    transport.requests[1]["params"]["event"]["items"], replacement
                )
            self.assertEqual(payload, before)

        self.run_async(run)

    def test_workspace_edit_and_opaque_extension_forwarding(self):
        async def run():
            name = "workspace.change.before"
            opaque = {
                "parts": None,
                "effects": [{"type": "allow"}],
                "body": {"ref": "opaque"},
            }
            payload = WorkspaceChangeBeforeInput(
                workspace={"kind": "cwd", "change": {"cwd": "/before"}},
                extensions={"org.example.future": deepcopy(opaque)},
            )
            caps = {
                "effects": ["modify"],
                "modify": {"workspace": {"replace": True, "merge": True}},
            }
            transport = Replies(
                {
                    "effects": [
                        {
                            "type": "modify",
                            "target": "workspace",
                            "operation": "replace",
                            "value": {"cwd": "/after"},
                        }
                    ],
                    "extensions": {"org.example.future": deepcopy(opaque)},
                }
            )
            async with hooks_for(name, caps, transport) as hooks:
                result = await hooks.dispatch(name, payload)
                self.assertEqual(len(result.accepted_responses), 1, result.diagnostics)
                self.assertEqual(result.event["workspace"]["change"], {"cwd": "/after"})
                self.assertEqual(
                    result.event["extensions"]["org.example.future"], opaque
                )
                self.assertEqual(
                    result.accepted_response["result"]["extensions"][
                        "org.example.future"
                    ],
                    opaque,
                )
                self.assertEqual(payload["workspace"]["change"], {"cwd": "/before"})

        self.run_async(run)

    def test_model_return_candidate_preserves_known_messages(self):
        async def run():
            name = "model.request.before"
            messages = [
                {
                    "id": "model-message",
                    "role": "assistant",
                    "parts": text_parts("supplied", "model-part"),
                }
            ]
            transport = Replies({"effects": [{"type": "return", "value": messages}]})
            payload = ModelRequestBeforeInput(
                attempt={"id": "attempt-one", "number": 1},
                model={"id": "model-one", "provider": "example"},
                params={"unrecognized": {"parts": None}},
                items=[],
            )
            async with hooks_for(name, {"effects": ["return"]}, transport) as hooks:
                result = await hooks.dispatch(name, payload)
                self.assertEqual(len(result.accepted_responses), 1, result.diagnostics)
                self.assertEqual(result.candidate["value"], messages)
                self.assertEqual(result.event["params"], payload["params"])
                self.assertNotIn("parts", result.candidate["value"][0]["parts"][0])

        self.run_async(run)

    def test_form_answer_content_edit(self):
        from test_public_content import Store, elicitation
        import json

        async def run():
            original, response = elicitation(Store())
            original["params"]["event"]["source"] = "urn:test:typed"
            response["params"]["event"]["source"] = "urn:test:typed"
            transport = Replies(
                {
                    "effects": [
                        {
                            "type": "modify",
                            "target": "content",
                            "operation": "replace",
                            "value": {"ok": True},
                        }
                    ]
                }
            )
            name = "user.elicitation.result"
            async with hooks_for(
                name, response["params"]["capabilities"], transport
            ) as hooks:
                result = await hooks.dispatch(
                    name, response["params"]["event"], original_request=original
                )
                self.assertEqual(len(result.accepted_responses), 1, result.diagnostics)
                self.assertEqual(
                    json.loads(result.event["elicitation"]["result"]["text"]),
                    {"action": "accept", "content": {"ok": True}},
                )

        self.run_async(run)

    def test_elicit_result_return_preserves_known_payload_and_opaque_metadata(self):
        from test_public_content import Store, elicitation

        async def run():
            original, _ = elicitation(Store())
            original["params"]["event"]["source"] = "urn:test:typed"
            value = {
                "action": "accept",
                "content": {"ok": True},
                "_meta": {"future": {"parts": None}},
            }
            transport = Replies({"effects": [{"type": "return", "value": value}]})
            name = "user.elicitation.request"
            before = deepcopy(original)
            async with hooks_for(
                name, original["params"]["capabilities"], transport
            ) as hooks:
                result = await hooks.dispatch(name, original["params"]["event"])
                self.assertEqual(len(result.accepted_responses), 1, result.diagnostics)
                self.assertEqual(result.candidate["value"], value)
                self.assertEqual(result.content["candidate"], value)
            self.assertEqual(original, before)

        self.run_async(run)

    def test_null_effects_is_not_neutral_and_canonical_validation_is_retained(self):
        with self.assertRaises(ProtocolError):
            Validator().validate(
                "intercept-response",
                {
                    "jsonrpc": "2.0",
                    "id": "one",
                    "result": {"protocolVersion": "draft", "effects": None},
                },
            )
