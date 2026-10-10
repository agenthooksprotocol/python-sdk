"""Direct host messages, private projections, and immutable attachment owners."""

from copy import deepcopy
import hashlib
import unittest

import anyio

from agenthooksprotocol import Attachment, Hooks
from agenthooksprotocol.event import ContextCompactBeforeInput
from agenthooksprotocol.runtime import ProtocolError


class Transport:
    def __init__(self, replies=()):
        self.requests = []
        self.replies = list(replies)

    async def request(self, request):
        self.requests.append(deepcopy(request))
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "draft",
                "effects": self.replies.pop(0) if self.replies else [],
            },
        }

    async def notify(self, request):
        self.requests.append(deepcopy(request))


def harness(
    selections,
    replies=(),
    *,
    timeout=1000,
    caps=None,
    unmatched=False,
    event="context.compact.before",
):
    names = [f"org.example.receiver{i}" for i in range(len(selections))]
    transports = {
        name: Transport(replies[i] if i < len(replies) else ())
        for i, name in enumerate(names)
    }
    config = {
        "protocolVersion": "draft",
        "hooks": [
            {
                "id": name,
                "transport": {"type": "http", "url": "https://receiver.invalid"},
                "subscriptions": [
                    {
                        "events": ["context.compact.after" if unmatched else event],
                        "mode": "intercept",
                        "timeoutMs": timeout,
                        "failurePolicy": "fail-closed",
                        "content": {"default": selection},
                    }
                ],
            }
            for name, selection in zip(names, selections)
        ],
    }
    capabilities = {
        name: {
            "modes": ["intercept"],
            "capabilities": (caps or {"effects": []})
            if name == event
            else {"effects": []},
        }
        for name in (event, "context.compact.after")
    }
    return Hooks(
        config, source="urn:test", capabilities=capabilities, transport=transports
    ), transports


def host(owner):
    return {
        "trigger": "manual",
        "items": [
            {
                "role": "user",
                "parts": [
                    {"kind": "text", "text": "hello"},
                    {
                        "kind": "attachment",
                        "mediaType": "application/pdf",
                        "body": owner,
                    },
                ],
            }
        ],
    }


def receipt(data, ref="urn:blob:one"):
    return {"ref": ref, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class InlineMessageTests(unittest.TestCase):
    def run_async(self, test):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(test, backend=backend)

    def test_direct_host_construction_shares_exact_owner_per_selected_backend(self):
        async def run():
            for typed in (False, True):
                calls, uploads = [], []
                data = b"binary attachment"

                async def load():
                    calls.append("read")
                    return data

                async def close():
                    calls.append("close")

                owner = Attachment.lazy(load, aclose=close)
                payload = host(owner)
                if typed:
                    payload = ContextCompactBeforeInput(**payload)
                    self.assertIs(next(iter(payload.content_sources.values())), owner)
                    self.assertIn("ahp:owned:pending", repr(payload.to_wire()))
                self.assertEqual(calls, [])
                hooks, transports = harness(["body", "metadata", "body"])

                def uploader(name):
                    async def upload(value):
                        self.assertIs(value, data)
                        self.assertIs(owner._snapshot, value)
                        uploads.append(name)
                        return receipt(value, "urn:blob:" + name)

                    return upload

                async with hooks:
                    result = await hooks.context_compact_before(
                        payload, uploads={name: uploader(name) for name in transports}
                    )
                    self.assertEqual(result.diagnostics, [])
                    with self.assertRaises(ProtocolError):
                        await hooks.context_compact_before(payload)
                self.assertEqual(calls, ["read", "close"])
                self.assertCountEqual(
                    uploads, ["org.example.receiver0", "org.example.receiver2"]
                )
                for index, transport in enumerate(transports.values()):
                    parts = transport.requests[0]["params"]["event"]["items"][0][
                        "parts"
                    ]
                    self.assertNotIn("ahp:owned:pending", repr(parts))
                    self.assertEqual(
                        parts[0].get("text"), None if index == 1 else "hello"
                    )
                    self.assertEqual("body" in parts[1], index != 1)
                self.assertNotIn("ahp:owned:pending", repr(result.event))
                slot = next(iter(result.attachments._bindings))
                self.assertIs(result.attachments._bindings[slot], owner)
                self.assertIs(await result.attachments.read(slot), data)
                await result.aclose()
                self.assertIsNone(owner._snapshot)

        self.run_async(run)

    def test_metadata_omit_unmatched_keep_unread_owner_after_shutdown(self):
        async def run():
            for selection, unmatched in (
                ("metadata", False),
                ("omit", False),
                ("body", True),
            ):
                calls = []

                async def load():
                    calls.append("read")
                    return b"x"

                async def close():
                    calls.append("close")

                owner = Attachment.lazy(load, aclose=close)
                hooks, _ = harness([selection], unmatched=unmatched)
                async with hooks:
                    result = await hooks.context_compact_before(host(owner))
                self.assertEqual(calls, [])
                await result.aclose()
                self.assertEqual(calls, ["close"])

        self.run_async(run)

    def test_timeout_bad_receipt_and_metadata_mismatch_never_publish(self):
        async def run():
            for failure in ("timeout", "receipt", "metadata", "limit"):
                closed = []

                async def load():
                    return b"bytes"

                async def close():
                    closed.append(True)

                owner = Attachment.lazy(
                    load, aclose=close, max_bytes=1 if failure == "limit" else 10
                )
                payload = host(owner)
                if failure == "metadata":
                    part = payload["items"][0]["parts"][1]
                    # Host body parts cannot assert receipt metadata.
                    part["size"] = 99
                    hooks, _ = harness(["body"])
                    async with hooks:
                        with self.assertRaises(ValueError):
                            await hooks.context_compact_before(payload)
                    self.assertEqual(closed, [True])
                    continue
                hooks, transports = harness(["body"], timeout=10)

                async def upload(data):
                    if failure == "timeout":
                        await anyio.sleep_forever()
                    return receipt(data) | {"size": 999}

                async with hooks:
                    result = await hooks.context_compact_before(
                        payload, uploads={next(iter(transports)): upload}
                    )
                    self.assertTrue(result.diagnostics)
                    self.assertFalse(next(iter(transports.values())).requests)
                await result.aclose()
                self.assertEqual(closed, [True])

        self.run_async(run)

    def test_projection_visits_only_schema_slots_and_preserves_hidden_parts_on_append(
        self,
    ):
        async def run():
            caps = {
                "effects": ["modify"],
                "modify": {"prompt": {"merge": True, "replace": True}},
            }
            appended = {
                "id": "new",
                "role": "assistant",
                "parts": [
                    {
                        "id": "new-text",
                        "kind": "text",
                        "mediaType": "text/plain",
                        "selection": "body",
                        "text": "new",
                    }
                ],
            }
            hooks, transports = harness(
                ["metadata", "body"],
                replies=(
                    [
                        [
                            {
                                "type": "modify",
                                "target": "prompt",
                                "operation": "merge",
                                "value": [appended],
                            }
                        ]
                    ],
                    [],
                ),
                caps=caps,
                event="turn.start",
            )
            payload = {
                "trigger": "manual",
                "items": [
                    {"role": "user", "parts": [{"kind": "text", "text": "private"}]}
                ],
            }
            opaque = {
                "id": "opaque",
                "kind": "text",
                "mediaType": "text/plain",
                "selection": "body",
                "text": "opaque",
            }
            payload["extensions"] = {"org.example.test": opaque}
            payload.update(trigger="user", turn={"id": "turn"})
            async with hooks:
                result = await hooks.turn_start(payload)
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(result.event["items"][0]["parts"][0]["text"], "private")
            self.assertEqual(result.event["extensions"]["org.example.test"], opaque)
            self.assertEqual(len(result.event["items"]), 2)
            second = list(transports.values())[1].requests[0]["params"]["event"]
            self.assertEqual(second["items"][0]["parts"][0]["text"], "private")

        self.run_async(run)

    def test_inline_instructions_replace_merge_and_atomic_invalid_batch(self):
        async def run():
            def text(id, value):
                return {
                    "id": id,
                    "kind": "text",
                    "mediaType": "text/plain",
                    "selection": "body",
                    "text": value,
                }

            caps = {
                "effects": ["modify", "return"],
                "modify": {"instructions": {"replace": True, "merge": True}},
            }
            effects = [
                {
                    "type": "modify",
                    "target": "instructions",
                    "operation": "replace",
                    "value": [text("b", "replace")],
                },
                {
                    "type": "modify",
                    "target": "instructions",
                    "operation": "merge",
                    "value": [text("c", "append")],
                },
                {"type": "return", "value": [text("s", "summary")]},
            ]
            hooks, _ = harness(["body"], replies=([effects],), caps=caps)
            async with hooks:
                result = await hooks.context_compact_before(
                    {
                        "trigger": "manual",
                        "items": [],
                        "instructions": [text("a", "start")],
                    }
                )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(
                [part["text"] for part in result.event["instructions"]],
                ["replace", "append"],
            )
            self.assertEqual(result.candidate["value"], [text("s", "summary")])
            hooks, _ = harness(
                ["body"],
                replies=(
                    [
                        effects
                        + [
                            {
                                "type": "modify",
                                "target": "instructions",
                                "operation": "replace",
                                "value": "bad",
                            }
                        ]
                    ],
                ),
                caps=caps,
            )
            async with hooks:
                rejected = await hooks.context_compact_before(
                    {
                        "trigger": "manual",
                        "items": [],
                        "instructions": [text("a", "start")],
                    }
                )
            self.assertTrue(rejected.diagnostics)
            self.assertEqual(rejected.event["instructions"], [text("a", "start")])

        self.run_async(run)

    def test_inline_elicitation_parses_json_without_source_or_upload(self):
        import json
        from agenthooksprotocol import ContentContext
        from agenthooksprotocol._content import PreparedContent
        from agenthooksprotocol.runtime import Validator, apply_response

        async def run():
            payload = {
                "mode": "form",
                "message": "Name?",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
            }

            def part(id, value):
                return {
                    "id": id,
                    "kind": "text",
                    "mediaType": "text/plain",
                    "selection": "body",
                    "text": json.dumps(value),
                }

            event = {
                "id": "request-event",
                "type": "user.elicitation.request",
                "source": "urn:test",
                "time": "2026-01-01T00:00:00Z",
                "elicitation": {
                    "server": "server",
                    "mode": "form",
                    "request": part("request-text", payload),
                },
            }
            request = {
                "jsonrpc": "2.0",
                "id": event["id"],
                "method": "hooks/intercept",
                "params": {
                    "protocolVersion": "draft",
                    "event": event,
                    "capabilities": {
                        "effects": ["return"],
                        "elicitation": {"form": {}},
                    },
                },
            }
            response = {
                "jsonrpc": "2.0",
                "id": event["id"],
                "result": {
                    "protocolVersion": "draft",
                    "effects": [
                        {
                            "type": "return",
                            "value": {"action": "accept", "content": {"name": "Ada"}},
                        }
                    ],
                },
            }
            validator = Validator()
            request_context = ContentContext(
                bindings={"request": ("elicitation", "request")},
                principal="org.example.receiver",
            )
            request_content = await request_context.prepare(request, validator)
            returned = apply_response(
                request,
                response,
                validator,
                content=request_content,
                include_staged=True,
            )
            self.assertEqual(returned["candidate"]["value"]["content"], {"name": "Ada"})
            result_event = deepcopy(event)
            result_event.update(
                id="result-event",
                type="user.elicitation.result",
                parentEventId=event["id"],
            )
            result_event["elicitation"] = {
                "server": "server",
                "mode": "form",
                "action": "accept",
                "result": part(
                    "result-text", {"action": "accept", "content": {"name": "Ada"}}
                ),
            }
            result_request = deepcopy(request)
            result_request["id"] = result_event["id"]
            result_request["params"]["event"] = result_event
            result_request["params"]["capabilities"] = {
                "effects": ["modify"],
                "modify": {"content": {"replace": True, "merge": True}},
                "elicitation": {"form": {}},
            }
            context = ContentContext(
                bindings={"content": ("elicitation", "result")},
                principal="org.example.receiver",
                original_request=request,
            )
            prepared = await context.prepare(result_request, validator)
            self.assertIsInstance(prepared, PreparedContent)
            response["id"] = result_event["id"]
            response["result"]["effects"] = [
                {
                    "type": "modify",
                    "target": "content",
                    "operation": "replace",
                    "value": {"name": "Grace"},
                }
            ]
            staged = apply_response(
                result_request,
                response,
                validator,
                content=prepared,
                include_staged=True,
            )
            final = await prepared.finalize(staged)
            self.assertEqual(
                json.loads(final["event"]["elicitation"]["result"]["text"])["content"],
                {"name": "Grace"},
            )
            self.assertEqual(prepared.contents(final["event"])._bindings, {})

        self.run_async(run)

    def test_outer_cancellation_closes_owner_before_return(self):
        async def run():
            calls = []

            async def load():
                calls.append("load")
                return b"x"

            async def close():
                await anyio.sleep(0)
                calls.append("close")

            owner = Attachment.lazy(load, aclose=close)
            hooks, transports = harness(["body"])

            async def upload(data):
                deadline.deadline = anyio.current_time()
                await anyio.sleep_forever()

            async with hooks:
                with self.assertRaises(TimeoutError):
                    with anyio.fail_after(10) as deadline:
                        await hooks.context_compact_before(
                            host(owner), uploads={next(iter(transports)): upload}
                        )
            self.assertEqual(calls, ["load", "close"])
            self.assertTrue(owner._closed)

        self.run_async(run)

    def test_invalid_raw_host_dispatch_closes_fresh_source_without_reading(self):
        async def run():
            calls = []

            async def load():
                self.fail("invalid host metadata must not read")

            async def close():
                calls.append("close")

            owner = Attachment.lazy(load, aclose=close)
            payload = host(owner)
            payload["items"][0]["parts"][1]["mediaType"] = "application/json"
            hooks, _ = harness(["body"])
            async with hooks:
                with self.assertRaises(ValueError):
                    await hooks.context_compact_before(payload)
            self.assertEqual(calls, ["close"])

        self.run_async(run)

    def test_replace_message_list_retires_removed_owner_before_next_receiver(self):
        async def run():
            calls = []

            async def load():
                calls.append("load")
                return b"early upload"

            async def close():
                calls.append("close")

            owner = Attachment.lazy(load, aclose=close)
            caps = {
                "effects": ["modify"],
                "modify": {"prompt": {"replace": True, "merge": True}},
            }
            effects = [
                {
                    "type": "modify",
                    "target": "prompt",
                    "operation": "replace",
                    "value": [],
                }
            ]
            hooks, transports = harness(
                ["metadata", "body"],
                replies=([effects], []),
                caps=caps,
                event="turn.start",
            )
            payload = host(owner)
            payload.update(trigger="user", turn={"id": "turn"})

            async def receipt_upload(data):
                calls.append("upload")
                return receipt(data)

            async with hooks:
                result = await hooks.turn_start(
                    payload, uploads={name: receipt_upload for name in transports}
                )
            self.assertEqual(calls, ["load", "close", "upload"])
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(result.event["items"], [])
            self.assertFalse(result.attachments._bindings)
            self.assertEqual(
                list(transports.values())[1].requests[0]["params"]["event"]["items"], []
            )

        self.run_async(run)

    def test_identical_metadata_replace_substitutes_instead_of_restoring_text(self):
        async def run():
            before = {
                "id": "message",
                "role": "user",
                "parts": [{"id": "text", "kind": "text", "text": "secret"}],
            }
            replacement = [
                {
                    "id": "message",
                    "role": "user",
                    "parts": [
                        {
                            "id": "text",
                            "kind": "text",
                            "mediaType": "text/plain",
                            "selection": "metadata",
                        }
                    ],
                }
            ]
            effects = [
                {
                    "type": "modify",
                    "target": "prompt",
                    "operation": "replace",
                    "value": replacement,
                }
            ]
            caps = {
                "effects": ["modify"],
                "modify": {"prompt": {"replace": True, "merge": True}},
            }
            hooks, transports = harness(
                ["metadata", "body"],
                replies=([effects], []),
                caps=caps,
                event="turn.start",
            )
            async with hooks:
                result = await hooks.turn_start(
                    {"items": [before], "trigger": "user", "turn": {"id": "turn"}}
                )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(result.event["items"], replacement)
            self.assertEqual(
                list(transports.values())[1].requests[0]["params"]["event"]["items"],
                replacement,
            )

        self.run_async(run)

    def test_inline_specialized_fields_are_normalized_and_projected_privately(self):
        async def run():
            from agenthooksprotocol import event

            input = event.ContextCompactBeforeInput(
                trigger="manual",
                items=[],
                instructions=[{"kind": "text", "text": "secret"}],
            )
            hooks, transports = harness(["metadata", "body"])
            async with hooks:
                result = await hooks.context_compact_before(input)
            self.assertEqual(result.diagnostics, [])
            original = result.event["instructions"][0]
            self.assertTrue(original["synthesized"])
            self.assertEqual(original["text"], "secret")
            first = list(transports.values())[0].requests[0]["params"]["event"][
                "instructions"
            ][0]
            second = list(transports.values())[1].requests[0]["params"]["event"][
                "instructions"
            ][0]
            self.assertEqual(first["id"], second["id"])
            self.assertNotIn("text", first)
            self.assertEqual(second["text"], "secret")

        self.run_async(run)

    def test_shared_owner_survives_removal_and_identity_based_reordering(self):
        async def run():
            calls = []

            async def load():
                calls.append("load")
                return b"binary"

            async def close():
                calls.append("close")

            owner = Attachment.lazy(load, aclose=close)
            messages = [
                {
                    "id": f"m{index}",
                    "role": "user",
                    "parts": [
                        {
                            "id": f"p{index}",
                            "kind": "attachment",
                            "mediaType": "application/pdf",
                            "body": owner,
                        }
                    ],
                }
                for index in range(2)
            ]
            retained = [
                {
                    "id": "m1",
                    "role": "user",
                    "parts": [
                        {
                            "id": "p1",
                            "kind": "attachment",
                            "mediaType": "application/pdf",
                            "selection": "metadata",
                        }
                    ],
                }
            ]
            caps = {
                "effects": ["modify"],
                "modify": {"prompt": {"replace": True, "merge": True}},
            }
            effects = [
                {
                    "type": "modify",
                    "target": "prompt",
                    "operation": "replace",
                    "value": retained,
                }
            ]
            hooks, transports = harness(
                ["metadata", "body"],
                replies=([effects], []),
                caps=caps,
                event="turn.start",
            )

            async def upload(data):
                self.assertIs(data, owner._snapshot)
                self.assertEqual(calls, ["load", "close"])
                return receipt(data)

            async with hooks:
                result = await hooks.turn_start(
                    {"trigger": "user", "turn": {"id": "turn"}, "items": messages},
                    uploads={name: upload for name in transports},
                )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(calls, ["load", "close"])
            self.assertEqual(len(result.attachments._bindings), 1)
            slot = next(iter(result.attachments._bindings))
            self.assertIs(result.attachments._bindings[slot], owner)
            self.assertEqual(await result.attachments.read(slot), b"binary")
            await result.aclose()

        self.run_async(run)

    def test_invalid_automatic_upload_binding_closes_unread_fresh_owner(self):
        async def run():
            calls = []

            async def load():
                self.fail("invalid upload configuration must not read")

            async def close():
                calls.append("close")

            owner = Attachment.lazy(load, aclose=close)
            hooks, _ = harness(["metadata"])
            async with hooks:
                with self.assertRaises(ValueError):
                    await hooks.context_compact_before(
                        host(owner), uploads={"org.example.receiver0": None}
                    )
            self.assertEqual(calls, ["close"])
            self.assertTrue(owner._closed)

        self.run_async(run)

    def test_tool_output_replacement_append_and_serial_delivery(self):
        async def run():
            def message(identity, text):
                return {
                    "id": identity,
                    "role": "tool",
                    "parts": [
                        {
                            "id": identity + "-part",
                            "kind": "text",
                            "mediaType": "text/plain",
                            "selection": "body",
                            "text": text,
                        }
                    ],
                }

            original, replacement, appended = (
                message("original", "old"),
                message("replacement", '{"ok":true}'),
                message("appended", "next"),
            )
            caps = {
                "effects": ["modify"],
                "modify": {"output": {"replace": True, "merge": True}},
            }
            replace = {
                "type": "modify",
                "target": "output",
                "operation": "replace",
                "value": [replacement],
            }
            merge = {
                "type": "modify",
                "target": "output",
                "operation": "merge",
                "value": [appended],
            }
            hooks, transports = harness(
                ["body", "body", "body"],
                replies=([[replace]], [[merge]], []),
                caps=caps,
                event="tool.after",
            )
            from agenthooksprotocol.event import ToolAfterInput

            payload = ToolAfterInput(
                call_id="call",
                name="read",
                input={},
                path="native",
                origin="native",
                execution={"status": "executed"},
                outcome="ok",
                items=[original],
            )
            async with hooks:
                result = await hooks.tool_after(payload)
            async with result:
                self.assertEqual(result.diagnostics, [])
                self.assertEqual(result.event["items"], [replacement, appended])
                requests = [
                    transport.requests[0]["params"]["event"]["items"]
                    for transport in transports.values()
                ]
                self.assertEqual(
                    requests, [[original], [replacement], [replacement, appended]]
                )
                self.assertNotIn("output", result.event["tool"])

        self.run_async(run)

    def test_direct_owner_malformed_schema_part_placement_closes_without_reading(self):
        async def run():
            for placement in ("text-body", "wrong-field", "metadata-body"):
                calls = []

                async def load():
                    self.fail("Malformed placement must not read the attachment")

                async def close():
                    calls.append("close")

                owner = Attachment.lazy(load, aclose=close)
                payload = host(owner)
                part = payload["items"][0]["parts"][1]
                self.assertIs(part["body"], owner)
                self.assertEqual(calls, [])
                if placement == "text-body":
                    part.update(kind="text", mediaType="text/plain", text="bad")
                elif placement == "wrong-field":
                    part["description"] = part.pop("body")
                else:
                    part["selection"] = "metadata"
                hooks, transports = harness(["body"])
                async with hooks:
                    with self.assertRaises((ValueError, ProtocolError)):
                        await hooks.context_compact_before(payload)
                self.assertEqual(calls, ["close"])
                self.assertTrue(owner._closed)
                self.assertTrue(
                    all(not transport.requests for transport in transports.values())
                )

        self.run_async(run)

    def test_direct_typed_and_dict_eager_lazy_owners_survive_unselected_shutdown(self):
        async def run():
            for typed in (False, True):
                for eager in (False, True):
                    for selection, unmatched in (
                        ("metadata", False),
                        ("omit", False),
                        ("body", True),
                    ):
                        calls = []
                        data = b"retained direct owner"

                        async def load():
                            calls.append("read")
                            return data

                        async def close():
                            calls.append("close")

                        owner = (
                            Attachment.from_bytes(data)
                            if eager
                            else Attachment.lazy(load, aclose=close)
                        )
                        payload = host(owner)
                        self.assertIs(payload["items"][0]["parts"][1]["body"], owner)
                        if typed:
                            payload = ContextCompactBeforeInput(**payload)
                            self.assertIs(
                                next(iter(payload.content_sources.values())), owner
                            )
                        self.assertEqual(calls, [])
                        hooks, _ = harness([selection], unmatched=unmatched)
                        async with hooks:
                            result = await hooks.context_compact_before(payload)
                        self.assertEqual(result.diagnostics, [])
                        self.assertEqual(calls, [])
                        slot = next(iter(result.attachments._bindings))
                        self.assertIs(result.attachments._bindings[slot], owner)
                        async with result:
                            self.assertIs(await result.attachments.read(slot), data)
                        self.assertEqual(calls, [] if eager else ["read", "close"])
                        self.assertTrue(owner._closed)

        self.run_async(run)

    def test_direct_typed_invalid_placement_cleanup_before_and_after_admission(self):
        async def run():
            for admitted in (False, True):
                calls = []

                async def load():
                    self.fail("Invalid typed content must not read")

                async def close():
                    calls.append("close")

                owner = Attachment.lazy(load, aclose=close)
                # Before dispatch, ownership is the constructor caller's.
                async with owner:
                    payload = host(owner)
                    if not admitted:
                        payload["items"][0]["parts"][1]["kind"] = "text"
                        with self.assertRaises(ValueError):
                            ContextCompactBeforeInput(**payload)
                        self.assertEqual(calls, [])
                    else:
                        payload = ContextCompactBeforeInput(**payload)
                        payload["items"][0]["parts"][1]["kind"] = "text"
                        hooks, transports = harness(["body"])
                        async with hooks:
                            with self.assertRaises(ProtocolError):
                                await hooks.context_compact_before(payload)
                        self.assertEqual(calls, ["close"])
                        self.assertTrue(
                            all(
                                not transport.requests
                                for transport in transports.values()
                            )
                        )
                self.assertEqual(calls, ["close"])
                self.assertTrue(owner._closed)

        self.run_async(run)
