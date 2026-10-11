"""Owned attachment regression coverage on both supported async backends."""

import hashlib
import unittest

import anyio

from agenthooksprotocol import Attachment
from agenthooksprotocol.content import OwnedAttachment
from agenthooksprotocol.event import ContextCompactBeforeInput
from agenthooksprotocol.runtime import ProtocolError
from test_owned_content_hooks import harness, payload, INSTRUCTIONS


def inline_input(owner, value=None):
    value = payload() if value is None else value
    value["items"][0]["parts"][0].pop("size", None)
    value["items"][0]["parts"][0].pop("selection", None)
    value["items"][0]["parts"][0]["body"] = OwnedAttachment(owner)
    return ContextCompactBeforeInput(**value)


class AttachmentTests(unittest.TestCase):
    def run_async(self, test):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(test, backend=backend)

    def test_unread_results_outlive_hooks_and_reject_reuse(self):
        async def run():
            for unmatched in (False, True):
                calls = []

                async def load():
                    calls.append("load")
                    return b"hello"

                async def close():
                    calls.append("close")

                attachment = Attachment.lazy(load, aclose=close)
                bound = inline_input(attachment)
                hooks, _ = harness(["metadata"], unmatched=unmatched)
                async with hooks:
                    result = await hooks.context_compact_before(bound)
                    self.assertEqual(calls, [])
                    with self.assertRaises(ProtocolError):
                        await hooks.context_compact_before(bound)
                async with result:
                    self.assertEqual(
                        await result.attachments.read(INSTRUCTIONS), b"hello"
                    )
                    self.assertEqual(
                        await result.attachments.read(INSTRUCTIONS), b"hello"
                    )
                    self.assertEqual(calls, ["load", "close"])
                with self.assertRaises(ProtocolError):
                    await result.attachments.read(INSTRUCTIONS)

        self.run_async(run)

    def test_rejected_reuse_closes_only_fresh_mixed_sources(self):
        from test_owned_content_hooks import Stream

        async def run():
            for constructed in (False, True):
                calls = []

                async def original_load():
                    calls.append("original load")
                    return b"hello"

                async def original_close():
                    calls.append("original close")

                async def fresh_load():
                    self.fail("rejected lazy attachment must remain unread")

                async def fresh_close():
                    calls.append("fresh close")

                original = Attachment.lazy(original_load, aclose=original_close)
                hooks, _ = harness(["metadata"])
                async with hooks:
                    result = await hooks.context_compact_before(inline_input(original))
                    fresh = Attachment.lazy(fresh_load, aclose=fresh_close)
                    stream = Stream()
                    ordinary = Attachment(stream)
                    value = payload()
                    part = value["items"][0]["parts"][0]
                    part.pop("selection", None)
                    part.pop("size", None)
                    value["items"] = [
                        {
                            "role": "user",
                            "parts": [
                                dict(part, id=str(index), body=OwnedAttachment(owner))
                            ],
                        }
                        for index, owner in enumerate(
                            (original, fresh, ordinary, fresh)
                        )
                    ]
                    value = ContextCompactBeforeInput(**value) if constructed else value
                    with self.assertRaisesRegex(ProtocolError, "already transferred"):
                        await hooks.context_compact_before(value)
                    self.assertEqual(calls, ["fresh close"])
                    self.assertEqual((stream.reads, stream.closes), (0, 1))
                    self.assertTrue(fresh._closed)
                    self.assertTrue(ordinary._closed)
                    self.assertFalse(original._closed)
                async with result:
                    self.assertEqual(
                        await result.attachments.read(INSTRUCTIONS), b"hello"
                    )
                self.assertEqual(
                    calls, ["fresh close", "original load", "original close"]
                )

        self.run_async(run)

    def test_multiple_consumers_share_original_and_eager_bytes(self):
        async def run():
            for eager in (True, False):
                calls = []

                async def load():
                    calls.append("load")
                    return b"hello"

                attachment = (
                    Attachment.from_bytes(b"hello") if eager else Attachment.lazy(load)
                )
                bound = inline_input(attachment)
                before = bound.to_wire()
                hooks, transports = harness(["body", "body"])
                writes = []

                async def upload(data):
                    self.assertIsInstance(data, bytes)
                    writes.append(data)
                    return {
                        "ref": f"urn:attachment:{len(writes)}",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }

                async with hooks:
                    result = await hooks.context_compact_before(
                        bound, uploads={name: upload for name in transports}
                    )
                self.assertEqual(result.diagnostics, [])
                self.assertEqual(writes, [b"hello", b"hello"])
                self.assertEqual(calls, [] if eager else ["load"])
                self.assertEqual(bound.to_wire(), before)
                async with result:
                    data = await result.attachments.read(INSTRUCTIONS)
                    with self.assertRaises(TypeError):
                        data[0] = 0
                    self.assertEqual(
                        await result.attachments.read(INSTRUCTIONS), b"hello"
                    )

        self.run_async(run)

    def test_cleanup_unopened_rejected_and_failed(self):
        async def run():
            for rejected in (False, True):
                calls = []

                async def load():
                    self.fail("unopened source evaluated")

                async def close():
                    calls.append("close")

                bound = inline_input(Attachment.lazy(load, aclose=close))
                hooks, _ = harness(["metadata"])
                if rejected:
                    await hooks.aclose()
                    with self.assertRaises(Exception):
                        await hooks.context_compact_before(bound)
                else:
                    async with hooks:
                        result = await hooks.context_compact_before(bound)
                    await result.aclose()
                    await result.aclose()
                self.assertEqual(calls, ["close"])
            for mode in ("limit", "error", "timeout", "cancel"):
                calls = []

                async def load():
                    calls.append("load")
                    if mode == "error":
                        raise ValueError("failed")
                    if mode in ("timeout", "cancel"):
                        await anyio.sleep_forever()
                    return b"oversize"

                async def close():
                    calls.append("close")

                attachment = Attachment.lazy(
                    load, aclose=close, max_bytes=1, timeout=0.01
                )
                if mode == "cancel":
                    with anyio.move_on_after(0.001):
                        await attachment.snapshot()
                else:
                    with self.assertRaises((ValueError, ProtocolError, TimeoutError)):
                        await attachment.snapshot()
                self.assertIsNotNone(attachment._error)
                with self.assertRaises(type(attachment._error)) as repeated:
                    await attachment.snapshot()
                self.assertIs(repeated.exception, attachment._error)
                await attachment.aclose()
                self.assertEqual(calls, ["load", "close"])

        self.run_async(run)

    def test_reject_unrelated_reference_and_metadata_mismatch(self):
        async def run():
            value = payload()
            value["items"][0]["parts"][0].pop("size")
            value["items"][0]["parts"][0].update(
                selection="body", body={"ref": "urn:other"}
            )
            hooks, _ = harness(["metadata"])
            async with hooks:
                result = await hooks.context_compact_before(
                    ContextCompactBeforeInput(**value)
                )
                async with result:
                    with self.assertRaises(KeyError):
                        await result.attachments.read(INSTRUCTIONS)
            value = payload()
            value["items"][0]["parts"][0]["size"] = 9
            attachment = Attachment.from_bytes(b"hello")
            hooks, _ = harness(["metadata"])
            async with hooks:
                result = await hooks.context_compact_before(
                    inline_input(attachment, value)
                )
            async with result:
                result.attachments._metadata[INSTRUCTIONS] = {"size": 9}
                with self.assertRaises(ProtocolError):
                    await result.attachments.read(INSTRUCTIONS)

        self.run_async(run)

    def test_hooks_close_joins_cancelled_attachment_cleanup(self):
        async def run():
            started = anyio.Event()
            closed = []

            async def load():
                return b"hello"

            async def close():
                await anyio.sleep(0.02)
                closed.append(True)

            hooks, transports = harness(["metadata"])

            async def request(_request):
                started.set()
                await anyio.sleep_forever()

            for transport in transports.values():
                transport.request = request
            bound = inline_input(Attachment.lazy(load, aclose=close))

            async def dispatch():
                from agenthooksprotocol import OperationCancelledError

                try:
                    await hooks.context_compact_before(bound)
                except OperationCancelledError:
                    pass

            async with anyio.create_task_group() as group:
                group.start_soon(dispatch)
                await started.wait()
                await hooks.aclose()
                self.assertEqual(closed, [True])

        self.run_async(run)

    def test_upload_and_result_share_the_same_owner_and_bytes(self):
        async def run():
            for eager in (False, True):
                data = bytes(bytearray(b"x" * 131073))
                calls = []

                async def load():
                    calls.append("load")
                    return data

                attachment = (
                    Attachment.from_bytes(data) if eager else Attachment.lazy(load)
                )
                value = payload()
                value["items"][0]["parts"][0]["size"] = len(data)
                bound = inline_input(attachment, value)
                uploads = []

                async def upload(body):
                    self.assertIs(body, data)
                    uploads.append(body)
                    return {
                        "ref": f"urn:direct:{len(uploads)}",
                        "size": len(body),
                        "sha256": hashlib.sha256(body).hexdigest(),
                    }

                hooks, transports = harness(["body", "body"])
                async with hooks:
                    result = await hooks.context_compact_before(
                        bound, uploads={name: upload for name in transports}
                    )
                self.assertEqual(result.diagnostics, [])
                self.assertEqual(len(uploads), 2)
                self.assertEqual(calls, [] if eager else ["load"])
                async with result:
                    self.assertIs(
                        result.attachments._bindings[INSTRUCTIONS], attachment
                    )
                    self.assertIs(await result.attachments.read(INSTRUCTIONS), data)
                    self.assertIs(attachment._snapshot, data)

        self.run_async(run)

    def test_existing_text_edits_preserve_binary_owner_without_store(self):
        from test_public_content import Replies, hooks_for, modify

        async def run():
            caps = {
                "effects": ["modify"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            reviewed = [
                {
                    "id": "reviewed",
                    "kind": "text",
                    "mediaType": "text/plain",
                    "selection": "body",
                    "text": "reviewed",
                }
            ]
            transport = Replies([modify("instructions", reviewed)], [])
            hooks = hooks_for("context.compact.before", caps, transport, count=2)
            owner = Attachment.from_bytes(b"hello", max_bytes=32)
            value = payload()
            value["instructions"] = [
                {
                    "id": "old",
                    "kind": "text",
                    "mediaType": "text/plain",
                    "selection": "body",
                    "text": "old",
                }
            ]
            writes = []

            async def upload(data):
                writes.append(data)
                return {
                    "ref": f"urn:direct:{len(writes)}",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with hooks:
                result = await hooks.context_compact_before(
                    inline_input(owner, value), uploads={"org.example.content": upload}
                )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(result.event["instructions"], reviewed)
            self.assertEqual(writes, [b"hello", b"hello"])
            async with result:
                self.assertIs(result.attachments._bindings[INSTRUCTIONS], owner)
                self.assertIs(await result.attachments.read(INSTRUCTIONS), writes[0])
                self.assertIs(writes[0], writes[1])
                self.assertEqual(owner.max_bytes, 32)
            self.assertTrue(owner._closed)

        self.run_async(run)

    def test_existing_json_return_uses_inline_complete_json_without_store(self):
        import json
        from unittest.mock import patch
        from test_public_content import Replies, hooks_for

        async def run():
            request = {
                "mode": "form",
                "message": "Answer",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                },
            }
            value = {
                "elicitation": {
                    "mode": "form",
                    "server": "example",
                    "request": {
                        "id": "question",
                        "kind": "text",
                        "mediaType": "text/plain",
                        "selection": "body",
                        "text": json.dumps(request),
                    },
                }
            }
            caps = {"effects": ["return"], "elicitation": {"form": {}}}
            answer = {"action": "accept", "content": {"ok": True}}
            first = {"action": "accept", "content": {"ok": False}}
            hooks = hooks_for(
                "user.elicitation.request",
                caps,
                Replies(
                    [{"type": "return", "value": first}],
                    [{"type": "return", "value": answer}],
                ),
                count=2,
            )

            async def upload(data):
                self.fail("inline JSON must never upload")

            with patch.object(
                Attachment,
                "from_bytes",
                side_effect=AssertionError("inline JSON must never own bytes"),
            ):
                async with hooks:
                    result = await hooks.user_elicitation_request(
                        value, uploads={"org.example.content": upload}
                    )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(result.candidate, {"value": answer})
            self.assertEqual(result.attachments._bindings, {})
            self.assertEqual(
                json.loads(result.event["elicitation"]["request"]["text"]), request
            )
            await result.aclose()

        self.run_async(run)

    def test_invalid_text_replacement_preserves_original_binary_owner(self):
        from test_public_content import Replies, hooks_for, modify

        async def run():
            caps = {
                "effects": ["modify"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            hooks = hooks_for(
                "context.compact.before",
                caps,
                Replies(
                    [
                        modify(
                            "instructions",
                            [
                                {
                                    "id": "invalid",
                                    "kind": "attachment",
                                    "mediaType": "application/pdf",
                                    "selection": "metadata",
                                }
                            ],
                        )
                    ]
                ),
            )
            owner = Attachment.from_bytes(b"hello", max_bytes=5)
            writes = []

            async def upload(data):
                writes.append(data)
                return {
                    "ref": "urn:direct:original",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with hooks:
                result = await hooks.context_compact_before(
                    inline_input(owner), uploads={"org.example.content": upload}
                )
            self.assertEqual(result.decision, "deny")
            self.assertEqual(len(result.diagnostics), 1)
            self.assertEqual(writes, [b"hello"])
            async with result:
                self.assertIs(result.attachments._bindings[INSTRUCTIONS], owner)
                self.assertEqual(await result.attachments.read(INSTRUCTIONS), b"hello")

        self.run_async(run)

    def test_existing_json_modify_reads_inline_correlation_and_complete_answer(self):
        import json
        from unittest.mock import patch
        from agenthooksprotocol import ContentContext
        from agenthooksprotocol.event import UserElicitationRequestInput
        from test_public_content import Replies, hooks_for, modify, wire

        async def run():
            question = {
                "mode": "form",
                "message": "Answer",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                },
            }
            request = UserElicitationRequestInput(
                elicitation={
                    "mode": "form",
                    "server": "example",
                    "request": {
                        "id": "question",
                        "kind": "text",
                        "mediaType": "text/plain",
                        "selection": "body",
                        "text": json.dumps(question),
                    },
                }
            ).to_wire()
            request_caps = {"effects": ["return"], "elicitation": {"form": {}}}
            original = wire(
                "user.elicitation.request", "original", request, request_caps
            )
            answer = {"action": "accept", "content": {"ok": False}}
            changed = {"action": "accept", "content": {"ok": True}}
            value = {
                "parentEventId": "original",
                "session": {"id": "session"},
                "elicitation": {
                    "mode": "form",
                    "server": "example",
                    "action": "accept",
                    "result": {
                        "id": "answer",
                        "kind": "text",
                        "mediaType": "text/plain",
                        "selection": "body",
                        "text": json.dumps(answer),
                    },
                },
            }
            caps = {
                "effects": ["modify"],
                "modify": {"content": {"replace": True, "merge": True}},
                "elicitation": {"form": {}},
            }
            hooks = hooks_for(
                "user.elicitation.result",
                caps,
                Replies([modify("content", changed["content"])]),
            )

            async def upload(data):
                self.fail("inline JSON must never upload")

            context = ContentContext(
                bindings={"content": ("elicitation", "result")},
                principal="org.example.content",
                original_request=original,
            )
            with patch.object(
                Attachment,
                "from_bytes",
                side_effect=AssertionError("inline JSON must never own bytes"),
            ):
                async with hooks:
                    result = await hooks.user_elicitation_result(
                        value, content=context, uploads={"org.example.content": upload}
                    )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(
                json.loads(result.event["elicitation"]["result"]["text"]), changed
            )
            self.assertEqual(result.attachments._bindings, {})
            await result.aclose()

        self.run_async(run)

    def test_unpublished_binary_owners_are_retired(self):
        from contextlib import nullcontext
        from unittest.mock import patch
        from agenthooksprotocol import OperationCancelledError
        from agenthooksprotocol.lifecycle import Lifecycle

        async def run():
            for failure in ("upload", "receipt", "cancel", "late"):
                owner = Attachment.from_bytes(b"hello")
                hooks, transports = harness(["body"])

                async def upload(data):
                    if failure == "upload":
                        raise ValueError("upload failed")
                    if failure == "cancel":
                        await anyio.sleep_forever()
                    return {
                        "ref": "urn:direct:failed",
                        "size": len(data),
                        "sha256": "0" * 64
                        if failure == "receipt"
                        else hashlib.sha256(data).hexdigest(),
                    }

                late = (
                    patch.object(Lifecycle, "commit_accept", return_value=None)
                    if failure == "late"
                    else nullcontext()
                )
                with late:
                    async with hooks:
                        try:
                            with anyio.move_on_after(0.1) as scope:
                                result = await hooks.context_compact_before(
                                    inline_input(owner),
                                    uploads={name: upload for name in transports},
                                )
                            if not scope.cancel_called:
                                await result.aclose()
                        except OperationCancelledError:
                            self.assertEqual(failure, "late")
                self.assertTrue(owner._closed)
                self.assertIsNone(owner._snapshot)

        self.run_async(run)

    def test_effective_result_owner_cannot_be_transferred_twice(self):
        async def run():
            owner = Attachment.from_bytes(b"hello")
            hooks, _ = harness(["metadata"])
            async with hooks:
                result = await hooks.context_compact_before(inline_input(owner))
                effective = result.attachments._bindings[INSTRUCTIONS]
                self.assertIs(effective, owner)
                self.assertTrue(effective._claimed)
                with self.assertRaisesRegex(ProtocolError, "already transferred"):
                    await hooks.context_compact_before(inline_input(effective))
            async with result:
                self.assertEqual(await result.attachments.read(INSTRUCTIONS), b"hello")

        self.run_async(run)

    def test_replaced_and_removed_owners_close_before_next_serial_receiver(self):
        from agenthooksprotocol.event import ModelRequestBeforeInput
        from test_public_content import Replies, hooks_for, modify

        async def run():
            for replacement in (
                [],
                [
                    {
                        "id": "replacement",
                        "role": "user",
                        "parts": [
                            {
                                "id": "text",
                                "kind": "text",
                                "mediaType": "text/plain",
                                "selection": "body",
                                "text": "reviewed",
                            }
                        ],
                    }
                ],
            ):
                owner = Attachment.from_bytes(b"hello")
                caps = {
                    "effects": ["modify"],
                    "modify": {"request": {"replace": True, "merge": False}},
                }
                replies = Replies([modify("request", replacement)], [])
                original = replies.request

                async def request(value):
                    if replies.requests:
                        self.assertTrue(owner._closed)
                        self.assertIsNone(owner._snapshot)
                    return await original(value)

                replies.request = request
                hooks = hooks_for("model.request.before", caps, replies, count=2)

                async def upload(data):
                    return {
                        "ref": "urn:direct:original",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }

                async with hooks:
                    value = ModelRequestBeforeInput(
                        items=[
                            {
                                "role": "user",
                                "parts": [
                                    {
                                        "kind": "attachment",
                                        "mediaType": "application/pdf",
                                        "body": OwnedAttachment(owner),
                                    }
                                ],
                            }
                        ],
                        attempt={"id": "attempt", "number": 1},
                        model={"id": "model", "provider": "example"},
                        params={},
                    )
                    result = await hooks.model_request_before(
                        value, uploads={"org.example.content": upload}
                    )
                self.assertEqual(result.diagnostics, [])
                self.assertEqual(result.event["items"], replacement)
                self.assertTrue(owner._closed)
                self.assertEqual(result.attachments._bindings, {})
                await result.aclose()

        self.run_async(run)

    def test_constructor_bounds_and_immutable_input(self):
        with self.assertRaises(TypeError):
            Attachment.from_bytes(bytearray(b"hello"))
        with self.assertRaises(ValueError):
            Attachment.from_bytes(b"hello", max_bytes=1)
