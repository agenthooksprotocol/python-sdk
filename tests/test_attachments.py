"""Owned attachment regression coverage on both supported async backends."""

import hashlib
import unittest

import anyio

from agenthooksprotocol import Attachment
from agenthooksprotocol.event import ContextCompactBeforeInput
from agenthooksprotocol.runtime import ProtocolError
from test_owned_content_hooks import harness, payload, INSTRUCTIONS


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
                bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                    attachment
                )
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
        from agenthooksprotocol import ContentSources, OwnedContentSource
        from test_owned_content_hooks import Stream

        async def run():
            for explicit in (False, True):
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
                first = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                    original
                )
                hooks, _ = harness(["metadata"])
                async with hooks:
                    result = await hooks.context_compact_before(first)
                    fresh = Attachment.lazy(fresh_load, aclose=fresh_close)
                    stream = Stream()
                    ordinary = OwnedContentSource(stream)
                    value = payload()
                    item = dict(value["instructions"], role="user")
                    value["items"] = [dict(item, id=str(index)) for index in range(3)]
                    bindings = {
                        INSTRUCTIONS: original,
                        "context.compact.before.items[0]": fresh,
                        "context.compact.before.items[1]": ordinary,
                        # Aliased fresh resources must still be closed exactly once.
                        "context.compact.before.items[2]": fresh,
                    }
                    with self.assertRaisesRegex(ProtocolError, "already transferred"):
                        if explicit:
                            await hooks.context_compact_before(
                                value, sources=ContentSources(bindings)
                            )
                        else:
                            bound = ContextCompactBeforeInput(
                                **value
                            ).bind_instructions_source(original)
                            bound = bound.bind_items_source(fresh, index=0)
                            bound = bound.bind_items_source(ordinary, index=1)
                            bound = bound.bind_items_source(fresh, index=2)
                            await hooks.context_compact_before(bound)
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
                bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                    attachment
                )
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

                bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                    Attachment.lazy(load, aclose=close)
                )
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
                with self.assertRaises(ProtocolError):
                    await attachment.snapshot()
                await attachment.aclose()
                self.assertEqual(calls, ["load", "close"])

        self.run_async(run)

    def test_reject_unrelated_reference_and_metadata_mismatch(self):
        async def run():
            for existing in (True, False):
                value = payload()
                if existing:
                    value["instructions"].update(
                        selection="body", body={"ref": "urn:other"}
                    )
                    value["instructions"].pop("size")
                else:
                    value["instructions"]["size"] = 9
                attachment = Attachment.from_bytes(b"hello")
                bound = ContextCompactBeforeInput(**value).bind_instructions_source(
                    attachment
                )
                hooks, _ = harness(["metadata"])
                async with hooks:
                    if existing:
                        with self.assertRaises(ProtocolError):
                            await hooks.context_compact_before(bound)
                        self.assertTrue(attachment._closed)
                    else:
                        result = await hooks.context_compact_before(bound)
                        async with result:
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
            bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                Attachment.lazy(load, aclose=close)
            )

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
                value["instructions"]["size"] = len(data)
                bound = ContextCompactBeforeInput(**value).bind_instructions_source(
                    attachment
                )
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

    def test_existing_text_edits_replace_the_effective_owner_without_store(self):
        from test_public_content import Replies, hooks_for, modify

        async def run():
            caps = {
                "effects": ["modify"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            transport = Replies([modify("instructions", "reviewed")], [])
            hooks = hooks_for("context.compact.before", caps, transport, count=2)
            original = Attachment.from_bytes(b"hello", max_bytes=32)
            bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                original
            )
            uploads = []

            async def upload(body):
                uploads.append(body)
                return {
                    "ref": f"urn:direct:{len(uploads)}",
                    "size": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }

            async with hooks:
                result = await hooks.context_compact_before(
                    bound, uploads={"org.example.content": upload}
                )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(uploads, [b"hello", b"reviewed", b"reviewed"])
            self.assertTrue(original._closed)
            async with result:
                self.assertEqual(result.content["instructions"], "reviewed")
                self.assertIs(await result.attachments.read(INSTRUCTIONS), uploads[1])
                self.assertIs(uploads[1], uploads[2])
                self.assertEqual(
                    result.attachments._bindings[INSTRUCTIONS].max_bytes, 32
                )

        self.run_async(run)

    def test_existing_json_return_uses_effective_attachment_without_store(self):
        import json
        from unittest.mock import patch
        from agenthooksprotocol import ContentSources
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
            data = json.dumps(request).encode()
            # Use canonical generated slot metadata rather than a wire reference.
            from agenthooksprotocol._boundaries import CONTENT_SOURCE_SLOTS

            slot = next(
                name
                for name, value in CONTENT_SOURCE_SLOTS.items()
                if value == ("user.elicitation.request", ("elicitation", "request"))
            )
            owner = Attachment.from_bytes(data)
            value = {
                "elicitation": {
                    "mode": "form",
                    "server": "example",
                    "request": {
                        "id": "question",
                        "kind": "content",
                        "mediaType": "application/json",
                        "selection": "metadata",
                    },
                }
            }
            caps = {"effects": ["return"], "elicitation": {"form": {}}}
            answer = {"action": "accept", "content": {"ok": True}}
            first_answer = {"action": "accept", "content": {"ok": False}}
            transport = Replies(
                [{"type": "return", "value": first_answer}],
                [{"type": "return", "value": answer}],
            )
            hooks = hooks_for("user.elicitation.request", caps, transport, count=2)
            created = []
            real_from_bytes = Attachment.from_bytes

            def create(data, **kwargs):
                effective = real_from_bytes(data, **kwargs)
                created.append(effective)
                return effective

            uploads = []

            async def upload(body):
                uploads.append(body)
                return {
                    "ref": f"urn:direct:{len(uploads)}",
                    "size": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }

            with patch.object(Attachment, "from_bytes", side_effect=create):
                async with hooks:
                    result = await hooks.user_elicitation_request(
                        value,
                        sources=ContentSources({slot: owner}),
                        uploads={"org.example.content": upload},
                    )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(len(uploads), 4)
            self.assertEqual(len(created), 2)
            self.assertTrue(created[0]._closed)
            self.assertIsNone(created[0]._snapshot)
            self.assertFalse(created[1]._closed)
            async with result:
                self.assertIs(await result.attachments.read(slot), data)
                effective = await result.attachments.read("candidate")
                self.assertIs(effective, uploads[-1])
                self.assertEqual(json.loads(effective), answer)
            self.assertTrue(created[1]._closed)
            self.assertIsNone(created[1]._snapshot)

        self.run_async(run)

    def test_text_replacement_limit_preserves_original_on_rejection(self):
        from test_public_content import Replies, hooks_for, modify

        async def run():
            caps = {
                "effects": ["modify"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            hooks = hooks_for(
                "context.compact.before",
                caps,
                Replies([modify("instructions", "too large")]),
            )
            owner = Attachment.from_bytes(b"hello", max_bytes=5)
            bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                owner
            )
            uploads = []

            async def upload(data):
                uploads.append(data)
                return {
                    "ref": f"urn:direct:{len(uploads)}",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with hooks:
                result = await hooks.context_compact_before(
                    bound, uploads={"org.example.content": upload}
                )
            self.assertEqual(result.decision, "deny")
            self.assertEqual(len(result.diagnostics), 1)
            self.assertEqual(uploads, [b"hello"])
            async with result:
                self.assertIs(result.attachments._bindings[INSTRUCTIONS], owner)
                self.assertEqual(await result.attachments.read(INSTRUCTIONS), b"hello")

        self.run_async(run)

    def test_existing_json_modify_reads_owned_correlation_and_effective_answer(self):
        import json
        from agenthooksprotocol import ContentContext, ContentSources
        from agenthooksprotocol._boundaries import CONTENT_SOURCE_SLOTS
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
            request_owner = Attachment.from_bytes(json.dumps(question).encode())
            request_caps = {"effects": ["return"], "elicitation": {"form": {}}}
            original = wire(
                "user.elicitation.request",
                "original",
                {
                    "elicitation": {
                        "mode": "form",
                        "server": "example",
                        "request": {
                            "id": "question",
                            "kind": "content",
                            "mediaType": "application/json",
                            "selection": "body",
                            "body": {"ref": "urn:receiver:original"},
                        },
                    }
                },
                request_caps,
            )
            answer = {"action": "accept", "content": {"ok": False}}
            owner = Attachment.from_bytes(json.dumps(answer).encode())
            slot = next(
                name
                for name, value in CONTENT_SOURCE_SLOTS.items()
                if value == ("user.elicitation.result", ("elicitation", "result"))
            )
            value = {
                "parentEventId": "original",
                "session": {"id": "session"},
                "elicitation": {
                    "mode": "form",
                    "server": "example",
                    "action": "accept",
                    "result": {
                        "id": "answer",
                        "kind": "content",
                        "mediaType": "application/json",
                        "selection": "metadata",
                    },
                },
            }
            caps = {
                "effects": ["modify"],
                "modify": {"content": {"replace": True, "merge": True}},
                "elicitation": {"form": {}},
            }
            changed = {"action": "accept", "content": {"ok": True}}
            hooks = hooks_for(
                "user.elicitation.result",
                caps,
                Replies([modify("content", changed["content"])]),
            )
            uploads = []

            async def upload(data):
                uploads.append(data)
                return {
                    "ref": f"urn:direct:{len(uploads)}",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            # Correlation needs the original request, not an external byte store.
            context = ContentContext(
                upload=upload,
                bindings={"content": ("elicitation", "result")},
                principal="org.example.content",
                original_request=original,
                attachments={"request": request_owner},
            )
            async with request_owner:
                async with hooks:
                    result = await hooks.user_elicitation_result(
                        value,
                        content=context,
                        sources=ContentSources({slot: owner}),
                        uploads={"org.example.content": upload},
                    )
                self.assertEqual(result.diagnostics, [])
                async with result:
                    data = await result.attachments.read(slot)
                    self.assertIs(data, uploads[-1])
                    self.assertEqual(json.loads(data), changed)
                    self.assertIsNot(result.attachments._bindings[slot], owner)

        self.run_async(run)

    def test_unpublished_replacement_owners_are_retired(self):
        from contextlib import nullcontext
        from unittest.mock import patch
        from agenthooksprotocol import OperationCancelledError
        from agenthooksprotocol.lifecycle import Lifecycle
        from test_public_content import Replies, hooks_for, modify

        async def run():
            for failure in ("upload", "receipt", "cancel", "late"):
                created = []
                real_from_bytes = Attachment.from_bytes

                def create(data, **kwargs):
                    owner = real_from_bytes(data, **kwargs)
                    created.append(owner)
                    return owner

                original = Attachment.from_bytes(b"hello")
                bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                    original
                )
                caps = {
                    "effects": ["modify"],
                    "modify": {"instructions": {"replace": True, "merge": False}},
                }
                hooks = hooks_for(
                    "context.compact.before",
                    caps,
                    Replies([modify("instructions", "reviewed")]),
                )
                writes = []

                async def upload(data):
                    writes.append(data)
                    if len(writes) == 2:
                        if failure == "upload":
                            raise ValueError("upload failed")
                        if failure == "cancel":
                            await anyio.sleep_forever()
                    return {
                        "ref": f"urn:direct:{len(writes)}",
                        "size": len(data),
                        "sha256": "0" * 64
                        if failure == "receipt" and len(writes) == 2
                        else hashlib.sha256(data).hexdigest(),
                    }

                late = (
                    patch.object(Lifecycle, "commit_accept", return_value=None)
                    if failure == "late"
                    else nullcontext()
                )
                with patch.object(Attachment, "from_bytes", side_effect=create), late:
                    async with hooks:
                        try:
                            with anyio.move_on_after(0.1) as scope:
                                result = await hooks.context_compact_before(
                                    bound, uploads={"org.example.content": upload}
                                )
                            if not scope.cancel_called:
                                await result.aclose()
                        except OperationCancelledError:
                            self.assertEqual(failure, "late")
                self.assertEqual(len(created), 1)
                self.assertTrue(created[0]._closed)
                self.assertIsNone(created[0]._snapshot)

        self.run_async(run)

    def test_effective_replacement_cannot_be_transferred_twice(self):
        from test_public_content import Replies, hooks_for, modify

        async def run():
            caps = {
                "effects": ["modify"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            hooks = hooks_for(
                "context.compact.before",
                caps,
                Replies([modify("instructions", "reviewed")]),
            )
            original = Attachment.from_bytes(b"hello")
            bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                original
            )
            count = []

            async def upload(data):
                count.append(data)
                return {
                    "ref": f"urn:direct:{len(count)}",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with hooks:
                result = await hooks.context_compact_before(
                    bound, uploads={"org.example.content": upload}
                )
                replacement = result.attachments._bindings[INSTRUCTIONS]
                self.assertTrue(replacement._claimed)
                with self.assertRaisesRegex(ProtocolError, "already transferred"):
                    await hooks.context_compact_before(
                        ContextCompactBeforeInput(**payload()).bind_instructions_source(
                            replacement
                        )
                    )
            async with result:
                self.assertEqual(
                    await result.attachments.read(INSTRUCTIONS), b"reviewed"
                )

        self.run_async(run)

    def test_constructor_bounds_and_immutable_input(self):
        with self.assertRaises(TypeError):
            Attachment.from_bytes(bytearray(b"hello"))
        with self.assertRaises(ValueError):
            Attachment.from_bytes(b"hello", max_bytes=1)
