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

    def test_constructor_bounds_and_immutable_input(self):
        with self.assertRaises(TypeError):
            Attachment.from_bytes(bytearray(b"hello"))
        with self.assertRaises(ValueError):
            Attachment.from_bytes(b"hello", max_bytes=1)
