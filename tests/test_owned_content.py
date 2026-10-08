"""Owned delivery streams: no eager reads, bounded preparation, native cancellation."""

import hashlib
import unittest

import anyio

from agenthooksprotocol.content import ContentSources, OwnedContentSource
from agenthooksprotocol.runtime import ProtocolError, Validator
from agenthooksprotocol._boundaries import CONTENT_SOURCE_SLOTS


def generated_slot(kind, path):
    return next(
        name for name, value in CONTENT_SOURCE_SLOTS.items() if value == (kind, path)
    )


INSTRUCTIONS = generated_slot("context.compact.before", ("instructions",))
SUMMARY = generated_slot("context.compact.after", ("summary",))


class Stream:
    def __init__(self, data=b"hello", *, blocked=False):
        self.data = data
        self.reads = 0
        self.closes = 0
        self.blocked = blocked

    async def read(self, size):
        self.reads += 1
        if self.blocked:
            await anyio.sleep_forever()
        part, self.data = self.data[:size], self.data[size:]
        return part

    async def aclose(self):
        await anyio.sleep(0)
        self.closes += 1


def event():
    return {
        "type": "context.compact.before",
        "instructions": {
            "id": "instructions",
            "kind": "content",
            "mediaType": "text/plain",
            "selection": "metadata",
            "size": 5,
        },
    }


class OwnedContentTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_unused_and_non_body_selections_never_read_or_upload(self):
        async def run():
            for selection in ("omit", "metadata"):
                stream = Stream()

                async def upload(data):
                    self.fail("unexpected upload")

                async with ContentSources(
                    {INSTRUCTIONS: OwnedContentSource(stream)}
                ) as sources:
                    self.assertEqual(stream.reads, 0)
                    view = await sources.project(
                        event(),
                        {"default": selection},
                        upload=upload,
                        validator=Validator(),
                    )
                    self.assertEqual(view["instructions"]["selection"], selection)
                    self.assertEqual(view["instructions"]["size"], 5)
                self.assertEqual((stream.reads, stream.closes), (0, 1))
            unused = Stream()
            async with ContentSources({INSTRUCTIONS: OwnedContentSource(unused)}):
                pass
            self.assertEqual((unused.reads, unused.closes), (0, 1))

        self.run_async(run)

    def test_snapshot_once_independently_uploaded_per_destination(self):
        async def run():
            stream = Stream()
            writes = []

            async def upload(data):
                writes.append(data)
                return {
                    "ref": f"urn:blob:{len(writes)}",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            original = event()
            async with ContentSources(
                {INSTRUCTIONS: OwnedContentSource(stream)}
            ) as sources:
                views = []

                async def project():
                    views.append(
                        await sources.project(
                            original,
                            {"default": "body"},
                            upload=upload,
                            validator=Validator(),
                        )
                    )

                async with anyio.create_task_group() as group:
                    group.start_soon(project)
                    group.start_soon(project)
                self.assertNotEqual(
                    views[0]["instructions"]["body"]["ref"],
                    views[1]["instructions"]["body"]["ref"],
                )
                for view in views:
                    item = view["instructions"]
                    self.assertEqual(set(item["body"]), {"ref"})
                    self.assertNotIn("size", item)
                    self.assertNotIn("sha256", item)
                self.assertEqual(writes, [b"hello", b"hello"])
                self.assertEqual(stream.reads, 2)
            self.assertEqual(stream.closes, 1)
            self.assertNotIn("body", original["instructions"])

        self.run_async(run)

    def test_limits_expectations_and_failed_source_are_terminal(self):
        async def run():
            for kwargs in (
                {"max_bytes": 4},
                {"expected_size": 4},
                {"expected_sha256": "0" * 64},
            ):
                stream = Stream()
                source = OwnedContentSource(stream, **kwargs)
                with self.assertRaises(ProtocolError):
                    await source.snapshot()
                reads = stream.reads
                with self.assertRaises(ProtocolError):
                    await source.snapshot()
                await source.aclose()
                self.assertEqual(stream.reads, reads)
                self.assertEqual(stream.closes, 1)
            async with OwnedContentSource(Stream(b""), max_bytes=0) as source:
                self.assertEqual(await source.snapshot(), b"")
            async with OwnedContentSource(Stream(), max_bytes=5) as source:
                self.assertEqual(await source.snapshot(), b"hello")

        self.run_async(run)

    def test_outer_deadline_and_explicit_cancellation_close_sources(self):
        async def run():
            for mode in ("deadline", "cancel"):
                stream = Stream(blocked=True)
                source = OwnedContentSource(stream)
                if mode == "deadline":
                    with self.assertRaises(TimeoutError):
                        with anyio.fail_after(0.01):
                            async with ContentSources({INSTRUCTIONS: source}):
                                await source.snapshot()
                else:
                    with anyio.CancelScope() as scope:
                        scope.cancel()
                        async with source:
                            await source.snapshot()
                self.assertEqual(stream.closes, 1)
                with self.assertRaises(ProtocolError):
                    await source.snapshot()

        self.run_async(run)

    def test_source_timeout_closes_stream(self):
        async def run():
            stream = Stream(blocked=True)
            async with OwnedContentSource(stream, timeout=0.01) as source:
                with self.assertRaises(TimeoutError):
                    await source.snapshot()
            self.assertEqual(stream.closes, 1)

        self.run_async(run)

    def test_bad_receiver_descriptor_prevents_publication(self):
        async def run():
            stream = Stream()

            async def upload(data):
                return {"ref": "urn:bad", "size": 5, "sha256": "0" * 64}

            async with ContentSources(
                {INSTRUCTIONS: OwnedContentSource(stream)}
            ) as sources:
                with self.assertRaises(ProtocolError):
                    await sources.project(
                        event(),
                        {"default": "body"},
                        upload=upload,
                        validator=Validator(),
                    )
            self.assertEqual(stream.closes, 1)

        self.run_async(run)

    def test_upload_consumes_same_outer_budget(self):
        async def run():
            stream = Stream()

            async def upload(data):
                await anyio.sleep_forever()

            with self.assertRaises(TimeoutError):
                with anyio.fail_after(0.01):
                    async with ContentSources(
                        {INSTRUCTIONS: OwnedContentSource(stream)}
                    ) as sources:
                        await sources.project(
                            event(),
                            {"default": "body"},
                            upload=upload,
                            validator=Validator(),
                        )
            self.assertEqual(stream.closes, 1)

        self.run_async(run)

    def test_invalid_limits_rejected_without_io(self):
        for kwargs in (
            {"max_bytes": -1},
            {"max_bytes": True},
            {"timeout": float("inf")},
            {"timeout": 0},
            {"expected_sha256": "bad"},
            {"expected_size": -1},
        ):
            stream = Stream()
            with self.assertRaises(ValueError):
                OwnedContentSource(stream, **kwargs)
            self.assertEqual((stream.reads, stream.closes), (0, 0))

    def test_destination_callback_is_required_only_for_body(self):
        async def run():
            stream = Stream()
            async with ContentSources(
                {INSTRUCTIONS: OwnedContentSource(stream)}
            ) as sources:
                await sources.project(
                    event(),
                    {"default": "metadata"},
                    backend="unknown",
                    validator=Validator(),
                )
                with self.assertRaises(ProtocolError):
                    await sources.project(
                        event(),
                        {"default": "body"},
                        backend="unknown",
                        validator=Validator(),
                    )
                self.assertEqual(stream.reads, 0)
            self.assertEqual(stream.closes, 1)

        self.run_async(run)

    def test_cancelled_unused_set_closes_all_sources(self):
        async def run():
            streams = [Stream(), Stream()]
            sources = ContentSources(
                {
                    INSTRUCTIONS: OwnedContentSource(streams[0]),
                    SUMMARY: OwnedContentSource(streams[1]),
                }
            )
            with anyio.CancelScope() as scope:
                scope.cancel()
                async with sources:
                    await anyio.sleep_forever()
            self.assertEqual([stream.closes for stream in streams], [1, 1])
            self.assertEqual([stream.reads for stream in streams], [0, 0])

        self.run_async(run)

    def test_anyio_receive_stream(self):
        class Receiver:
            def __init__(self):
                self.reads = 0
                self.closed = False

            async def receive(self, amount):
                self.reads += 1
                if self.reads == 1:
                    return b"hello"
                raise anyio.EndOfStream

            async def aclose(self):
                self.closed = True

        async def run():
            receiver = Receiver()
            async with OwnedContentSource(receiver) as source:
                self.assertEqual(await source.snapshot(), b"hello")
            self.assertTrue(receiver.closed)

        self.run_async(run)

    def test_read_and_cleanup_failures_do_not_replace_cancellation(self):
        class BadClose(Stream):
            async def aclose(self):
                self.closes += 1
                raise ValueError("close failed")

        async def run():
            stream = BadClose(blocked=True)
            with self.assertRaises(TimeoutError):
                with anyio.fail_after(0.01):
                    await OwnedContentSource(stream).snapshot()
            self.assertEqual(stream.closes, 1)

        self.run_async(run)

    def test_settled_reference_is_not_overwritten_by_original_source(self):
        async def run():
            stream = Stream()
            value = event()
            value["instructions"].update(
                selection="body",
                body={"ref": "urn:settled"},
            )
            value["instructions"].pop("size", None)
            value["instructions"].pop("sha256", None)
            async with ContentSources(
                {INSTRUCTIONS: OwnedContentSource(stream)}
            ) as sources:
                projected = await sources.project(
                    value, {"default": "body"}, backend="unknown", validator=Validator()
                )
                self.assertEqual(
                    projected["instructions"]["body"]["ref"], "urn:settled"
                )
            self.assertEqual(stream.reads, 0)

        self.run_async(run)

    def test_generated_array_slot_indices_resolve_only_bound_item(self):
        async def run():
            arrays = [
                (name, kind, path)
                for name, (kind, path) in CONTENT_SOURCE_SLOTS.items()
                if "*" in path
            ]
            self.assertTrue(arrays, "generator must expose array content slots")
            name, kind, path = arrays[0]

            def value_at(components):
                if not components:
                    return {
                        "id": "array-item",
                        "kind": "content",
                        "mediaType": "text/plain",
                        "selection": "metadata",
                    }
                head, *tail = components
                child = value_at(tail)
                return [None, child] if head == "*" else {head: child}

            value = value_at(path)
            value["type"] = kind
            binding = name + "[1]" * path.count("*")
            stream = Stream()

            async def upload(data):
                return {
                    "ref": "urn:array:body",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with ContentSources({binding: OwnedContentSource(stream)}) as sources:
                projected = await sources.project(
                    value, {"default": "body"}, upload=upload, validator=Validator()
                )
            item = projected
            original = value
            for component in path:
                index = 1 if component == "*" else component
                item, original = item[index], original[index]
            self.assertEqual(item["body"]["ref"], "urn:array:body")
            self.assertNotIn("body", original)
            self.assertEqual(stream.closes, 1)

        self.run_async(run)

    def test_generated_array_binding_rejects_missing_negative_and_extra_indices(self):
        async def run():
            name, (_, path) = next(
                (name, value)
                for name, value in CONTENT_SOURCE_SLOTS.items()
                if "*" in value[1]
            )
            for binding in (
                name,
                name + "[-1]",
                name + "[01]",
                name + "[0]" * (path.count("*") + 1),
                INSTRUCTIONS + "[0]",
            ):
                stream = Stream()
                async with OwnedContentSource(stream) as source:
                    with self.assertRaises(ValueError):
                        ContentSources({binding: source})
                self.assertEqual((stream.reads, stream.closes), (0, 1))

        self.run_async(run)

    def test_missing_indexed_descriptor_does_not_read(self):
        async def run():
            name, (kind, path) = next(
                (name, value)
                for name, value in CONTENT_SOURCE_SLOTS.items()
                if "*" in value[1]
            )
            stream = Stream()
            async with ContentSources(
                {name + "[100]" * path.count("*"): OwnedContentSource(stream)}
            ) as sources:
                with self.assertRaises(ProtocolError):
                    await sources.project(
                        {"type": kind},
                        {"default": "body"},
                        backend="unknown",
                        validator=Validator(),
                    )
            self.assertEqual((stream.reads, stream.closes), (0, 1))

        self.run_async(run)
