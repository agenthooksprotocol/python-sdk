"""Retained public results and pending handles do not own retired content."""

import gc
import hashlib
import unittest
import weakref

import anyio

from agenthooksprotocol._content import ContentContext
from agenthooksprotocol.content import ContentSources, OwnedContentSource
from agenthooksprotocol.runtime import ProtocolError
from test_owned_content_hooks import INSTRUCTIONS, Stream, harness, payload
from test_public_content import Replies, Store, hooks_for, modify, wire


class ContentLifetimeTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def pending_fixture(self, *, upload=None, transport=None):
        store = Store()
        caps = {
            "effects": ["modify"],
            "modify": {"instructions": {"replace": True, "merge": False}},
        }
        context = ContentContext(
            resolve=store.resolve,
            upload=upload or store.upload,
            bindings={"instructions": ("instructions",)},
            principal="hook",
        )
        hooks = hooks_for(
            "context.compact.before", caps,
            transport or Replies([modify("instructions", "new")], []),
        )

        def begin(ident):
            return hooks.begin(wire("context.compact.before", ident, {
                "trigger": "manual", "items": [],
                "instructions": store.add("old", "text/plain"),
            }, caps), content=context)

        return store, hooks, begin

    def assert_retired(self, pending, prepared):
        self.assertIsNone(pending.prepared_content)
        self.assertFalse(hasattr(prepared, "raw"))
        self.assertEqual(prepared.effective, {})
        self.assertEqual(prepared.selected, {})
        self.assertIsNone(prepared.context)

    def test_accept_releases_original_without_invalidating_replacement(self):
        async def run():
            store, hooks, begin = self.pending_fixture()
            async with hooks:
                pending = begin("accepted")
                await pending.acquire()
                prepared = pending.prepared_content
                result = await pending.accept_content()
                self.assert_retired(pending, prepared)
                self.assertEqual(result.state["content"]["instructions"], "new")
                reference = result.event["instructions"]["body"]
                self.assertEqual(await store.resolve(reference), b"new")
                self.assertEqual(len(store.bodies), 2)
                reads = len(store.reads)
                self.assertIsNone(await pending.accept_content())
                self.assertEqual(len(store.reads), reads)
                self.assertEqual(hooks._operations, [])

        self.run_async(run)

    def test_acquisition_failure_timeout_and_cancellation_retire_bytes(self):
        async def run():
            for mode in ("failure", "timeout", "cancel"):
                captured = []

                class FailingTransport:
                    async def request(self, request):
                        captured.append(pending.prepared_content)
                        if mode == "cancel":
                            pending.cancel()
                            await anyio.lowlevel.checkpoint()
                        if mode == "timeout":
                            raise TimeoutError("delivery timed out")
                        raise ValueError("delivery failed")

                store, hooks, begin = self.pending_fixture(transport=FailingTransport())
                async with hooks:
                    pending = begin(mode)
                    if mode == "cancel":
                        self.assertIsNone(await pending.acquire())
                    else:
                        with self.assertRaises((ValueError, TimeoutError)):
                            await pending.acquire()
                    self.assert_retired(pending, captured[0])
                    self.assertEqual(len(store.bodies), 1)
                    self.assertEqual(hooks._operations, [])

        self.run_async(run)

    def test_idle_cancel_fallback_and_close_release_prepared_bytes(self):
        async def run():
            for terminal in ("cancel", "fallback", "close"):
                store, hooks, begin = self.pending_fixture()
                async with hooks:
                    pending = begin(terminal)
                    await pending.acquire()
                    prepared = pending.prepared_content
                    if terminal == "cancel":
                        pending.cancel()
                    elif terminal == "fallback":
                        await pending.accept_content(fallback=True)
                    else:
                        await hooks.aclose()
                    self.assert_retired(pending, prepared)
                    self.assertEqual(len(store.bodies), 1)
                    self.assertEqual(hooks._operations, [])

        self.run_async(run)

    def test_retained_terminal_handles_do_not_retain_caller_store(self):
        async def run():
            for terminal in ("accepted", "cancelled", "closed", "fallback"):
                store, hooks, begin = self.pending_fixture()
                reference = weakref.ref(store)
                result = None
                async with hooks:
                    pending = begin(terminal)
                    await pending.acquire()
                    prepared = pending.prepared_content
                    if terminal == "accepted":
                        result = await pending.accept_content()
                        returned_bytes = await store.resolve(
                            result.event["instructions"]["body"]
                        )
                        self.assertEqual(returned_bytes, b"new")
                    elif terminal == "cancelled":
                        pending.cancel()
                    elif terminal == "closed":
                        await hooks.aclose()
                    else:
                        result = await pending.accept_content(fallback=True)
                    self.assert_retired(pending, prepared)
                    self.assertIsNone(pending.content)
                    # Retirement did not destroy persistent receiver data.
                    self.assertEqual(len(store.bodies), 2 if terminal == "accepted" else 1)
                    del store, begin
                    gc.collect()
                    self.assertIsNone(reference(), terminal)
                    if terminal != "closed":
                        self.assertIsNone(await pending.accept_content())
                        with self.assertRaisesRegex(RuntimeError, "Content-bound"):
                            pending.accept()
                # Keep the result, pending handle AND retired preparation alive.
                if terminal == "accepted":
                    self.assertEqual(result.state["content"]["instructions"], "new")
                    self.assertEqual(returned_bytes, b"new")
                    self.assertIs(pending.result, result)

        self.run_async(run)

    def test_dropped_pending_is_not_retained_by_harness(self):
        async def run():
            _, hooks, begin = self.pending_fixture()
            async with hooks:
                pending = begin("dropped")
                await pending.acquire()
                handle = weakref.ref(pending)
                prepared = weakref.ref(pending.prepared_content)
                del pending
                gc.collect()
                self.assertIsNone(handle())
                self.assertIsNone(prepared())
                self.assertEqual(len(hooks._pending), 0)

        self.run_async(run)

    def test_one_pending_retirement_does_not_clear_another_or_shared_store(self):
        async def run():
            store, hooks, begin = self.pending_fixture()
            async with hooks:
                first, second = begin("first"), begin("second")
                async with anyio.create_task_group() as group:
                    group.start_soon(first.acquire)
                    group.start_soon(second.acquire)
                first.cancel()
                self.assertIsNone(first.prepared_content)
                self.assertTrue(second.prepared_content.selected)
                result = await second.accept_content()
                self.assertIsNotNone(result)
                self.assertGreaterEqual(len(store.bodies), 2)
                self.assertEqual(hooks._operations, [])

        self.run_async(run)

    def test_finalization_failure_and_timeout_retire_bytes(self):
        async def run():
            for error in (ValueError("storage failure"), TimeoutError()):
                async def fail(data):
                    raise error

                store, hooks, begin = self.pending_fixture(upload=fail)
                async with hooks:
                    pending = begin("failed")
                    await pending.acquire()
                    prepared = pending.prepared_content
                    with self.assertRaises(Exception):
                        await pending.accept_content()
                    self.assert_retired(pending, prepared)
                    self.assertIsNone(pending.result)
                    self.assertEqual(hooks._operations, [])
                    # Nonterminal failures retain the adapter for a fresh retry.
                    self.assertIsNotNone(pending.content)
                    pending.content.upload = store.upload
                    result = await pending.accept_content()
                    self.assertEqual(result.state["content"]["instructions"], "new")
                    self.assertIsNone(pending.content)

        self.run_async(run)

    def test_cancelled_finalization_retires_after_inflight_work_exits(self):
        async def run():
            started = anyio.Event()

            async def block(data):
                started.set()
                await anyio.sleep_forever()

            _, hooks, begin = self.pending_fixture(upload=block)
            async with hooks:
                pending = begin("cancelled")
                await pending.acquire()
                prepared = pending.prepared_content
                async with anyio.create_task_group() as group:
                    group.start_soon(pending.accept_content)
                    await started.wait()
                    pending.cancel()
                self.assert_retired(pending, prepared)
                self.assertEqual(hooks._operations, [])

        self.run_async(run)

    def test_retained_unused_source_releases_buffered_reader(self):
        async def run():
            hooks, _ = harness(["metadata"])
            stream = Stream()
            reference = weakref.ref(stream)
            source = OwnedContentSource(stream)
            sources = ContentSources({INSTRUCTIONS: source})
            del stream
            async with hooks:
                result = await hooks.context_compact_before(payload(), sources=sources)
                gc.collect()
                self.assertIsNone(reference())
                self.assertIsNone(source.stream)
                self.assertIsNone(source._snapshot)
                self.assertEqual(sources._references, {})
                self.assertEqual(sources.bindings, {})
                self.assertEqual(sources.uploads, {})
                self.assertEqual(result.diagnostics, [])
                self.assertEqual(hooks._operations, [])

        self.run_async(run)

    def test_more_than_4096_calls_release_sources_and_keep_results(self):
        async def run():
            hooks, transports = harness(["body"])
            retained = []

            async def upload(data):
                return {"ref": "urn:blob:hello", "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()}

            async with hooks:
                for _ in range(4097):
                    source = OwnedContentSource(Stream())
                    sources = ContentSources({INSTRUCTIONS: source})
                    result = await hooks.context_compact_before(
                        payload(), sources=sources,
                        uploads={name: upload for name in transports},
                    )
                    self.assertEqual(result.diagnostics, [])
                    self.assertIsNone(source._snapshot)
                    self.assertIsNone(source.stream)
                    self.assertEqual(sources._references, {})
                    self.assertEqual(sources.bindings, {})
                    self.assertEqual(sources.uploads, {})
                    self.assertEqual(hooks._operations, [])
                    retained.append((result, source))
                self.assertEqual(len(retained), 4097)
                self.assertEqual(retained[0][0].event["instructions"]["selection"],
                                 "metadata")
                for transport in transports.values():
                    self.assertEqual(len(transport.requests), 4097)
                    self.assertEqual(
                        transport.requests[-1]["params"]["event"]["instructions"]["body"],
                        {"ref": "urn:blob:hello"},
                    )

        # Exercise the full public path; the other lifetime cases cover both loops.
        anyio.run(run)

    def test_live_source_limit_still_fails_and_releases_reader(self):
        async def run():
            source = OwnedContentSource(Stream(), max_bytes=4)
            with self.assertRaises(ProtocolError):
                await source.snapshot()
            self.assertIsNone(source._snapshot)
            self.assertIsNone(source.stream)
            await source.aclose()

        self.run_async(run)
