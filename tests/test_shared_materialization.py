"""Shared owned materialization must work on both AnyIO backends."""

import hashlib
import unittest

import anyio

from agenthooksprotocol import Attachment, OperationCancelledError
from agenthooksprotocol._content import OwnedContentSource
from agenthooksprotocol.runtime import ProtocolError


class SharedMaterializationTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    async def overlap(self, *, cancel=None, error=None, close=False):
        started, release = anyio.Event(), anyio.Event()
        calls, cleanups, outcomes, scopes = [], [], {}, {}
        data = b"shared immutable bytes"

        async def load():
            calls.append(1)
            started.set()
            await release.wait()
            if error is not None:
                raise error
            return data

        async def cleanup():
            cleanups.append(1)
            await anyio.lowlevel.checkpoint()

        owner = Attachment.lazy(load, aclose=cleanup)

        async def read(name):
            with anyio.CancelScope() as scope:
                scopes[name] = scope
                try:
                    outcomes[name] = await owner.snapshot()
                except anyio.get_cancelled_exc_class():
                    outcomes[name] = "cancelled"
                except Exception as exc:
                    outcomes[name] = exc

        with anyio.fail_after(2):
            async with anyio.create_task_group() as group:
                group.start_soon(read, "leader")
                await started.wait()
                group.start_soon(read, "follower")
                while owner._waiters != 2:
                    await anyio.lowlevel.checkpoint()
                if cancel is not None:
                    scopes[cancel].cancel()
                    while owner._waiters != 1:
                        await anyio.lowlevel.checkpoint()
                    self.assertTrue(owner._pending)
                    self.assertFalse(owner._failed)
                if close:
                    await owner.aclose()
                else:
                    release.set()
        self.assertEqual(calls, [1])
        self.assertEqual(cleanups, [1])
        self.assertFalse(owner._pending)
        self.assertEqual(owner._waiters, 0)
        if close:
            self.assertTrue(owner._cancelled)
            self.assertTrue(
                all(isinstance(v, OperationCancelledError) for v in outcomes.values())
            )
        elif error is not None:
            self.assertTrue(all(v is error for v in outcomes.values()))
            with self.assertRaises(type(error)) as caught:
                await owner.snapshot()
            self.assertIs(caught.exception, error)
        else:
            for name, value in outcomes.items():
                if name == cancel:
                    self.assertEqual(value, "cancelled")
                else:
                    self.assertIs(value, data)
            self.assertIs(await owner.snapshot(), data)
        await owner.aclose()
        await owner.aclose()
        self.assertEqual(cleanups, [1])
        with self.assertRaises(ProtocolError):
            await owner.snapshot()

    def test_shared_success(self):
        self.run_async(self.overlap)

    def test_cancel_leader_preserves_follower(self):
        async def run():
            await self.overlap(cancel="leader")

        self.run_async(run)

    def test_cancel_follower_preserves_leader(self):
        async def run():
            await self.overlap(cancel="follower")

        self.run_async(run)

    def test_shared_exact_error(self):
        async def run():
            await self.overlap(error=ValueError("loader failed"))

        self.run_async(run)

    def test_close_cancels_and_joins(self):
        async def run():
            await self.overlap(close=True)

        self.run_async(run)

    def test_last_waiter_cancellation_joins_cleanup(self):
        async def run():
            started, exited = anyio.Event(), anyio.Event()
            cleanups = []

            async def load():
                started.set()
                try:
                    await anyio.sleep_forever()
                finally:
                    exited.set()

            async def cleanup():
                cleanups.append(1)

            owner = Attachment.lazy(load, aclose=cleanup)
            async with anyio.create_task_group() as group:
                group.start_soon(owner.snapshot)
                await started.wait()
                group.cancel_scope.cancel()
            self.assertTrue(exited.is_set())
            self.assertTrue(owner._cancelled)
            self.assertFalse(owner._failed)
            self.assertFalse(owner._pending)
            self.assertEqual(cleanups, [1])
            with self.assertRaises(OperationCancelledError):
                await owner.snapshot()
            await owner.aclose()
            self.assertEqual(cleanups, [1])

        self.run_async(run)

    def test_cleanup_completion_precedes_all_reads(self):
        async def run():
            cleaning, finish = anyio.Event(), anyio.Event()
            error = ValueError("cleanup failed")
            values = []

            async def load():
                return b"must not escape before cleanup"

            async def cleanup():
                cleaning.set()
                await finish.wait()
                raise error

            owner = Attachment.lazy(load, aclose=cleanup)

            async def read():
                try:
                    await owner.snapshot()
                except ValueError as exc:
                    values.append(exc)

            with anyio.fail_after(2):
                async with anyio.create_task_group() as group:
                    group.start_soon(read)
                    await cleaning.wait()
                    group.start_soon(read)
                    while owner._waiters != 2:
                        await anyio.lowlevel.checkpoint()
                    finish.set()
            self.assertEqual(len(values), 2)
            self.assertTrue(all(value is error for value in values))
            self.assertIsNone(owner._snapshot)
            await owner.aclose()

        self.run_async(run)

    def test_timeout_and_validation_stay_terminal(self):
        async def run():
            async def block():
                await anyio.sleep_forever()

            owner = Attachment.lazy(block, timeout=0.01)
            with self.assertRaises(TimeoutError) as first:
                await owner.snapshot()
            with self.assertRaises(TimeoutError) as second:
                await owner.snapshot()
            self.assertIs(first.exception, second.exception)
            self.assertTrue(owner._failed)
            self.assertFalse(owner._cancelled)
            await owner.aclose()

            class Stream:
                def __init__(self):
                    self.parts = iter([b"abc", b""])
                    self.closes = 0

                async def read(self, amount):
                    return next(self.parts)

                async def aclose(self):
                    self.closes += 1

            for options in (
                {"max_bytes": 2},
                {"expected_size": 4},
                {"expected_sha256": hashlib.sha256(b"wrong").hexdigest()},
            ):
                stream = Stream()
                source = OwnedContentSource(stream, **options)
                with self.assertRaises(ProtocolError) as first:
                    await source.snapshot()
                with self.assertRaises(ProtocolError) as second:
                    await source.snapshot()
                self.assertIs(first.exception, second.exception)
                await source.aclose()
                self.assertEqual(stream.closes, 1)

        self.run_async(run)

    def test_cancelled_leader_returns_and_releases_permit_before_source_finishes(self):
        async def run():
            started, leader_returned, permit_released = (
                anyio.Event() for _ in range(3)
            )
            scopes, outcomes, cleanups = {}, {}, []
            limiter = anyio.Semaphore(2)
            data = b"surviving reader"

            async def load():
                started.set()
                # Completion depends on cancellation returning, not vice versa.
                await leader_returned.wait()
                await permit_released.wait()
                return data

            async def cleanup():
                cleanups.append(True)

            owner = Attachment.lazy(load, aclose=cleanup)

            async def read(name):
                with anyio.CancelScope() as scope:
                    scopes[name] = scope
                    try:
                        async with limiter:
                            outcomes[name] = await owner.snapshot()
                    except anyio.get_cancelled_exc_class():
                        outcomes[name] = "cancelled"
                if name == "leader":
                    leader_returned.set()

            async def next_transfer():
                async with limiter:
                    self.assertTrue(leader_returned.is_set())
                    permit_released.set()

            try:
                with anyio.fail_after(2):
                    async with anyio.create_task_group() as group:
                        group.start_soon(read, "leader")
                        await started.wait()
                        group.start_soon(read, "follower")
                        while owner._waiters != 2:
                            await anyio.lowlevel.checkpoint()
                        scopes["leader"].cancel()
                        await leader_returned.wait()
                        self.assertTrue(owner._pending)
                        self.assertEqual(owner._waiters, 1)
                        self.assertEqual(cleanups, [])
                        group.start_soon(next_transfer)
                self.assertEqual(outcomes["leader"], "cancelled")
                self.assertIs(outcomes["follower"], data)
                self.assertIs(await owner.snapshot(), data)
                self.assertEqual(cleanups, [True])
            finally:
                await owner.aclose()
            self.assertEqual(cleanups, [True])

        self.run_async(run)

    def test_result_reads_after_shutdown_cancel_leader_without_changing_result(self):
        from copy import deepcopy
        from test_inline_messages import harness, host

        async def run():
            started, returned = anyio.Event(), anyio.Event()
            data, calls, outcomes, scopes = b"retained result", [], {}, {}

            async def load():
                calls.append("load")
                started.set()
                await returned.wait()
                return data

            async def cleanup():
                calls.append("close")

            owner = Attachment.lazy(load, aclose=cleanup)
            hooks, _ = harness(["body"], unmatched=True)
            async with hooks:
                result = await hooks.context_compact_before(host(owner))
            self.assertEqual(calls, [])
            original = deepcopy(result.event)
            slot = next(iter(result.attachments._bindings))

            async def read(name):
                with anyio.CancelScope() as scope:
                    scopes[name] = scope
                    try:
                        outcomes[name] = await result.attachments.read(slot)
                    except anyio.get_cancelled_exc_class():
                        outcomes[name] = "cancelled"
                if name == "leader":
                    returned.set()

            async with result:
                with anyio.fail_after(2):
                    async with anyio.create_task_group() as group:
                        group.start_soon(read, "leader")
                        await started.wait()
                        group.start_soon(read, "follower")
                        while owner._waiters != 2:
                            await anyio.lowlevel.checkpoint()
                        scopes["leader"].cancel()
                        await returned.wait()
                self.assertEqual(outcomes["leader"], "cancelled")
                self.assertIs(outcomes["follower"], data)
                self.assertIs(await result.attachments.read(slot), data)
                self.assertIs(result.attachments._bindings[slot], owner)
                self.assertEqual(result.event, original)
                self.assertIsNone(owner._worker)
            self.assertEqual(calls, ["load", "close"])
            self.assertTrue(owner._closed)

        self.run_async(run)

    def test_materialization_and_cleanup_preserve_request_context(self):
        from contextvars import ContextVar

        async def run():
            request_context = ContextVar("attachment-request", default="missing")
            request_context.set("authorized-request")
            started, release = anyio.Event(), anyio.Event()
            calls, results = [], []

            async def load():
                calls.append(("start", request_context.get()))
                started.set()
                await release.wait()
                calls.append(("finish", request_context.get()))
                return b"context-owned"

            async def cleanup():
                calls.append(("close", request_context.get()))

            owner = Attachment.lazy(load, aclose=cleanup)

            async def read():
                results.append(await owner.snapshot())

            async with owner:
                with anyio.fail_after(2):
                    async with anyio.create_task_group() as group:
                        group.start_soon(read)
                        await started.wait()
                        request_context.set("different-request")
                        release.set()
                self.assertEqual(results, [b"context-owned"])
            self.assertEqual(
                calls,
                [
                    (stage, "authorized-request")
                    for stage in ("start", "finish", "close")
                ],
            )
            self.assertIsNone(owner._worker)

        self.run_async(run)
