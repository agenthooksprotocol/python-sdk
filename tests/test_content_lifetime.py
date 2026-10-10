"""Binary attachment ownership retires independently of retained call handles."""

import gc
import hashlib
import unittest
import weakref

import anyio

from agenthooksprotocol import Attachment, OperationCancelledError
from agenthooksprotocol.runtime import ProtocolError
from test_attachments import inline_input
from test_owned_content_hooks import INSTRUCTIONS, Stream, harness, payload


class ContentLifetimeTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def input(self, owner):
        value = payload()
        value["items"][0]["parts"][0].pop("id")
        return inline_input(owner, value)

    def fixture(self, *, selection="body", upload=None, transport=None):
        hooks, transports = harness([selection])
        handles = []
        receiver = next(iter(transports.values()))
        original = receiver.request

        async def request(value):
            handles.extend(p for p in hooks._pending if p not in handles)
            return await (transport(value) if transport else original(value))

        receiver.request = request

        async def store(data):
            return {
                "ref": "urn:blob:hello",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }

        async def call(owner):
            return await hooks.context_compact_before(
                self.input(owner),
                uploads={name: upload or store for name in transports},
            )

        return hooks, handles, call

    def assert_retired(self, hooks, handles, owner):
        self.assertTrue(owner._closed)
        self.assertIsNone(owner._snapshot)
        self.assertIsNone(owner.stream)
        self.assertEqual(hooks._operations, [])
        for pending in handles:
            self.assertIsNone(pending.prepared_content)
            self.assertIsNone(pending.content)

    def test_accept_releases_original_without_invalidating_replacement(self):
        async def run():
            hooks, handles, call = self.fixture()
            owner = Attachment.from_bytes(b"hello")
            async with hooks:
                result = await call(owner)
                self.assertEqual(hooks._operations, [])
                self.assertTrue(all(p.prepared_content is None for p in handles))
                self.assertIs(result.attachments._bindings[INSTRUCTIONS], owner)
                # A retired invocation cannot invalidate its result-owned bytes.
                for pending in handles:
                    self.assertIsNone(await pending.accept_content())
                self.assertEqual(await result.attachments.read(INSTRUCTIONS), b"hello")
            self.assertFalse(owner._closed)
            await result.aclose()
            self.assert_retired(hooks, handles, owner)

        self.run_async(run)

    def test_acquisition_failure_timeout_and_cancellation_retire_bytes(self):
        async def run():
            for mode in ("failure", "timeout", "cancel"):

                async def fail(request):
                    if mode == "cancel":
                        for pending in handles:
                            pending.cancel()
                        await anyio.lowlevel.checkpoint()
                    if mode == "timeout":
                        raise TimeoutError("delivery timed out")
                    raise ValueError("delivery failed")

                hooks, handles, call = self.fixture(transport=fail)
                owner = Attachment.from_bytes(b"hello")
                async with hooks:
                    try:
                        result = await call(owner)
                    except OperationCancelledError:
                        self.assertEqual(mode, "cancel")
                    else:
                        self.assertEqual(result.decision, "deny")
                        await result.aclose()
                self.assert_retired(hooks, handles, owner)

        self.run_async(run)

    def test_idle_cancel_fallback_and_close_release_prepared_bytes(self):
        async def run():
            for terminal in ("cancel", "fallback", "close"):
                started = anyio.Event()

                async def block(request):
                    started.set()
                    await anyio.sleep_forever()

                hooks, handles, call = self.fixture(transport=block)
                owner = Attachment.from_bytes(b"hello")

                async def dispatch():
                    try:
                        result = await call(owner)
                    except OperationCancelledError:
                        return
                    await result.aclose()

                async with hooks:
                    async with anyio.create_task_group() as group:
                        group.start_soon(dispatch)
                        await started.wait()
                        if terminal == "close":
                            await hooks.aclose()
                        elif terminal == "fallback":
                            for pending in handles:
                                pending.accept(fallback=True)
                            group.cancel_scope.cancel()
                        else:
                            for pending in handles:
                                pending.cancel()
                self.assert_retired(hooks, handles, owner)

        self.run_async(run)

    def test_retained_terminal_handles_do_not_retain_caller_reader(self):
        async def run():
            for terminal in ("accepted", "cancelled", "closed", "fallback"):
                started = anyio.Event()

                async def block(request):
                    started.set()
                    await anyio.sleep_forever()

                stream = Stream()
                reference = weakref.ref(stream)
                owner = Attachment(stream)
                del stream
                hooks, handles, call = self.fixture(
                    selection="metadata" if terminal == "accepted" else "body",
                    transport=None if terminal == "accepted" else block,
                )
                retained = []

                async def dispatch():
                    try:
                        retained.append(await call(owner))
                    except OperationCancelledError:
                        pass

                async with hooks:
                    if terminal == "accepted":
                        retained.append(await call(owner))
                        returned = await retained[0].attachments.read(INSTRUCTIONS)
                        self.assertEqual(returned, b"hello")
                    else:
                        async with anyio.create_task_group() as group:
                            group.start_soon(dispatch)
                            await started.wait()
                            if terminal == "cancelled":
                                handles[0].cancel()
                            elif terminal == "closed":
                                await hooks.aclose()
                            else:
                                retained.append(handles[0].accept(fallback=True))
                                group.cancel_scope.cancel()
                gc.collect()
                self.assertIsNone(reference())
                self.assertIsNone(owner.stream)
                self.assertTrue(all(p.content is None for p in handles))
                if terminal == "accepted":
                    self.assertEqual(
                        await retained[0].attachments.read(INSTRUCTIONS), returned
                    )
                for result in retained:
                    if result is not None:
                        await result.aclose()
                self.assert_retired(hooks, handles, owner)

        self.run_async(run)

    def test_dropped_pending_is_not_retained_by_harness(self):
        async def run():
            hooks, handles, call = self.fixture()
            owner = Attachment.from_bytes(b"hello")
            async with hooks:
                result = await call(owner)
                references = [weakref.ref(p) for p in handles]
                handles.clear()
                gc.collect()
                self.assertTrue(all(ref() is None for ref in references))
                self.assertEqual(len(hooks._pending), 0)
                self.assertEqual(await result.attachments.read(INSTRUCTIONS), b"hello")
            await result.aclose()

        self.run_async(run)

    def test_one_pending_retirement_does_not_clear_another_owner(self):
        async def run():
            first_started, second_started, release = (
                anyio.Event(),
                anyio.Event(),
                anyio.Event(),
            )
            requests = []

            async def block(request):
                requests.append(request)
                if len(requests) == 1:
                    first_started.set()
                    await anyio.sleep_forever()
                second_started.set()
                await release.wait()
                return {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {"protocolVersion": "draft", "effects": []},
                }

            hooks, handles, call = self.fixture(transport=block)
            first, second = (
                Attachment.from_bytes(b"hello"),
                Attachment.from_bytes(b"hello"),
            )
            results = []

            async def dispatch(owner):
                try:
                    results.append(await call(owner))
                except OperationCancelledError:
                    pass

            async with hooks:
                async with anyio.create_task_group() as group:
                    group.start_soon(dispatch, first)
                    await first_started.wait()
                    group.start_soon(dispatch, second)
                    await second_started.wait()
                    handles[0].cancel()
                    self.assertFalse(second._closed)
                    release.set()
                self.assertTrue(first._closed)
                self.assertEqual(len(results), 1)
                self.assertEqual(
                    await results[0].attachments.read(INSTRUCTIONS), b"hello"
                )
                self.assertEqual(hooks._operations, [])
            await results[0].aclose()
            self.assert_retired(hooks, handles, first)
            self.assert_retired(hooks, handles, second)

        self.run_async(run)

    def test_finalization_failure_and_timeout_retire_bytes(self):
        async def run():
            for error in (ValueError("storage failure"), TimeoutError()):

                async def fail(data):
                    raise error

                hooks, handles, call = self.fixture(upload=fail)
                owner = Attachment.from_bytes(b"hello")
                async with hooks:
                    result = await call(owner)
                    self.assertEqual(result.decision, "deny")
                    await result.aclose()
                self.assert_retired(hooks, handles, owner)
                # One-shot byte owners cannot be retried; a fresh owner can.
                hooks, handles, call = self.fixture()
                fresh = Attachment.from_bytes(b"hello")
                async with hooks:
                    result = await call(fresh)
                    self.assertEqual(result.diagnostics, [])
                async with result:
                    self.assertEqual(
                        await result.attachments.read(INSTRUCTIONS), b"hello"
                    )
                self.assert_retired(hooks, handles, fresh)

        self.run_async(run)

    def test_cancelled_finalization_retires_after_inflight_work_exits(self):
        async def run():
            started, exited = anyio.Event(), anyio.Event()

            async def block(data):
                started.set()
                try:
                    await anyio.sleep_forever()
                finally:
                    exited.set()

            hooks, handles, call = self.fixture(upload=block)
            owner = Attachment.from_bytes(b"hello")
            async with hooks:
                async with anyio.create_task_group() as group:
                    group.start_soon(call, owner)
                    await started.wait()
                    group.cancel_scope.cancel()
                self.assertTrue(exited.is_set())
            self.assert_retired(hooks, handles, owner)

        self.run_async(run)

    def test_retained_unused_source_releases_buffered_reader(self):
        async def run():
            hooks, handles, call = self.fixture(selection="metadata")
            stream = Stream()
            reference = weakref.ref(stream)
            owner = Attachment(stream)
            del stream
            async with hooks:
                result = await call(owner)
                self.assertEqual(result.diagnostics, [])
                self.assertIsNotNone(reference())
                self.assertIsNone(owner._snapshot)
            # Unread binary sources now intentionally outlive Hooks.
            await result.aclose()
            gc.collect()
            self.assertIsNone(reference())
            self.assert_retired(hooks, handles, owner)

        self.run_async(run)

    def test_more_than_4096_calls_release_sources_and_keep_results(self):
        async def run():
            hooks, transports = harness(["body"])
            retained = []

            async def upload(data):
                return {
                    "ref": "urn:blob:hello",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with hooks:
                for _ in range(4097):
                    owner = Attachment(Stream())
                    result = await hooks.context_compact_before(
                        self.input(owner),
                        uploads={name: upload for name in transports},
                    )
                    self.assertEqual(result.diagnostics, [])
                    self.assertIsNone(owner.stream)
                    self.assertEqual(hooks._operations, [])
                    retained.append((result, owner))
                self.assertEqual(len(retained), 4097)
                for transport in transports.values():
                    self.assertEqual(len(transport.requests), 4097)
                    self.assertEqual(
                        transport.requests[-1]["params"]["event"]["items"][0]["parts"][
                            0
                        ]["body"],
                        {"ref": "urn:blob:hello"},
                    )
            for result, owner in retained:
                self.assertEqual(await result.attachments.read(INSTRUCTIONS), b"hello")
                await result.aclose()
                self.assert_retired(hooks, [], owner)

        # The remaining lifetime scenarios exercise both async backends.
        anyio.run(run)

    def test_live_source_limit_still_fails_and_releases_reader(self):
        async def run():
            owner = Attachment(Stream(), max_bytes=4)
            with self.assertRaises(ProtocolError):
                await owner.snapshot()
            self.assertIsNone(owner._snapshot)
            self.assertIsNone(owner.stream)
            await owner.aclose()

        self.run_async(run)
