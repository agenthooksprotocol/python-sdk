"""Owned content is scoped to an awaited Hooks call and each selected receiver."""

from copy import deepcopy
import hashlib
import unittest

import anyio

from agenthooksprotocol import Hooks
from agenthooksprotocol._boundaries import CONTENT_SOURCE_SLOTS
from agenthooksprotocol._hooks import HooksClosedError
from agenthooksprotocol.content import ContentSources, OwnedContentSource


INSTRUCTIONS = next(
    name
    for name, value in CONTENT_SOURCE_SLOTS.items()
    if value == ("context.compact.before", ("instructions",))
)


class Stream:
    def __init__(self):
        self.data = b"hello"
        self.reads = 0
        self.closes = 0

    async def read(self, size):
        self.reads += 1
        result, self.data = self.data[:size], self.data[size:]
        return result

    async def aclose(self):
        await anyio.sleep(0)
        self.closes += 1


class Transport:
    def __init__(self):
        self.requests = []
        self.notifications = []
        self.closes = 0

    async def request(self, request):
        self.requests.append(deepcopy(request))
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"protocolVersion": "draft", "effects": []},
        }

    async def notify(self, note):
        self.notifications.append(deepcopy(note))

    async def aclose(self):
        self.closes += 1


def payload():
    return {
        "trigger": "manual",
        "items": [],
        "instructions": {
            "id": "instructions",
            "kind": "content",
            "mediaType": "text/plain",
            "selection": "metadata",
            "size": 5,
        },
    }


def harness(selections, *, mode="intercept", unmatched=False):
    transports = {
        f"org.example.receiver{index}": Transport() for index in range(len(selections))
    }
    names = list(transports)
    config = {
        "protocolVersion": "draft",
        "hooks": [
            {
                "id": name,
                "transport": {"type": "http", "url": "https://receiver.invalid"},
                "subscriptions": [
                    {
                        "events": [
                            "context.compact.after"
                            if unmatched
                            else "context.compact.before"
                        ],
                        "mode": mode,
                        "timeoutMs": 1000,
                        "failurePolicy": "fail-closed",
                        "content": {"default": selection},
                    }
                ],
            }
            for name, selection in zip(names, selections)
        ],
    }
    if mode == "observe":
        for backend in config["hooks"]:
            for subscription in backend["subscriptions"]:
                subscription.pop("timeoutMs")
                subscription.pop("failurePolicy")
    capabilities = {
        name: {"modes": [mode], "capabilities": {"effects": []}}
        for name in ("context.compact.before", "context.compact.after")
    }
    return Hooks(
        config, source="urn:test", capabilities=capabilities, transport=transports
    ), transports


class OwnedContentHooksTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_per_backend_upload_and_single_snapshot(self):
        async def run():
            hooks, transports = harness(["body", "body"])
            stream = Stream()
            writes = []

            def uploader(destination):
                async def upload(data):
                    writes.append((destination, data))
                    return {
                        "ref": f"urn:blob:{destination}",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }

                return upload

            sources = ContentSources({INSTRUCTIONS: OwnedContentSource(stream)})
            async with hooks:
                result = await hooks.context_compact_before(
                    payload(),
                    sources=sources,
                    uploads={name: uploader(name) for name in transports},
                )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(writes, [(name, b"hello") for name in transports])
            for name, transport in transports.items():
                body = transport.requests[0]["params"]["event"]["instructions"]["body"]
                self.assertEqual(body["ref"], f"urn:blob:{name}")
                self.assertEqual(transport.closes, 0)
            self.assertEqual((stream.reads, stream.closes), (2, 1))

        self.run_async(run)

    def test_metadata_omit_and_unmatched_do_not_read(self):
        async def run():
            for selection, unmatched in (
                ("metadata", False),
                ("omit", False),
                ("body", True),
            ):
                hooks, transports = harness([selection], unmatched=unmatched)
                stream = Stream()
                async with hooks:
                    result = await hooks.context_compact_before(
                        payload(),
                        sources=ContentSources(
                            {INSTRUCTIONS: OwnedContentSource(stream)}
                        ),
                    )
                self.assertEqual(result.diagnostics, [])
                self.assertEqual((stream.reads, stream.closes), (0, 1))
                transport = next(iter(transports.values()))
                self.assertEqual(len(transport.requests), 0 if unmatched else 1)

        self.run_async(run)

    def test_outer_upload_deadline_cancels_before_event_publication(self):
        async def run():
            hooks, transports = harness(["body"])
            stream = Stream()
            cancelled = []

            async def upload(data):
                # Shorten the existing caller budget only after upload starts;
                # schema validation speed must not make this phase test flaky.
                budget.deadline = anyio.current_time() + 0.01
                try:
                    await anyio.sleep_forever()
                finally:
                    cancelled.append(True)

            async with hooks:
                with self.assertRaises(TimeoutError):
                    with anyio.fail_after(5) as budget:
                        await hooks.context_compact_before(
                            payload(),
                            sources=ContentSources(
                                {INSTRUCTIONS: OwnedContentSource(stream)}
                            ),
                            uploads={name: upload for name in transports},
                        )
            self.assertEqual(cancelled, [True])
            self.assertEqual(stream.closes, 1)
            self.assertTrue(
                all(not transport.requests for transport in transports.values())
            )

        self.run_async(run)

    def test_close_cancels_active_owned_upload_not_borrowed_transport(self):
        async def run():
            hooks, transports = harness(["body"])
            stream = Stream()
            started, finished = anyio.Event(), anyio.Event()

            async def upload(data):
                started.set()
                await anyio.sleep_forever()

            async def call():
                try:
                    await hooks.context_compact_before(
                        payload(),
                        sources=ContentSources(
                            {INSTRUCTIONS: OwnedContentSource(stream)}
                        ),
                        uploads={name: upload for name in transports},
                    )
                except HooksClosedError:
                    pass
                finally:
                    finished.set()

            async with anyio.create_task_group() as group:
                group.start_soon(call)
                await started.wait()
                await hooks.aclose()
                await finished.wait()
            self.assertEqual(stream.closes, 1)
            self.assertTrue(
                all(
                    not transport.requests and transport.closes == 0
                    for transport in transports.values()
                )
            )

        self.run_async(run)

    def test_observation_body_upload_is_owned_by_call(self):
        async def run():
            hooks, transports = harness(["body"], mode="observe")
            stream = Stream()
            writes = []

            async def upload(data):
                writes.append(data)
                return {
                    "ref": "urn:blob:observe",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with hooks:
                result = await hooks.context_compact_before(
                    payload(),
                    sources=ContentSources(
                        {INSTRUCTIONS: OwnedContentSource(stream)},
                        uploads={name: upload for name in transports},
                    ),
                )
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(writes, [b"hello"])
            self.assertEqual(stream.closes, 1)
            self.assertEqual(len(next(iter(transports.values())).notifications), 1)

        self.run_async(run)

    def test_generated_input_binds_indexed_source_without_wire_source_objects(self):
        from agenthooksprotocol.event import ContextCompactBeforeInput

        async def run():
            hooks, transports = harness(["body"])
            stream = Stream()
            item = payload()["instructions"]
            item["role"] = "user"
            original = ContextCompactBeforeInput(
                trigger="manual", items=[deepcopy(item)]
            )
            bound = original.bind_items_source(OwnedContentSource(stream), index=0)
            self.assertEqual(original.content_sources, {})
            self.assertTrue(bound.content_sources)
            self.assertEqual(bound.to_wire(), original.to_wire())
            writes = []

            async def upload(data):
                writes.append(data)
                return {
                    "ref": "urn:blob:indexed",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            async with hooks:
                result = await hooks.context_compact_before(
                    bound, uploads={name: upload for name in transports}
                )
            self.assertEqual(result.diagnostics, [])
            delivered = next(iter(transports.values())).requests[0]["params"]["event"][
                "items"
            ][0]
            self.assertEqual(delivered["body"]["ref"], "urn:blob:indexed")
            self.assertEqual(writes, [b"hello"])
            self.assertEqual((stream.reads, stream.closes), (2, 1))

        self.run_async(run)

    def test_generated_named_input_unused_source_is_closed(self):
        from agenthooksprotocol.event import ContextCompactBeforeInput

        async def run():
            hooks, transports = harness(["metadata"])
            stream = Stream()
            bound = ContextCompactBeforeInput(**payload()).bind_instructions_source(
                OwnedContentSource(stream)
            )
            async with hooks:
                result = await hooks.context_compact_before(bound)
            self.assertEqual(result.diagnostics, [])
            self.assertEqual((stream.reads, stream.closes), (0, 1))

        self.run_async(run)
