"""Deterministic upload fanout, destination isolation, and receipt reuse."""

from copy import deepcopy
import unittest

import anyio

from agenthooksprotocol import Attachment, Hooks
from test_inline_messages import Transport, harness, host, receipt


class GuardedTransport(Transport):
    def __init__(self, guard, replies=()):
        super().__init__(replies)
        self.guard = guard

    async def request(self, request):
        self.guard()
        return await super().request(request)


class UploadPlanningTests(unittest.TestCase):
    def run_async(self, test):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(test, backend=backend)

    def configured(
        self,
        selections,
        *,
        limit=8,
        replies=(),
        caps=None,
        event="context.compact.before",
        configure=None,
        guard=None,
    ):
        template, transports = harness(
            selections, replies, timeout=5000, caps=caps, event=event
        )
        config = deepcopy(template.config)
        capabilities = deepcopy(template.capabilities)
        if configure is not None:
            configure(config, capabilities)
        if guard is not None:
            transports = {
                name: GuardedTransport(guard, transport.replies)
                for name, transport in transports.items()
            }
        return Hooks(
            config,
            source="urn:test",
            capabilities=capabilities,
            transport=transports,
            max_concurrent_uploads=limit,
        ), transports

    def test_positive_integer_concurrency_limit(self):
        template, transports = harness(["body"])
        for limit in (0, -1, True, False, 1.5, "2", None):
            with self.subTest(limit=limit), self.assertRaises((ValueError, TypeError)):
                Hooks(
                    template.config,
                    source="urn:test",
                    capabilities=template.capabilities,
                    transport=transports,
                    max_concurrent_uploads=limit,
                )

    def test_uploads_overlap_at_cap_and_all_receipts_precede_interception(self):
        async def run():
            started, completed, reads = [], [], []
            releases = [anyio.Event() for _ in range(3)]
            two_started, three_started = anyio.Event(), anyio.Event()
            active = peak = 0
            data = b"shared"

            async def load():
                reads.append(True)
                return data

            def guard():
                self.assertEqual(len(completed), 3)

            hooks, transports = self.configured(["body"] * 3, limit=2, guard=guard)
            names = list(transports)

            def uploader(index):
                async def upload(value):
                    nonlocal active, peak
                    self.assertIs(value, data)
                    active += 1
                    peak = max(peak, active)
                    started.append(index)
                    if len(started) == 2:
                        two_started.set()
                    if len(started) == 3:
                        three_started.set()
                    await releases[index].wait()
                    active -= 1
                    completed.append(index)
                    return receipt(value, f"urn:blob:{index}")

                return upload

            async def release():
                await two_started.wait()
                self.assertEqual(len(started), 2)
                self.assertFalse(any(t.requests for t in transports.values()))
                releases[started[0]].set()
                await three_started.wait()
                self.assertFalse(any(t.requests for t in transports.values()))
                for gate in releases:
                    gate.set()

            payload = host(Attachment.lazy(load))
            # Repeated slots retain the exact owner, not copied loaders.
            payload["items"][0]["parts"].append(dict(payload["items"][0]["parts"][1]))
            async with hooks, anyio.create_task_group() as group:
                group.start_soon(release)
                with anyio.fail_after(3):
                    result = await hooks.context_compact_before(
                        payload,
                        uploads={name: uploader(i) for i, name in enumerate(names)},
                    )
            self.assertEqual(peak, 2)
            self.assertEqual(reads, [True])
            self.assertEqual(sorted(started), [0, 1, 2])
            self.assertEqual(result.diagnostics, [])
            for index, transport in enumerate(transports.values()):
                parts = transport.requests[0]["params"]["event"]["items"][0]["parts"]
                self.assertEqual(parts[1]["body"]["ref"], f"urn:blob:{index}")
                self.assertEqual(parts[1]["body"], parts[2]["body"])
            await result.aclose()

        self.run_async(run)

    def test_metadata_omit_and_unmatched_sources_remain_unread(self):
        async def run():
            closed = []

            async def load():
                self.fail("unselected bodies must not be read")

            async def close():
                closed.append(True)

            def configure(config, capabilities):
                config["hooks"][2]["subscriptions"][0]["events"] = [
                    "context.compact.after"
                ]

            hooks, transports = self.configured(
                ["metadata", "omit", "body"], configure=configure
            )

            async def upload(data):
                self.fail("unselected bodies must not be uploaded")

            async with hooks:
                result = await hooks.context_compact_before(
                    host(Attachment.lazy(load, aclose=close)),
                    uploads={name: upload for name in transports},
                )
            self.assertEqual(result.diagnostics, [])
            self.assertFalse(list(transports.values())[2].requests)
            await result.aclose()
            self.assertEqual(closed, [True])

        self.run_async(run)

    def test_upload_failure_is_deferred_to_its_subscription_policy(self):
        async def run():
            for policy in ("fail-open", "fail-closed"):
                completed = []

                def configure(config, capabilities):
                    config["hooks"][1]["subscriptions"][0]["failurePolicy"] = policy

                def guard():
                    self.assertEqual(set(completed), {0, 1, 2})

                hooks, transports = self.configured(
                    ["body"] * 3, configure=configure, guard=guard
                )
                names = list(transports)

                def uploader(index):
                    async def upload(data):
                        completed.append(index)
                        if index == 1:
                            raise RuntimeError("destination unavailable")
                        return receipt(data, f"urn:blob:{index}")

                    return upload

                async with hooks:
                    result = await hooks.context_compact_before(
                        host(Attachment.from_bytes(b"x")),
                        uploads={name: uploader(i) for i, name in enumerate(names)},
                    )
                self.assertEqual(
                    transports[names[0]].requests[0]["method"], "hooks/intercept"
                )
                self.assertFalse(transports[names[1]].requests)
                self.assertEqual(
                    transports[names[2]].requests[0]["method"],
                    "hooks/observe" if policy == "fail-closed" else "hooks/intercept",
                )
                self.assertEqual(result.decision == "deny", policy == "fail-closed")
                self.assertTrue(
                    any(d["backend"] == names[1] for d in result.diagnostics)
                )
                await result.aclose()

        self.run_async(run)

    def test_denial_reuses_uncalled_subscription_receipt_with_distinct_scope(self):
        async def run():
            calls = []
            denial = [{"type": "deny", "reason": "policy"}]

            def configure(config, capabilities):
                config["hooks"][0]["subscriptions"].append(
                    deepcopy(config["hooks"][0]["subscriptions"][0])
                )

            hooks, transports = self.configured(
                ["body"],
                replies=([denial],),
                caps={"effects": ["deny"]},
                configure=configure,
            )
            name = next(iter(transports))

            async def upload(data):
                calls.append(receipt(data, f"urn:blob:scope-{len(calls)}"))
                return calls[-1]

            async with hooks:
                result = await hooks.context_compact_before(
                    host(Attachment.from_bytes(b"x")), uploads={name: upload}
                )
            self.assertEqual(len(calls), 2)
            requests = transports[name].requests
            self.assertEqual(
                [r["method"] for r in requests], ["hooks/intercept", "hooks/observe"]
            )
            self.assertCountEqual(
                [
                    r["params"]["event"]["items"][0]["parts"][1]["body"]["ref"]
                    for r in requests
                ],
                [r["ref"] for r in calls],
            )
            self.assertEqual(result.decision, "deny")
            self.assertEqual(result.diagnostics, [])
            await result.aclose()

        self.run_async(run)

    def test_removed_attachment_tolerates_early_committed_upload(self):
        async def run():
            uploads, cleanup = [], []
            effects = [
                {
                    "type": "modify",
                    "target": "prompt",
                    "operation": "replace",
                    "value": [],
                }
            ]

            def guard():
                self.assertEqual(uploads, [b"x"])

            hooks, transports = self.configured(
                ["metadata", "body"],
                replies=([effects], []),
                caps={
                    "effects": ["modify"],
                    "modify": {"prompt": {"replace": True, "merge": True}},
                },
                event="turn.start",
                guard=guard,
            )

            async def load():
                return b"x"

            async def close():
                cleanup.append(True)

            async def upload(data):
                uploads.append(data)
                return receipt(data)

            payload = host(Attachment.lazy(load, aclose=close))
            payload.update(trigger="user", turn={"id": "turn"})
            async with hooks:
                result = await hooks.turn_start(
                    payload, uploads={list(transports)[1]: upload}
                )
            self.assertEqual(result.event["items"], [])
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(cleanup, [True])
            self.assertEqual(
                list(transports.values())[1].requests[0]["params"]["event"]["items"], []
            )
            await result.aclose()

        self.run_async(run)

    def test_cancellation_joins_all_uploads_and_closes_owner(self):
        async def run():
            started, stopped, cleanup = [], [], []
            all_started = anyio.Event()
            hooks, transports = self.configured(["body", "body"], limit=2)

            async def load():
                return b"x"

            async def close():
                cleanup.append(True)

            owner = Attachment.lazy(load, aclose=close)

            def uploader(name):
                async def upload(data):
                    started.append(name)
                    if len(started) == 2:
                        all_started.set()
                    try:
                        await anyio.sleep_forever()
                    finally:
                        stopped.append(name)

                return upload

            async def dispatch():
                await hooks.context_compact_before(
                    host(owner), uploads={name: uploader(name) for name in transports}
                )

            async with hooks:
                with anyio.fail_after(3):
                    async with anyio.create_task_group() as group:
                        group.start_soon(dispatch)
                        await all_started.wait()
                        self.assertFalse(any(t.requests for t in transports.values()))
                        group.cancel_scope.cancel()
                self.assertEqual(set(stopped), set(transports))
                self.assertEqual(cleanup, [True])
                self.assertTrue(owner._closed)

        self.run_async(run)


if __name__ == "__main__":
    unittest.main()
