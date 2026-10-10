"""Accepted SDK ergonomics and operation contracts, on both native runtimes."""

import json
import unittest

import anyio

from agenthooksprotocol import Hooks, Permission, capability, effect, event, state
from agenthooksprotocol.diagnostics import Code
from agenthooksprotocol.runtime import ProtocolError
from test_public_hooks import MemoryTransport, config


def facts(**extra):
    return event.ToolBeforeInput(
        call_id="call-1",
        name="shell",
        input={"command": "original"},
        path="native",
        origin="native",
        **extra,
    )


class UnificationTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_generated_declarations_are_immutable_and_explicit(self):
        base = capability.intercept().deny()
        extended = base.modify_input(replace=True)
        self.assertEqual(base.to_wire()["modes"], ["intercept", "observe"])
        self.assertNotIn("modify", base.to_wire()["capabilities"])
        caps = extended.to_wire()["capabilities"]
        self.assertTrue(caps["modify"]["input"]["replace"])
        self.assertFalse(caps["modify"]["input"].get("merge", False))
        self.assertEqual(set(caps["effects"]), {"deny", "modify"})
        with self.assertRaises(ValueError):
            base.modify_input()
        with self.assertRaises(ValueError):
            base.modify_input(replace=False)
        with self.assertRaises(ValueError):
            capability.observe().deny()
        self.assertEqual(capability.observe().to_wire()["modes"], ["observe"])
        self.assertNotIn("elicitation", base.to_wire()["capabilities"])

    def test_generated_flow_counts_are_safe_and_required(self):
        base = capability.intercept()
        for field in (
            "continuation_count",
            "remaining_continuations",
            "max_continuations",
        ):
            for value in (-1, 9007199254740992, True, False, 0.5):
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    base.flow(operations=["stop"], **{field: value})
        for counts in ({}, {"continuation_count": 0}, {"remaining_continuations": 0}):
            with self.subTest(counts=counts), self.assertRaises(ValueError):
                base.flow(operations=["continue"], **counts)
        for value in (0, 9007199254740991):
            caps = base.flow(
                operations=["continue"],
                continuation_count=value,
                remaining_continuations=value,
                max_continuations=value,
            ).to_wire()["capabilities"]["flow"]
            self.assertEqual(caps["continuationCount"], value)
            self.assertEqual(caps["remainingContinuations"], value)
            self.assertEqual(caps["maxContinuations"], value)
        self.assertEqual(
            base.flow(operations=["stop"]).to_wire()["capabilities"]["flow"][
                "operations"
            ],
            ["stop"],
        )

    def test_permission_input_and_host_facts_share_canonical_settlement(self):
        async def run():
            transport = MemoryTransport([effect.replace_input({"command": "reviewed"})])
            async with Hooks(
                config(),
                source="urn:host",
                transport=transport,
                capabilities={
                    capability.Event.TOOL_BEFORE: capability.intercept().modify_input(
                        replace=True
                    )
                },
            ) as hooks:
                original = facts(
                    id="host-id", time="2026-01-01T00:00:00Z", parent_event_id="parent"
                )
                result = await hooks.tool_before(
                    original, initial_state=state.initial(Permission.ALLOW)
                )
                self.assertEqual(result.permission, Permission.NONE)
                self.assertIsInstance(result.permission, Permission)
                self.assertEqual(result.input, {"command": "reviewed"})
                self.assertFalse(result.interrupted)
                self.assertEqual(result.event["id"], "host-id")
                self.assertEqual(result.event["time"], "2026-01-01T00:00:00Z")
                self.assertEqual(result.event["parentEventId"], "parent")
                self.assertEqual(original["input"], {"command": "original"})
                self.assertEqual(
                    transport.requests[0]["params"]["event"]["call"]["id"], "call-1"
                )
                self.assertEqual(
                    result.accepted_response["result"]["effects"][0]["type"], "modify"
                )

        self.run_async(run)

    def test_initial_no_candidate_and_null_candidate_are_distinct(self):
        self.assertIsNone(state.initial(Permission.NONE)["candidate"])
        candidate = state.Candidate(value=None)
        self.assertEqual(
            state.initial(Permission.ALLOW, candidate=candidate)["candidate"],
            {"value": None},
        )

    def test_generated_effects_do_not_authorize_their_own_response(self):
        async def run():
            transport = MemoryTransport(
                [effect.deny(reason="policy"), effect.replace_input({"bad": True})]
            )
            async with Hooks(
                config(),
                source="urn:host",
                transport=transport,
                capabilities={"tool.before": capability.intercept().deny()},
            ) as hooks:
                result = await hooks.tool_before(facts())
                self.assertEqual(result.permission, Permission.NONE)
                self.assertEqual(result.input, {"command": "original"})
                self.assertEqual(result.accepted_responses, [])
                self.assertEqual(result.diagnostics[0]["code"], Code.PROTOCOL_REJECTION)
                with self.assertRaises(ProtocolError):
                    await hooks.tool_before(
                        facts(), capabilities={"effects": ["allow", "deny"]}
                    )

        self.run_async(run)

    def test_diagnostic_causes_are_distinct_attributed_and_redacted(self):
        async def run():
            class Reply(MemoryTransport):
                async def request(self, message):
                    return {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {
                            "code": -32000,
                            "message": "SECRET",
                            "data": {"token": "SECRET"},
                        },
                    }

            class Malformed(Reply):
                async def request(self, message):
                    reply = await super().request(message)
                    reply["error"]["code"] = "bad"
                    return reply

            class WrongIdentity(Reply):
                async def request(self, message):
                    return {
                        "jsonrpc": "2.0",
                        "id": "wrong-id",
                        "result": {"protocolVersion": "draft", "effects": []},
                    }

            for transport, expected in (
                (Reply(), Code.REMOTE_RPC),
                (Malformed(), Code.PROTOCOL_REJECTION),
                (WrongIdentity(), Code.PROTOCOL_REJECTION),
                (MemoryTransport(TimeoutError("SECRET")), Code.DEADLINE_EXCEEDED),
                (MemoryTransport(OSError("SECRET")), Code.TRANSPORT),
            ):
                async with Hooks(
                    config(policy="fail-closed"),
                    source="urn:host",
                    transport=transport,
                    capabilities={"tool.before": capability.intercept().deny()},
                ) as hooks:
                    result = await hooks.tool_before(facts())
                    diagnostic = result.diagnostics[0]
                    self.assertEqual(diagnostic["code"], expected)
                    self.assertEqual(diagnostic["subscription"], 0)
                    self.assertEqual(diagnostic["backend"], "org.example.hook")
                    self.assertEqual(diagnostic["failure_policy"], "fail-closed")
                    self.assertTrue(diagnostic["synthetic_denial"])
                    self.assertEqual(result.permission, Permission.DENY)
                    self.assertNotIn("SECRET", json.dumps(result.diagnostics))

        self.run_async(run)

    def test_outer_budget_includes_readiness_queue_without_delivery(self):
        async def run():
            transport = MemoryTransport([])
            hooks = Hooks(
                config(),
                source="urn:host",
                transport=transport,
                capabilities={"tool.before": capability.intercept().deny()},
            )
            started, release = anyio.Event(), anyio.Event()

            async def block_readiness():
                async with hooks._ready_lock:
                    started.set()
                    await release.wait()

            async with anyio.create_task_group() as group:
                group.start_soon(block_readiness)
                await started.wait()
                try:
                    with self.assertRaises(TimeoutError):
                        with anyio.fail_after(0.05):
                            await hooks.tool_before(facts())
                finally:
                    release.set()
            self.assertEqual(transport.requests, [])
            self.assertEqual(hooks._operations, [])
            await hooks.aclose()

        self.run_async(run)

    def test_bad_candidate_encoding_fails_before_delivery(self):
        async def run():
            transport = MemoryTransport([])
            async with Hooks(
                config(),
                source="urn:host",
                transport=transport,
                capabilities={"tool.before": capability.intercept().deny()},
            ) as hooks:
                with self.assertRaises(ValueError):
                    state.Candidate(value=object())
                # Post-construction dictionary mutation is deliberately not an
                # SDK decode entrypoint; dispatch must still guard delivery.
                initial = state.initial(
                    Permission.ALLOW, candidate=state.Candidate(value=None)
                )
                initial["candidate"]["value"] = object()
                with self.assertRaises(ProtocolError):
                    await hooks.tool_before(facts(), initial_state=initial)
                self.assertEqual(transport.requests, [])

        self.run_async(run)

    def test_single_remaining_budget_survives_provider_and_safe_retry(self):
        async def run():
            import httpx
            from agenthooksprotocol.auth import (
                AuthenticatedHTTPTransport,
                BearerCredential,
            )

            deadlines, messages = [], []
            stopped = anyio.Event()

            class Provider:
                async def credential(self, context):
                    deadlines.append(anyio.current_effective_deadline())
                    await anyio.sleep(0.01)
                    return BearerCredential("first")

                async def challenge(self, context, challenge):
                    deadlines.append(anyio.current_effective_deadline())
                    await anyio.sleep(0.01)
                    return BearerCredential("second")

            async def handle(req):
                deadlines.append(anyio.current_effective_deadline())
                messages.append(req.content)
                if len(messages) == 1:
                    return httpx.Response(401, headers={"www-authenticate": "Bearer"})
                try:
                    await anyio.sleep_forever()
                finally:
                    stopped.set()

            cfg = config()
            backend = cfg["hooks"][0]
            backend["transport"] = {"type": "http", "url": "https://event.test"}
            backend["authentication"] = {"type": "bearer", "tokenRef": "host:key"}
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend=backend,
                    auth_provider=Provider(),
                    client=client,
                )
                async with Hooks(
                    cfg,
                    source="urn:host",
                    transport=transport,
                    capabilities={"tool.before": capability.intercept().deny()},
                ) as hooks:
                    with self.assertRaises(TimeoutError):
                        with anyio.fail_after(0.25) as scope:
                            await hooks.tool_before(facts())
                    self.assertEqual(len(messages), 2)
                    self.assertEqual(messages[0], messages[1])
                    self.assertTrue(stopped.is_set())
                    self.assertTrue(
                        all(deadline == scope.deadline for deadline in deadlines)
                    )
                    self.assertEqual(hooks._operations, [])
                self.assertFalse(client.is_closed)

        self.run_async(run)

    def test_explicit_interruption_never_becomes_fail_open_permission(self):
        async def run():
            from agenthooksprotocol import OperationCancelledError

            cfg = config()
            cfg["hooks"][0]["subscriptions"].extend(
                config(mode="observe")["hooks"][0]["subscriptions"]
            )
            transport = MemoryTransport(OperationCancelledError("interrupted"))
            async with Hooks(
                cfg,
                source="urn:host",
                transport=transport,
                capabilities={"tool.before": capability.intercept().deny()},
            ) as hooks:
                with self.assertRaises(OperationCancelledError) as caught:
                    await hooks.tool_before(
                        facts(), initial_state=state.initial(Permission.ALLOW)
                    )
                self.assertEqual(caught.exception.code, Code.CANCELLED)
                self.assertEqual(transport.notifications, [])
                self.assertEqual(hooks._operations, [])

        self.run_async(run)

    def test_content_stage_preserves_transport_cause(self):
        async def run():
            from agenthooksprotocol.auth import TransportFailure
            from agenthooksprotocol.content import Attachment, OwnedAttachment
            from test_owned_content_hooks import harness, payload, Stream

            hooks, transports = harness(["body"])
            stream = Stream()
            value = payload()
            part = value["items"][0]["parts"][0]
            part.pop("size")
            part.update(selection="body", body=OwnedAttachment(Attachment(stream)))

            async def upload(data):
                raise TransportFailure("SECRET")

            async with hooks:
                result = await hooks.context_compact_before(
                    value,
                    uploads={name: upload for name in transports},
                )
            self.assertEqual(result.diagnostics[0]["stage"], "content")
            self.assertEqual(result.diagnostics[0]["code"], Code.TRANSPORT)
            self.assertEqual(stream.closes, 1)
            self.assertNotIn("SECRET", json.dumps(result.diagnostics))

        self.run_async(run)

    def test_deadline_during_shielded_cleanup_cannot_publish_allow(self):
        async def run():
            from agenthooksprotocol.content import ContentSources, OwnedContentSource
            from test_owned_content_hooks import harness, payload, INSTRUCTIONS, Stream

            class SlowClose(Stream):
                async def aclose(self):
                    await anyio.sleep(0.2)
                    self.closes += 1

            hooks, transports = harness(["metadata"])
            stream = SlowClose()
            async with hooks:
                with self.assertRaises(TimeoutError):
                    with anyio.fail_after(0.1):
                        await hooks.context_compact_before(
                            payload(),
                            initial_state=state.initial(Permission.ALLOW),
                            sources=ContentSources(
                                {INSTRUCTIONS: OwnedContentSource(stream)}
                            ),
                        )
                self.assertEqual(hooks._operations, [])
            self.assertEqual(stream.closes, 1)
            self.assertEqual(stream.reads, 0)

        self.run_async(run)

    def test_auth_provider_cancellation_never_becomes_delivery_failure(self):
        async def run():
            import httpx
            from agenthooksprotocol import OperationCancelledError
            from agenthooksprotocol.auth import (
                AuthenticatedHTTPTransport,
                BearerCredential,
                EnvironmentAuthProvider,
            )

            class Cancelling:
                async def credential(self, context):
                    context.cancellation.cancel()
                    return BearerCredential("unused")

                async def challenge(self, context, challenge):
                    raise AssertionError("No challenge should be reached")

            async def resolve(ref):
                raise OperationCancelledError("Resolver interrupted")

            cfg = config()
            backend = cfg["hooks"][0]
            backend["transport"] = {"type": "http", "url": "https://event.test"}
            backend["authentication"] = {"type": "bearer", "tokenRef": "vault:key"}
            seen = []

            async def handle(request):
                seen.append(request)
                raise AssertionError("No HTTP request should be reached")

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                for provider in (
                    Cancelling(),
                    EnvironmentAuthProvider(resolve_credential=resolve),
                ):
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend=backend,
                        auth_provider=provider,
                        client=client,
                    )
                    async with Hooks(
                        cfg,
                        source="urn:host",
                        transport=transport,
                        capabilities={"tool.before": capability.intercept().deny()},
                    ) as hooks:
                        with self.assertRaises(OperationCancelledError):
                            await hooks.tool_before(
                                facts(), initial_state=state.initial(Permission.ALLOW)
                            )
            self.assertEqual(seen, [])

        self.run_async(run)

    def test_borrowed_http_transport_diagnostic_categories(self):
        async def run():
            import httpx
            from agenthooksprotocol.transports.http import HTTPTransport

            for kind, expected in (
                ("malformed", Code.PROTOCOL_REJECTION),
                ("timeout", Code.DEADLINE_EXCEEDED),
                ("rpc", Code.REMOTE_RPC),
            ):

                async def handle(request):
                    if kind == "timeout":
                        raise httpx.ReadTimeout("SECRET")
                    if kind == "malformed":
                        return httpx.Response(200, content=b"not JSON")
                    message = json.loads(request.content)
                    return httpx.Response(
                        400,
                        json={
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "error": {"code": -32000, "message": "SECRET"},
                        },
                    )

                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handle)
                ) as client:
                    transport = HTTPTransport("https://event.test", client=client)
                    async with Hooks(
                        config(),
                        source="urn:host",
                        transport=transport,
                        capabilities={"tool.before": capability.intercept().deny()},
                    ) as hooks:
                        result = await hooks.tool_before(facts())
                    self.assertEqual(result.diagnostics[0]["code"], expected)
                    self.assertNotIn("SECRET", json.dumps(result.diagnostics))

        self.run_async(run)
