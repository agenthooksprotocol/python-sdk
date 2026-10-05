"""Public API tests: no private network bridge and both AnyIO backends."""

from copy import deepcopy
import json
import sys
import unittest

import anyio

from agenthooksprotocol._hooks import Hooks
from agenthooksprotocol.runtime import ProtocolError
from agenthooksprotocol.transports import StdioTransport
from test_interop import request


def config(*, policy="fail-open", mode="intercept", count=1):
    sub = {"events": ["tool.before"], "mode": mode, "content": {"default": "metadata"}}
    if mode == "intercept":
        sub.update(timeoutMs=1000, failurePolicy=policy)
    return {
        "protocolVersion": "draft",
        "hooks": [
            {
                "id": "org.example.hook",
                "transport": {
                    "type": "stdio",
                    "command": sys.executable,
                    "lifecycle": "persistent",
                },
                "subscriptions": [deepcopy(sub) for _ in range(count)],
            }
        ],
    }


def capabilities():
    return {
        "tool.before": {
            "modes": ["intercept", "observe"],
            "capabilities": request()["params"]["capabilities"],
        }
    }


class MemoryTransport:
    def __init__(self, *effects):
        self.effects = list(effects)
        self.requests = []
        self.notifications = []
        self.closed = False

    async def request(self, message):
        self.requests.append(deepcopy(message))
        effects = self.effects.pop(0)
        if isinstance(effects, Exception):
            raise effects
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"protocolVersion": "draft", "effects": effects},
        }

    async def notify(self, message):
        self.notifications.append(deepcopy(message))

    async def aclose(self):
        self.closed = True


class PublicHooksTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_constructor_checks_registration_and_explicit_modes(self):
        with self.assertRaises(ProtocolError):
            Hooks({}, source="urn:test", capabilities={})
        with self.assertRaises(ProtocolError):
            Hooks(
                config(),
                source="urn:test",
                capabilities={"tool.before": {"effects": []}},
            )
        with self.assertRaises(ProtocolError):
            Hooks(config(), source="relative", capabilities=capabilities())

    def test_serial_input_invalidation_and_decode_failure(self):
        async def run():
            transport = MemoryTransport(
                [{"type": "allow"}, {"type": "return", "value": 9}],
                [
                    {
                        "type": "modify",
                        "target": "input",
                        "operation": "replace",
                        "value": {"changed": True},
                    }
                ],
            )
            async with Hooks(
                config(count=2),
                source="urn:host",
                capabilities=capabilities(),
                transport=transport,
            ) as hooks:
                result = await hooks.dispatch(
                    "tool.before", request()["params"]["event"], event_id="event-one"
                )
                self.assertEqual(result.input, {"changed": True})
                self.assertEqual(result.state["authorization"], "pending")
                self.assertNotIn("result", result.state)
                self.assertEqual(len(result.accepted_responses), 2)
                self.assertEqual({r["id"] for r in transport.requests}, {"event-one"})
                self.assertEqual(
                    transport.requests[1]["params"]["state"]["permission"], "allow"
                )

                class BadCodec:
                    def decode(self, value):
                        value.clear()
                        raise ValueError("not my host model")

                with self.assertRaises(ValueError):
                    result.decode_input(BadCodec())
                self.assertEqual(result.input, {"changed": True})
                self.assertEqual(len(result.accepted_responses), 2)
            self.assertFalse(transport.closed)

        self.run_async(run)

    def test_narrowing_and_failure_policy_once(self):
        async def run():
            transport = MemoryTransport(RuntimeError("offline"), [{"type": "allow"}])
            hooks = Hooks(
                config(policy="fail-closed", count=2),
                source="urn:host",
                capabilities=capabilities(),
                transport=transport,
            )
            with self.assertRaises(ProtocolError):
                await hooks.dispatch(
                    "tool.before",
                    request()["params"]["event"],
                    capabilities={"effects": ["flow"]},
                )
            result = await hooks.dispatch("tool.before", request()["params"]["event"])
            self.assertEqual(result.decision, "deny")
            self.assertEqual(len(result.diagnostics), 1)
            self.assertEqual(len(transport.requests), 1)
            await hooks.aclose()

        self.run_async(run)

    def test_fail_open_and_ask_dominates_allow(self):
        async def run():
            transport = MemoryTransport(
                RuntimeError("offline"), [{"type": "ask"}], [{"type": "allow"}]
            )
            hooks = Hooks(
                config(count=3),
                source="urn:host",
                capabilities=capabilities(),
                transport=transport,
            )
            result = await hooks.dispatch("tool.before", request()["params"]["event"])
            self.assertEqual(result.decision, "ask")
            self.assertEqual(len(result.accepted_responses), 2)
            self.assertEqual(len(result.diagnostics), 1)

        self.run_async(run)

    def test_pending_candidate_remains_available_without_authorization(self):
        async def run():
            transport = MemoryTransport([{"type": "return", "value": {"ok": True}}])
            hooks = Hooks(
                config(),
                source=request()["params"]["event"]["source"],
                capabilities=capabilities(),
                transport=transport,
            )
            result = await hooks.exchange(request())
            self.assertEqual(result.permission, "none")
            self.assertEqual(result.candidate, {"value": {"ok": True}})
            self.assertEqual(result.state["authorization"], "pending")
            self.assertNotIn("executed", result.state)
            self.assertNotIn("result", result.state)
            initial = {
                "permission": "none",
                "candidate": {"value": 1, "provenance": {"source": "earlier"}},
            }
            transport.effects.append([])
            result = await hooks.dispatch(
                "tool.before", request()["params"]["event"], initial_state=initial
            )
            self.assertEqual(result.candidate, initial["candidate"])
            await hooks.aclose()

        self.run_async(run)

    def test_exact_notify_preserves_envelope_and_has_no_effect_authority(self):
        async def run():
            class Answering(MemoryTransport):
                async def notify(self, message):
                    self.notifications.append(deepcopy(message))
                    return {"effects": [{"type": "deny", "reason": "ignored"}]}

            transport = Answering()
            note = {
                "jsonrpc": "2.0",
                "method": "hooks/observe",
                "params": {
                    "protocolVersion": "draft",
                    "event": request()["params"]["event"],
                },
            }
            original = deepcopy(note)
            async with Hooks(
                config(mode="observe"),
                source=note["params"]["event"]["source"],
                capabilities=capabilities(),
                transport=transport,
            ) as hooks:
                self.assertEqual(await hooks.notify(note), [])
                self.assertEqual(transport.notifications, [original])
                self.assertEqual(note, original)
                invalid = deepcopy(note)
                invalid["id"] = "must-be-notification"
                with self.assertRaises(ProtocolError):
                    await hooks.notify(invalid)
                self.assertEqual(len(transport.notifications), 1)

        self.run_async(run)

    def test_low_level_entrypoints_cannot_expand_authority(self):
        async def run():
            req = request()
            transport = MemoryTransport([])
            declared = capabilities()
            declared["tool.before"]["capabilities"] = {"effects": ["message"]}
            async with Hooks(
                config(),
                source=req["params"]["event"]["source"],
                capabilities=declared,
                transport=transport,
            ) as hooks:
                with self.assertRaises(ProtocolError):
                    hooks.begin(req)
                with self.assertRaises(ProtocolError):
                    await hooks.exchange(req)
                req["params"]["capabilities"] = {"effects": ["message"]}
                conflicting = deepcopy(req)
                conflicting["params"]["event"]["source"] = "urn:conflicting"
                with self.assertRaises(ProtocolError):
                    await hooks.exchange(conflicting)
                note = {
                    "jsonrpc": "2.0",
                    "method": "hooks/observe",
                    "params": {
                        "protocolVersion": "draft",
                        "event": conflicting["params"]["event"],
                    },
                }
                with self.assertRaises(ProtocolError):
                    await hooks.notify(note)
                self.assertEqual(transport.requests, [])
                self.assertEqual(transport.notifications, [])
                self.assertIsNotNone(await hooks.exchange(req))
            observed = capabilities()
            observed["tool.before"]["modes"] = ["observe"]
            async with Hooks(
                config(mode="observe"),
                source=req["params"]["event"]["source"],
                capabilities=observed,
                transport=transport,
            ) as hooks:
                with self.assertRaises(ProtocolError):
                    hooks.begin(req)

        self.run_async(run)

    def test_shared_lineage_rejects_cycles_and_reparenting_before_delivery(self):
        async def run():
            for mode in ("intercept", "observe"):
                transport = MemoryTransport([], [])
                async with Hooks(
                    config(mode=mode),
                    source="urn:host",
                    capabilities=capabilities(),
                    transport=transport,
                ) as hooks:
                    event = request()["params"]["event"]
                    event["parentEventId"] = "B"
                    await hooks.dispatch("tool.before", event, event_id="A")
                    cyclic = deepcopy(event)
                    cyclic["parentEventId"] = "A"
                    with self.assertRaises(ProtocolError):
                        await hooks.dispatch("tool.before", cyclic, event_id="B")
                    changed = deepcopy(event)
                    changed["parentEventId"] = "C"
                    with self.assertRaises(ProtocolError):
                        await hooks.dispatch("tool.before", changed, event_id="A")
                    await hooks.wait()
                    self.assertEqual(
                        len(
                            transport.requests
                            if mode == "intercept"
                            else transport.notifications
                        ),
                        1,
                    )

        self.run_async(run)

    def test_bearer_environment_and_reference_resolution(self):
        from unittest.mock import patch

        registration = config()
        backend = registration["hooks"][0]
        backend["transport"] = {"type": "http", "url": "https://example.test"}
        backend["authentication"] = {"type": "bearer", "tokenEnv": "AHP_TEST_BEARER"}
        with patch.dict("os.environ", {"AHP_TEST_BEARER": "test-token"}):
            hooks = Hooks(registration, source="urn:host", capabilities=capabilities())
        self.assertEqual(
            hooks._headers[backend["id"]]["Authorization"], "Bearer test-token"
        )
        backend["authentication"] = {"type": "bearer", "tokenRef": "vault:hook"}
        hooks = Hooks(
            registration,
            source="urn:host",
            capabilities=capabilities(),
            resolve_credential=lambda ref: "ref-token",
        )
        self.assertEqual(
            hooks._headers[backend["id"]]["Authorization"], "Bearer ref-token"
        )

    def test_pending_stages_cancel_and_fallback(self):
        async def run():
            transport = MemoryTransport([{"type": "message", "text": "private"}])
            hooks = Hooks(
                config(),
                source=request()["params"]["event"]["source"],
                capabilities=capabilities(),
                transport=transport,
            )
            pending = hooks.begin(request())
            await pending.acquire()
            self.assertIsNone(pending.result)
            pending.cancel()
            self.assertIsNone(pending.accept())
            other = hooks.begin(request())
            result = other.accept(fallback=True)
            self.assertEqual(result.state["messages"], [])
            self.assertIsNone(other.accept())

        self.run_async(run)

    def test_observation_notification_silent(self):
        async def run():
            transport = MemoryTransport()
            hooks = Hooks(
                config(mode="observe"),
                source="urn:host",
                capabilities=capabilities(),
                transport=transport,
            )
            result = await hooks.dispatch("tool.before", request()["params"]["event"])
            self.assertEqual(result.accepted_responses, [])
            await hooks.wait()
            self.assertEqual(len(transport.notifications), 1)
            self.assertNotIn("id", transport.notifications[0])
            await hooks.aclose()

        self.run_async(run)

    def test_stdio_cancellation_reaps_before_next_request(self):
        async def run():
            code = 'import sys,json,time\nfor line in sys.stdin:\n r=json.loads(line)\n if r["id"]=="slow": time.sleep(30)\n print(json.dumps({"id":r["id"]}),flush=True)'
            transport = StdioTransport(sys.executable, ["-u", "-c", code])
            with anyio.move_on_after(0.1) as scope:
                await transport.request({"id": "slow"})
            self.assertTrue(scope.cancel_called)
            self.assertIsNone(transport._process)
            reply = await transport.request({"id": "next"})
            self.assertEqual(reply["id"], "next")
            await transport.aclose()

        self.run_async(run)

    def test_native_projection_never_bypasses_interception(self):
        async def run():
            for native in (None, {}, False, {"secret": "opaque"}):
                for include in (False, True):
                    registration = config()
                    registration["hooks"][0]["subscriptions"][0]["includeNative"] = (
                        include
                    )
                    event = request()["params"]["event"]
                    if native is not None:
                        event["native"] = native
                    transport = MemoryTransport([{"type": "deny", "reason": "policy"}])
                    async with Hooks(
                        registration,
                        source="urn:host",
                        capabilities=capabilities(),
                        transport=transport,
                    ) as hooks:
                        result = await hooks.dispatch("tool.before", event)
                    self.assertEqual(result.decision, "deny")
                    self.assertEqual(len(transport.requests), 1)
                    sent = transport.requests[0]["params"]["event"]
                    self.assertEqual("native" in sent, include and native is not None)

        self.run_async(run)

    def test_unknown_kind_filter_hints_do_not_drop_events(self):
        async def run():
            for kind in (None, "unknown", "org.new.Kind"):
                registration = config()
                registration["hooks"][0]["subscriptions"][0]["filters"] = {
                    "toolKinds": ["shell"],
                    "paths": ["not-the-path"],
                }
                event = request()["params"]["event"]
                event["tool"].pop("kind", None)
                if kind is not None:
                    event["tool"]["kind"] = kind
                transport = MemoryTransport([{"type": "deny", "reason": "policy"}])
                async with Hooks(
                    registration,
                    source="urn:host",
                    capabilities=capabilities(),
                    transport=transport,
                ) as hooks:
                    result = await hooks.dispatch("tool.before", event)
                self.assertEqual(result.decision, "deny")

        self.run_async(run)

    def test_observation_projection_and_completed_records_are_released(self):
        async def run():
            transport = MemoryTransport()
            async with Hooks(
                config(mode="observe"),
                source="urn:host",
                capabilities=capabilities(),
                transport=transport,
            ) as hooks:
                event = request()["params"]["event"]
                event["native"] = {"secret": "opaque"}
                for _ in range(20):
                    await hooks.dispatch("tool.before", event)
                    await hooks.wait()
                    self.assertEqual(hooks._observations, [])
                self.assertTrue(
                    all(
                        "native" not in note["params"]["event"]
                        for note in transport.notifications
                    )
                )

        self.run_async(run)

    def test_owned_observers_do_not_gate_and_close_cancels(self):
        async def run():
            started, stopped = anyio.Event(), anyio.Event()

            class Hanging(MemoryTransport):
                async def notify(self, message):
                    started.set()
                    try:
                        await anyio.sleep_forever()
                    finally:
                        stopped.set()

            transport = Hanging()
            async with Hooks(
                config(mode="observe"),
                source="urn:host",
                capabilities=capabilities(),
                transport=transport,
            ) as hooks:
                with anyio.fail_after(1):
                    result = await hooks.dispatch(
                        "tool.before", request()["params"]["event"]
                    )
                    await started.wait()
                self.assertNotIn("executed", result.state)
            self.assertTrue(stopped.is_set())

        self.run_async(run)

    def test_wait_reports_observation_failure(self):
        async def run():
            class Broken(MemoryTransport):
                async def notify(self, message):
                    raise RuntimeError("unavailable")

            hooks = Hooks(
                config(mode="observe"),
                source="urn:host",
                capabilities=capabilities(),
                transport=Broken(),
            )
            result = await hooks.dispatch("tool.before", request()["params"]["event"])
            self.assertEqual(len(await hooks.wait()), 1)
            self.assertEqual(result.diagnostics[0]["error"], "RuntimeError")
            await hooks.aclose()

        self.run_async(run)

    def test_stream_upload_eof_and_credential_isolation(self):
        import hashlib
        import httpx
        from agenthooksprotocol.transports.http import HTTPTransport

        async def run():
            calls = []

            async def handler(req):
                data = await req.aread()
                calls.append(req)
                return httpx.Response(
                    201,
                    json={
                        "ref": "urn:content",
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                )

            async def body():
                yield b"ab"
                yield b"cd"

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
                headers={"Authorization": "event-secret"},
            ) as client:
                transport = HTTPTransport(
                    "https://event.test",
                    client=client,
                    headers={"Authorization": "event-secret"},
                )
                descriptor = await transport.upload(
                    "https://receiver.test",
                    body(),
                    size=4,
                    sha256=hashlib.sha256(b"abcd").hexdigest(),
                )
                self.assertEqual(descriptor["size"], 4)
                self.assertNotIn("authorization", calls[0].headers)
                with self.assertRaises(ProtocolError):
                    await transport.upload(
                        "https://receiver.test",
                        body(),
                        size=5,
                        sha256=hashlib.sha256(b"abcd").hexdigest(),
                    )

                async def unread():
                    raise AssertionError("metadata must not read bytes")
                    yield b""

                self.assertIsNone(
                    await transport.upload(
                        "https://receiver.test", unread(), selection="metadata"
                    )
                )

        self.run_async(run)

    def test_http_observer_effect_ack_is_diagnostic_only(self):
        import httpx
        from agenthooksprotocol.transports.http import HTTPTransport

        async def run():
            def handler(request):
                return httpx.Response(
                    200,
                    json={
                        "result": {"effects": [{"type": "deny", "reason": "malicious"}]}
                    },
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                transport = HTTPTransport("https://example.test/hooks", client=client)
                async with Hooks(
                    config(mode="observe"),
                    source="urn:host",
                    capabilities=capabilities(),
                    transport=transport,
                ) as hooks:
                    result = await hooks.dispatch(
                        "tool.before", request()["params"]["event"]
                    )
                    diagnostics = await hooks.wait()
                    self.assertEqual(result.decision, "allow")
                    self.assertEqual(result.accepted_responses, [])
                    self.assertEqual(len(diagnostics), 1)
                    self.assertEqual(diagnostics[0]["error"], "ProtocolError")

        self.run_async(run)

    def test_http_borrowed_client_and_silent_notification(self):
        import httpx
        from agenthooksprotocol.transports.http import HTTPTransport

        async def run():
            def handler(request):
                message = json.loads(request.content)
                return (
                    httpx.Response(200, json={"id": message["id"]})
                    if "id" in message
                    else httpx.Response(204)
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler)
            ) as client:
                transport = HTTPTransport("https://example.test/hooks", client=client)
                self.assertEqual(await transport.request({"id": "one"}), {"id": "one"})
                await transport.notify({"method": "hooks/observe"})
                await transport.aclose()
                self.assertFalse(client.is_closed)

        self.run_async(run)
