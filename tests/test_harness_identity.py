"""Harness identity is configured once and required on every wire event."""

from copy import deepcopy
import inspect
import unittest

import anyio

from agenthooksprotocol import Hooks, capability, event
from agenthooksprotocol.runtime import ProtocolError, Validator
from test_interop import request
from test_public_hooks import MemoryTransport, capabilities, config


class HarnessIdentityTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_constructor_requires_typed_canonical_identity(self):
        self.assertIs(
            inspect.signature(Hooks).parameters["harness"].default,
            inspect.Parameter.empty,
        )
        with self.assertRaisesRegex(TypeError, "harness must be Harness"):
            Hooks(
                config(),
                source="urn:host",
                harness={"name": "host", "version": "1"},
                capabilities=capabilities(),
            )
        for field, value in (
            ("name", ""),
            ("version", ""),
            ("name", 1),
            ("version", None),
        ):
            identity = event.Harness(name="host", version="1")
            identity[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                Hooks(
                    config(),
                    source="urn:host",
                    harness=identity,
                    capabilities=capabilities(),
                )

    def test_dispatch_snapshots_identity_for_intercepts_and_observations(self):
        async def run():
            identity = event.Harness(name="test-host", version="1")
            expected = dict(identity)
            transport = MemoryTransport([], [], [], [])
            registration = config(count=2)
            registration["hooks"][0]["subscriptions"].append(
                config(mode="observe")["hooks"][0]["subscriptions"][0]
            )
            async with Hooks(
                registration,
                source="urn:host",
                harness=identity,
                capabilities=capabilities(),
                transport=transport,
            ) as hooks:
                identity["name"] = "mutated-config"
                payload = deepcopy(request()["params"]["event"])
                payload.pop("harness", None)
                first = await hooks.dispatch("tool.before", payload, event_id="first")
                self.assertEqual(first.event["harness"], expected)
                first.event["harness"]["name"] = "mutated-result"
                # Supply a complete canonical event, with matching identity.
                payload["harness"] = deepcopy(expected)
                second = await hooks.dispatch("tool.before", payload, event_id="second")
                self.assertEqual(second.event["harness"], expected)
                self.assertTrue(transport.requests)
                self.assertTrue(transport.notifications)
                for message in transport.requests + transport.notifications:
                    self.assertEqual(message["params"]["event"]["harness"], expected)
                payload["harness"]["name"] = "conflict"
                with self.assertRaisesRegex(ProtocolError, "harness conflicts"):
                    await hooks.dispatch("tool.before", payload)

        self.run_async(run)

    def test_observe_only_stamps_identity_and_wire_boundaries_reject_conflicts(self):
        async def run():
            identity = event.Harness(name="test-host", version="1")
            transport = MemoryTransport()
            declarations = capability.HostCapabilities(
                tool_before=capability.ToolBeforeCapabilities(observe=True)
            )
            async with Hooks(
                config(mode="observe"),
                source="urn:host",
                harness=identity,
                capabilities=declarations,
                transport=transport,
            ) as hooks:
                payload = deepcopy(request()["params"]["event"])
                payload.pop("harness", None)
                result = await hooks.dispatch("tool.before", payload)
                self.assertEqual(result.event["harness"], dict(identity))
                notification = deepcopy(transport.notifications[0])
                await hooks.notify(notification)
                notification["params"]["event"]["harness"]["name"] = "other"
                with self.assertRaisesRegex(ProtocolError, "harness conflicts"):
                    await hooks.notify(notification)
                del notification["params"]["event"]["harness"]
                with self.assertRaises(ProtocolError):
                    await hooks.notify(notification)

        self.run_async(run)

    def test_canonical_request_requires_harness(self):
        message = request()
        message["params"]["event"].pop("harness", None)
        with self.assertRaises(ProtocolError):
            Validator().validate("intercept-request", message)

    def test_named_host_inputs_do_not_accept_harness(self):
        for name in dir(event):
            model = getattr(event, name)
            if name.endswith("Input") and inspect.isclass(model):
                with self.subTest(model=name):
                    self.assertNotIn("harness", inspect.signature(model).parameters)
