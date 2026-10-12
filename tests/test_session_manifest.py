"""Static host manifests belong to configuration, not each session occurrence."""

from agenthooksprotocol import capability

from copy import deepcopy
import unittest

import anyio

from agenthooksprotocol import Hooks, HostManifestMetadata, event
from agenthooksprotocol._models import (
    StaticCapabilityManifestGapsItem,
    StaticCapabilityManifestLimits,
    StaticCapabilityManifestManagedPolicy,
)
from agenthooksprotocol.runtime import ProtocolError
from agenthooksprotocol.server import hooks as server
from test_public_hooks import config


def host_facts():
    return event.SessionStartInput(
        session={"id": "session-1"},
        trigger="startup",
        harness={"name": "test-host", "version": "1"},
        permission_mode="default",
        items=[],
    )


def manifest():
    return {
        "events": [{"event": "session.start", "modes": ["observe"]}],
        "gaps": [{"path": "events.other", "reason": "Not implemented"}],
        "transports": ["in_process"],
        "authentication": [],
        "toolPaths": [],
        "contentCategories": [],
        "limits": {},
        "managedPolicy": {"scopes": [], "disableable": True},
        "correlationIdentityFields": ["event.source", "event.id"],
    }


def metadata():
    return HostManifestMetadata(
        transports=("in_process",),
        authentication=(),
        tool_paths=(),
        content_categories=(),
        limits=StaticCapabilityManifestLimits(),
        managed_policy=StaticCapabilityManifestManagedPolicy(
            scopes=[], disableable=True
        ),
        correlation_identity_fields=("event.source", "event.id"),
        gaps=(
            StaticCapabilityManifestGapsItem(
                path="events.other", reason="Not implemented"
            ),
        ),
        additional_properties={"opaque": {"nested": ["original"]}},
    )


class ManifestTests(unittest.TestCase):
    def test_full_manifest_and_sdk_envelope_are_detached(self):
        async def run():
            received = []
            configured = metadata()
            expected = {**manifest(), "opaque": {"nested": ["original"]}}
            registration = config(mode="observe")
            registration["hooks"][0]["subscriptions"][0]["events"] = ["session.start"]

            async def observe(ctx: server.SessionStartObserveContext) -> None:
                occurrence = ctx.raw["params"]["event"]
                received.append(deepcopy(occurrence))
                occurrence["manifest"]["events"].clear()
                occurrence["session"]["id"] = "callback-mutation"
                occurrence["source"] = "urn:callback"
                occurrence["id"] = "callback-id"

            handler = server.Handlers(
                observe=server.ObserveHandlers(session_start=observe)
            )

            class Transport:
                async def notify(self, note):
                    await handler.process(note)

            facts = host_facts()
            original = deepcopy(facts)
            async with Hooks(
                registration,
                source="urn:configured",
                manifest_metadata=configured,
                capabilities=capability.HostCapabilities(
                    session_start=capability.Observe()
                ),
                transport=Transport(),
            ) as harness:
                configured.additional_properties["opaque"]["nested"].clear()
                snapshot = harness.manifest
                snapshot["events"].clear()
                first = await harness.session_start(facts, event_id="owned-id")
                self.assertEqual(await harness.wait_observations(), [])
                self.assertEqual(harness.manifest, expected)
                self.assertEqual(first.event["manifest"], expected)
                # Raw caller attempts cannot override SDK-owned envelope fields.
                await harness.session_start(
                    {
                        **facts,
                        "type": "tool.before",
                        "source": "urn:spoof",
                        "id": "spoof",
                        "manifest": {},
                    },
                    event_id="second-id",
                )
                self.assertEqual(await harness.wait_observations(), [])
                self.assertEqual(harness.config, registration)
            self.assertEqual(facts, original)
            self.assertEqual(len(received), 2)
            for occurrence, identity in zip(received, ("owned-id", "second-id")):
                self.assertEqual(occurrence["manifest"], expected)
                self.assertEqual(occurrence["source"], "urn:configured")
                self.assertEqual(occurrence["type"], "session.start")
                self.assertEqual(occurrence["id"], identity)
                self.assertEqual(occurrence["session"]["id"], "session-1")

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_derived_manifest_covers_omissions_without_granting_authority(self):
        harness = Hooks(
            config(),
            source="urn:configured",
            capabilities=capability.HostCapabilities(
                session_start=capability.Observe(),
                tool_before=capability.ToolBeforeCapabilities(
                    intercept=capability.ToolBeforeIntercept(deny=True)
                ),
            ),
        )
        result = harness.manifest
        self.assertEqual(
            result["events"],
            [
                {"event": "session.start", "modes": ["observe"]},
                {
                    "event": "tool.before",
                    "modes": ["intercept"],
                    "capabilities": {"effects": ["deny"]},
                },
            ],
        )
        paths = {gap["path"] for gap in result["gaps"]}
        self.assertEqual(len([p for p in paths if p.startswith("events.")]), 30)
        self.assertIn("events.session.end", paths)
        for field in ("transports", "authentication", "toolPaths", "contentCategories"):
            self.assertEqual(result[field], [])
            self.assertIn(field, paths)
        with self.assertRaisesRegex(
            ProtocolError, "Unsupported event or delivery mode"
        ):
            Hooks(
                config(),
                source="urn:configured",
                capabilities=capability.HostCapabilities(),
            )

    def test_shorthand_session_start_delivers_without_caller_manifest(self):
        async def run():
            received = []
            registration = config(mode="observe")
            registration["hooks"][0]["subscriptions"][0]["events"] = ["session.start"]

            async def observe(ctx: server.SessionStartObserveContext) -> None:
                received.append(deepcopy(ctx.raw["params"]["event"]))

            handler = server.Handlers(
                observe=server.ObserveHandlers(session_start=observe)
            )

            class Transport:
                async def notify(self, note):
                    await handler.process(note)

            async with Hooks(
                registration,
                source="urn:shorthand",
                capabilities=capability.HostCapabilities(
                    session_start=capability.Observe()
                ),
                transport=Transport(),
            ) as harness:
                await harness.session_start(host_facts())
                self.assertEqual(await harness.wait_observations(), [])
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0]["manifest"], harness.manifest)
                self.assertEqual(received[0]["source"], "urn:shorthand")
                self.assertTrue(received[0]["id"])
                with self.assertRaises(ProtocolError):
                    await harness.tool_before({})

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_constructor_rejects_removed_full_manifest_argument(self):
        for kwargs in (
            {"manifest": manifest()},
            {"manifest": manifest(), "capabilities": capability.HostCapabilities()},
            {"manifest": {}},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                Hooks(config(), source="urn:configured", **kwargs)
