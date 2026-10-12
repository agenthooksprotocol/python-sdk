"""Configure a static host manifest once; session_start supplies the envelope."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import anyio

from agenthooksprotocol import (
    Hooks,
    HostManifestMetadata,
    Session,
    SessionStartInputHarness,
    capability,
    event,
)
from agenthooksprotocol._models import (
    StaticCapabilityManifestGapsItem,
    StaticCapabilityManifestLimits,
    StaticCapabilityManifestManagedPolicy,
)
from agenthooksprotocol.server import hooks


async def main() -> dict[str, Any]:
    with Path(__file__).with_name("registration.json").open() as file:
        config = json.load(file)
    config["hooks"][0]["subscriptions"] = [
        {
            "events": ["session.start"],
            "mode": "observe",
            "content": {"default": "metadata"},
        }
    ]
    configured = HostManifestMetadata(
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
                path="events.other", reason="This example only emits session.start"
            ),
        ),
    )
    received: list[dict[str, Any]] = []

    async def observe(ctx: hooks.SessionStartObserveContext) -> None:
        received.append(deepcopy(ctx.raw["params"]["event"]))

    handler = hooks.Handlers(observe=hooks.ObserveHandlers(session_start=observe))

    class InProcessTransport:
        async def notify(self, note: dict[str, Any]) -> None:
            await handler.process(note)

    async with Hooks(
        config,
        source="urn:example:manifest",
        manifest_metadata=configured,
        capabilities=capability.HostCapabilities(session_start=capability.Observe()),
        transport=InProcessTransport(),
    ) as harness:
        await harness.session_start(
            event.SessionStartInput(
                session=Session(id="example-session"),
                trigger="startup",
                harness=SessionStartInputHarness(name="example", version="1"),
                permission_mode="default",
                items=[],
            ),
            event_id="example-start",
        )
        assert await harness.wait_observations() == []
    assert len(received) == 1
    assert received[0]["manifest"] == {
        **configured.to_wire(),
        "events": [{"event": "session.start", "modes": ["observe"]}],
    }
    assert received[0]["source"] == "urn:example:manifest"
    return {
        "automaticManifest": True,
        "source": received[0]["source"],
        "id": received[0]["id"],
    }


if __name__ == "__main__":
    print(json.dumps(anyio.run(main)))
