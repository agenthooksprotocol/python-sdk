"""Configure a static host manifest once; session_start supplies the envelope."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, cast

import anyio

from agenthooksprotocol import Hooks, event
from agenthooksprotocol.generated import ObserveNotification
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
    configured: dict[str, Any] = {
        "events": [{"event": "session.start", "modes": ["observe"]}],
        "gaps": [
            {"path": "events.other", "reason": "This example only emits session.start"}
        ],
        "transports": ["in_process"],
        "authentication": [],
        "toolPaths": [],
        "contentCategories": [],
        "limits": {},
        "managedPolicy": {"scopes": [], "disableable": True},
        "correlationIdentityFields": ["event.source", "event.id"],
    }
    received: list[dict[str, Any]] = []

    async def observe(note: ObserveNotification) -> None:
        received.append(deepcopy(cast(dict[str, Any], note)["params"]["event"]))

    handler = hooks.Handler(observe=observe)

    class InProcessTransport:
        async def notify(self, note: dict[str, Any]) -> None:
            await handler.process(note)

    async with Hooks(
        config,
        source="urn:example:manifest",
        manifest=configured,
        transport=InProcessTransport(),
    ) as harness:
        await harness.session_start(
            event.SessionStartInput(
                session={"id": "example-session"},
                trigger="startup",
                harness={"name": "example", "version": "1"},
                permission_mode="default",
                items=[],
            ),
            event_id="example-start",
        )
        assert await harness.wait() == []
    assert len(received) == 1 and received[0]["manifest"] == configured
    assert received[0]["source"] == "urn:example:manifest"
    return {
        "automaticManifest": True,
        "source": received[0]["source"],
        "id": received[0]["id"],
    }


if __name__ == "__main__":
    print(json.dumps(anyio.run(main)))
