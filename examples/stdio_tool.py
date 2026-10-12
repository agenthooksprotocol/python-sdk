"""Load JSON, own a real backend process, and receive a denial."""

from agenthooksprotocol import capability

import json
from pathlib import Path
import sys

import anyio
from agenthooksprotocol import HookResult, Hooks, event, tool


async def main() -> None:
    with Path(__file__).with_name("registration.json").open() as file:
        config = json.load(file)
    config["hooks"][0]["transport"] = {
        "type": "stdio",
        "command": sys.executable,
        "args": [str(Path(__file__).with_name("stdio_backend.py"))],
        "lifecycle": "persistent",
    }
    async with Hooks(
        config,
        source="urn:example:comparison",
        capabilities=capability.HostCapabilities(
            tool_before=capability.ToolBeforeCapabilities(
                intercept=capability.ToolBeforeIntercept(deny=True)
            )
        ),
    ) as harness:
        result: HookResult[object, object, object] = await harness.tool_before(
            event.ToolBeforeInput(
                call_id="call-1",
                path=tool.Path.NATIVE,
                name="shell",
                origin=tool.Origin.NATIVE,
                input={"command": "echo original", "timeoutMs": 1000},
            ),
            initial_state={"permission": "allow", "candidate": None},
            event_id="stdio-1",
        )
        print(
            json.dumps(
                {
                    "permission": result.permission.value,
                    "executed": False,
                    "effectiveInput": result.input,
                }
            )
        )
    # Context exit reaps the child. The host never runs the denied operation.


if __name__ == "__main__":
    anyio.run(main)
