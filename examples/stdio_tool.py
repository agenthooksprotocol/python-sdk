"""Load JSON, own a real backend process, and receive a denial."""

import json
from pathlib import Path
import sys

import anyio
from agenthooksprotocol import Hooks, capability, event, tool


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
        capabilities={
            "tool.before": capability.Declaration(
                modes=[capability.Mode.INTERCEPT], grants=[capability.Deny()]
            ),
        },
    ) as harness:
        result = await harness.tool_before(
            event.ToolBeforeInput(
                call=tool.Call(id="call-1"),
                path=tool.Path.NATIVE,
                tool=tool.Tool(
                    name="shell",
                    origin=tool.Origin.NATIVE,
                    input={"command": "echo original", "timeoutMs": 1000},
                ),
            ),
            initial_state={"permission": "allow", "candidate": None},
            event_id="stdio-1",
        )
        print(
            json.dumps(
                {
                    "decision": result.decision,
                    "executed": False,
                    "effectiveInput": result.effective_input,
                }
            )
        )
    # Context exit reaps the child. The host never runs the denied operation.


if __name__ == "__main__":
    anyio.run(main)
