"""Run a typed tool boundary without executing any real shell command.

The HTTPX ASGI transport runs the real SDK ASGI adapter in-process. The sibling
stdio example runs the same Handler over an actual owned child process.
"""

from __future__ import annotations

from pathlib import Path
import json
from typing import TypedDict

import anyio
import httpx

from agenthooksprotocol import HookResult, Hooks, Permission, capability, effect, event, state, tool
from agenthooksprotocol.wire import InterceptRequest, JsonObject, JsonValue
from agenthooksprotocol.server import asgi, hooks
from agenthooksprotocol.transports.http import HTTPTransport


class ShellInput(TypedDict):
    command: str
    timeoutMs: int


class ShellCodec:
    def encode(self, value: ShellInput) -> JsonObject:
        return {"command": value["command"], "timeoutMs": value["timeoutMs"]}

    def decode(self, value: JsonValue) -> ShellInput:
        if not isinstance(value, dict):
            raise ValueError("shell input must be an object")
        command, timeout = value.get("command"), value.get("timeoutMs")
        if not isinstance(command, str) or type(timeout) is not int:
            raise ValueError("command must be text and timeoutMs must be an integer")
        return ShellInput(command=command, timeoutMs=timeout)


def allowed_by_host(value: ShellInput) -> bool:
    return not value["command"].startswith("rm ") and value["timeoutMs"] > 0


async def main() -> None:
    # Ordinary JSON loading; no SDK-specific loader or awaited initialization.
    with Path(__file__).with_name("registration.json").open() as file:
        config = json.load(file)
    arguments = ShellInput(command="echo original", timeoutMs=1000)
    codec = ShellCodec()

    async def intercept(request: InterceptRequest) -> hooks.InterceptResult:
        return hooks.InterceptResult(
            effects=[
                effect.replace_input({"command": "echo reviewed", "timeoutMs": 1000}),
                effect.Allow(),
            ]
        )

    handler = hooks.Handler(intercept=intercept)
    # The injected AsyncClient is borrowed; this outer context owns its lifetime.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=asgi.App(handler))
    ) as client:
        transport = HTTPTransport("http://example.test/hooks", client=client)
        async with Hooks(
            config,
            source="urn:example:comparison",
            capabilities={
                "tool.before": capability.intercept()
                .allow()
                .deny()
                .modify_input(replace=True),
            },
            transport=transport,
        ) as harness:
            result: HookResult[JsonValue, JsonValue, JsonValue] = await harness.tool_before(
                event.ToolBeforeInput(
                    call_id="call-1",
                    path=tool.Path.NATIVE,
                    name="shell",
                    origin=tool.Origin.NATIVE,
                    input=codec.encode(arguments),
                ),
                initial_state=state.initial(Permission.NONE),
                event_id="example-1",
            )
            # Protocol settlement has already happened. Decoding is ordinary host code.
            try:
                effective = result.decode_input(codec)
                host_accepted = allowed_by_host(effective)
            except ValueError:
                host_accepted = False
            print(
                json.dumps(
                    {
                        "sdkAccepted": bool(result.accepted_responses),
                        "hostAccepted": host_accepted,
                        "decision": result.decision,
                        "effectiveInput": result.effective_input,
                        "executed": False,  # This example deliberately does not run a shell.
                    }
                )
            )


if __name__ == "__main__":
    anyio.run(main)
