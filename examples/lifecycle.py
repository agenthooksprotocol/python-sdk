"""Real public observation waiting and owned subprocess cancellation (S09/S10)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile

import anyio
import httpx
from agenthooksprotocol import Hooks, capability, effect, event, tool
from agenthooksprotocol.generated import InterceptRequest, ObserveNotification
from agenthooksprotocol.server import asgi, hooks
from agenthooksprotocol.transports.http import HTTPTransport


def input_event() -> event.ToolBeforeInput:
    return event.ToolBeforeInput(
        call=tool.Call(id="call-1"),
        path=tool.Path.NATIVE,
        tool=tool.Tool(
            name="shell",
            origin=tool.Origin.NATIVE,
            input={"command": "echo original", "timeoutMs": 1000},
        ),
    )


async def main() -> None:
    with Path(__file__).with_name("registration.json").open() as file:
        config = json.load(file)
    config["hooks"][0]["subscriptions"].append(
        {
            "events": ["tool.before"],
            "mode": "observe",
            "content": {"default": "metadata"},
        }
    )
    started, release, delivered = anyio.Event(), anyio.Event(), anyio.Event()

    async def intercept(request: InterceptRequest) -> hooks.InterceptResult:
        return hooks.InterceptResult(effects=[effect.Allow()])

    async def observe(notification: ObserveNotification) -> None:
        started.set()
        await release.wait()
        delivered.set()

    app = asgi.App(hooks.Handler(intercept=intercept, observe=observe))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        async with Hooks(
            config,
            source="urn:example:comparison",
            capabilities={
                "tool.before": capability.Declaration(
                    modes=[capability.Mode.INTERCEPT, capability.Mode.OBSERVE],
                    grants=[capability.Allow()],
                ),
            },
            transport=HTTPTransport("http://example.test/hooks", client=client),
        ) as harness:
            result = await harness.tool_before(input_event())
            with anyio.fail_after(2):
                await started.wait()
            assert not delivered.is_set() and result.decision == "allow"
            release.set()
            diagnostics = await harness.wait()
            assert delivered.is_set() and not diagnostics
    # The HTTP client was borrowed and closed by its outer context, not Hooks.

    with tempfile.TemporaryDirectory() as directory:
        pid_file = Path(directory) / "child.pid"
        # Explicit adversarial cancellation probe: child never answers requests.
        script = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
        config["hooks"][0]["transport"] = {
            "type": "stdio",
            "command": sys.executable,
            "args": ["-c", script, str(pid_file)],
            "lifecycle": "persistent",
        }
        config["hooks"][0]["subscriptions"] = config["hooks"][0]["subscriptions"][:1]
        cancelled = False
        async with Hooks(
            config,
            source="urn:example:comparison",
            capabilities={
                "tool.before": capability.Declaration(
                    modes=[capability.Mode.INTERCEPT], grants=[capability.Allow()]
                ),
            },
        ) as harness:
            with anyio.move_on_after(0.3) as scope:
                await harness.tool_before(input_event())
            cancelled = scope.cancel_called
        await harness.aclose()  # Shutdown is idempotent.
        assert cancelled and pid_file.exists()
        pid = int(pid_file.read_text())
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            reaped = True
        else:
            reaped = False
        assert reaped
    print(
        json.dumps(
            {
                "S09": {"nonGating": True, "waitCompleted": True},
                "S10": {
                    "cancelled": cancelled,
                    "childReaped": reaped,
                    "executed": False,
                },
            }
        )
    )


if __name__ == "__main__":
    anyio.run(main)
