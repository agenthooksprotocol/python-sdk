"""Executable comparison cases S01-S08; no shell command is executed.

The host operation is an in-memory execution recorder. Reports distinguish AHP
admission, ordinary application validation, denial, and synthetic execution.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
from typing import Any, cast

import anyio
import httpx
from agenthooksprotocol import HookResult, Hooks, capability, event, tool
from agenthooksprotocol.wire import JsonValue, Effect, InterceptRequest
from agenthooksprotocol.server import asgi, hooks
from agenthooksprotocol.transports.http import HTTPTransport
from typed_tool import ShellCodec, allowed_by_host


async def run_case(case: dict[str, Any]) -> dict[str, Any]:
    with Path(__file__).with_name("registration.json").open() as file:
        config = json.load(file)
    config["hooks"][0]["subscriptions"][0]["failurePolicy"] = case.get(
        "policy", "fail-closed"
    )

    async def intercept(request: InterceptRequest) -> hooks.InterceptResult:
        if case.get("deliveryError"):
            raise ValueError("deliberate backend failure")
        return hooks.InterceptResult(
            effects=cast(list[Effect], deepcopy(case["effects"]))
        )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=asgi.App(hooks.Handler(intercept=intercept)))
    ) as client:
        async with Hooks(
            config,
            source="urn:example:comparison",
            capabilities={
                "tool.before": capability.Declaration(
                    modes=[capability.Mode.INTERCEPT],
                    grants=[
                        capability.Allow(),
                        capability.Deny(),
                        capability.ModifyInput(replace=True),
                    ],
                ),
            },
            transport=HTTPTransport("http://example.test/hooks", client=client),
        ) as harness:
            result: HookResult[JsonValue, JsonValue, JsonValue] = await harness.tool_before(
                event.ToolBeforeInput(
                    call_id="call-1",
                    path=tool.Path.NATIVE,
                    name="shell",
                    origin=tool.Origin.NATIVE,
                    input={"command": "echo original", "timeoutMs": 1000},
                ),
                initial_state={
                    "permission": case.get("initialPermission", "allow"),
                    "candidate": None,
                },
                capabilities=case.get("narrow"),
                event_id=case["id"],
            )
            layer: str | None = None
            host_accepted = False
            executions: list[dict[str, Any]] = []
            try:
                effective = result.decode_input(ShellCodec())
                host_accepted = allowed_by_host(effective)
                if not host_accepted:
                    layer = "host-policy"
            except ValueError:
                layer = "host-input-schema"
            if result.diagnostics and not result.accepted_responses:
                layer = "protocol"
            if host_accepted and result.decision == "allow":
                # A harmless ordinary host operation, not SDK execution or a shell.
                executions.append(dict(effective))
            return {
                "id": case["id"],
                "sdkAccepted": bool(result.accepted_responses),
                "hostAccepted": host_accepted,
                "rejectionLayer": layer,
                "decision": result.decision,
                "effectiveInput": result.effective_input,
                "executed": bool(executions),
                "executionCount": len(executions),
                "diagnostics": result.diagnostics,
            }


async def main() -> None:
    def replace(command: Any) -> dict[str, Any]:
        return {
            "type": "modify",
            "target": "input",
            "operation": "replace",
            "value": {"command": command, "timeoutMs": 1000},
        }

    cases: list[dict[str, Any]] = [
        {"id": "S01", "effects": []},
        {"id": "S02", "effects": [replace("echo reviewed"), {"type": "allow"}]},
        {"id": "S03", "effects": [{"type": "deny", "reason": "Policy denied"}]},
        {"id": "S04", "effects": [replace(42), {"type": "allow"}]},
        {"id": "S05", "effects": [replace("rm prohibited"), {"type": "allow"}]},
        {
            "id": "S06",
            "effects": [replace("echo reviewed"), {"type": "allow"}],
            "narrow": {"effects": ["deny"]},
        },
        {"id": "S07-deny", "effects": [], "initialPermission": "deny"},
        {"id": "S07-allow", "effects": []},
        {"id": "S08-open", "effects": [], "deliveryError": True, "policy": "fail-open"},
        {
            "id": "S08-closed",
            "effects": [],
            "deliveryError": True,
            "policy": "fail-closed",
        },
    ]
    results = [await run_case(case) for case in cases]
    by_id = {row["id"]: row for row in results}
    assert by_id["S02"]["effectiveInput"]["command"] == "echo reviewed"
    assert by_id["S02"]["executionCount"] == 1
    assert by_id["S03"]["executionCount"] == 0
    assert by_id["S04"]["sdkAccepted"] and not by_id["S04"]["hostAccepted"]
    assert by_id["S04"]["rejectionLayer"] == "host-input-schema"
    assert not by_id["S04"]["executed"] and not by_id["S05"]["executed"]
    assert by_id["S06"]["effectiveInput"]["command"] == "echo original"
    assert not by_id["S06"]["executed"] and not by_id["S07-deny"]["executed"]
    assert by_id["S08-open"]["executed"] and not by_id["S08-closed"]["executed"]
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    anyio.run(main)
