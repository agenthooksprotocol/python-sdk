"""Synthetic catalogue host capabilities and real-transport scenario driver."""

from copy import deepcopy
from collections import defaultdict
from contextlib import AsyncExitStack
from .runtime import ProtocolError
from .registration import validate_registration
from . import capability
import anyio

EXECUTION_EVENTS = (
    "tool.before",
    "tool.after",
    "turn.start",
    "turn.finish.before",
    "turn.end",
    "turn.progress",
    "model.request.before",
    "model.response.after",
    "model.error",
    "model.switch.before",
    "model.switch.after",
    "tool.permission.request",
    "tool.permission.resolved",
    "tool.progress",
    "tool.batch.after",
    "context.compact.before",
    "context.compact.after",
)
CHANGE_EVENTS = (
    "task.change.before",
    "task.change.after",
    "workspace.change.before",
    "workspace.change.after",
    "file.changed",
)


def discovery(request, validator):
    validator.validate("capabilities-request", request)
    events = [
        {"event": name, "modes": ["observe"]}
        for name in EXECUTION_EVENTS + CHANGE_EVENTS
    ]
    events[0].update(
        modes=["observe", "intercept"],
        capabilities={
            "effects": [
                "allow",
                "deny",
                "ask",
                "modify",
                "return",
                "message",
                "flow",
                "inject",
            ],
            "modify": {"input": {"replace": True, "merge": True}},
            "flow": {"operations": ["stop"]},
            "inject": {"context": {"append": True, "deliverAt": ["now", "next_turn"]}},
        },
    )
    response = {
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "protocolVersion": request["params"]["protocolVersion"],
            "manifest": {
                "events": events,
                "gaps": [
                    {
                        "path": "events.other",
                        "reason": "Catalogue test host does not implement other events",
                    },
                    {
                        "path": "managedPolicy",
                        "reason": "Non-disableable managed subscriptions cannot be enforced",
                    },
                ],
                "transports": ["http", "stdio"],
                "authentication": ["bearer", "oauth"],
                "toolPaths": ["native"],
                "contentCategories": ["messages", "toolResults"],
                "limits": {"maxUploadBytes": 4 * 1024 * 1024},
                "managedPolicy": {"scopes": ["user", "project"], "disableable": True},
                "correlationIdentityFields": [
                    "event.source",
                    "event.id",
                    "call.id",
                    "task.id",
                    "parentEventId",
                ],
            },
        },
    }
    validator.validate("capabilities-response", response)
    return response


def run_catalogue(config, fixtures, transport, validator):
    return anyio.run(_run_catalogue, config, fixtures, transport, validator)


async def _run_catalogue(config, fixtures, transport, validator):
    from . import Hooks
    from .interop import atomic_json

    request = {
        "jsonrpc": "2.0",
        "id": "catalogue-discovery",
        "method": "hooks/capabilities",
        "params": {"protocolVersion": "draft"},
    }
    response = transport.discover(request)
    validator.validate("capabilities-response", response)
    if (
        response["id"] != request["id"]
        or response["result"]["protocolVersion"] != request["params"]["protocolVersion"]
    ):
        raise ProtocolError("Discovery correlation mismatch")
    manifest = response["result"]["manifest"]

    class NotificationTransport:
        async def notify(self, message):
            await anyio.to_thread.run_sync(transport.notify, message)

    # The synthetic host implements this fixed catalogue. External discovery
    # remains canonical wire evidence for registration checks, not a constructor
    # adapter that can grant arbitrary host capabilities.
    declarations = capability.HostCapabilities(
        tool_before=capability.Observe(),
        tool_after=capability.Observe(),
        turn_start=capability.Observe(),
        turn_finish_before=capability.Observe(),
        turn_end=capability.Observe(),
        turn_progress=capability.Observe(),
        model_request_before=capability.Observe(),
        model_response_after=capability.Observe(),
        model_error=capability.Observe(),
        model_switch_before=capability.Observe(),
        model_switch_after=capability.Observe(),
        tool_permission_request=capability.Observe(),
        tool_permission_resolved=capability.Observe(),
        tool_progress=capability.Observe(),
        tool_batch_after=capability.Observe(),
        context_compact_before=capability.Observe(),
        context_compact_after=capability.Observe(),
        task_change_before=capability.Observe(),
        task_change_after=capability.Observe(),
        workspace_change_before=capability.Observe(),
        workspace_change_after=capability.Observe(),
        file_changed=capability.Observe(),
    )
    registration = {
        "protocolVersion": "draft",
        "hooks": [
            {
                "id": "org.agenthooksprotocol.catalogue",
                "transport": {"type": "http", "url": "http://127.0.0.1/fixture"},
                "subscriptions": [
                    {
                        "events": [
                            entry["event"]
                            for entry in manifest["events"]
                            if "observe" in entry["modes"]
                        ],
                        "mode": "observe",
                        "content": {"default": "metadata"},
                    }
                ],
            }
        ],
    }
    observed, results, sources = defaultdict(int), [], {}
    async with AsyncExitStack() as stack:
        for scenario in fixtures["scenarios"]:
            actual = {"sent": [], "registrations": []}
            for step in scenario["steps"]:
                if step["op"] in ("notify", "rawNotify"):
                    raw = step["op"] == "rawNotify"
                    message = deepcopy(step["message"])
                    if raw:
                        # Explicit rawNotify scenarios are adversarial wire probes.
                        transport.notify(message, raw=True)
                    else:
                        source = message["params"]["event"]["source"]
                        if source not in sources:
                            sources[source] = await stack.enter_async_context(
                                Hooks(
                                    registration,
                                    source=source,
                                    capabilities=declarations,
                                    transport=NotificationTransport(),
                                )
                            )
                        await sources[source].notify(message)
                    ident = message["params"]["event"]["id"]
                    observed[ident] += 1
                    transport.control(
                        "/wait-observed", {"eventId": ident, "count": observed[ident]}
                    )
                    actual["sent"].append(message)
                elif step["op"] == "register":
                    try:
                        validate_registration(
                            step["registration"],
                            manifest,
                            step["requirements"],
                            step["context"],
                            validator,
                        )
                    except ProtocolError:
                        accepted = False
                    else:
                        accepted = True
                    actual["registrations"].append({"accepted": accepted})
                else:
                    raise ProtocolError("Unknown catalogue operation")
            results.append({"id": scenario["id"], "status": "passed", "actual": actual})
    atomic_json(
        config["reportFile"],
        {
            "language": "python",
            "results": results,
            "discovery": response,
            "receipts": transport.control("/receipts"),
        },
    )
