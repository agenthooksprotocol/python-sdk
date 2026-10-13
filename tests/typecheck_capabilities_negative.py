"""Compile-only negatives: each type-error line must receive a diagnostic.

Empty typed declarations have valid signatures but fail immediately at runtime;
those constraints are covered by test_typed_capabilities.py.
"""

from agenthooksprotocol import event as protocol_event
from typing import Any

from agenthooksprotocol import Hooks, capability


# fmt: off
def invalid_hosts(registration: dict[str, Any]) -> None:
    Hooks(
        registration,
        source="urn:typed",
        harness=protocol_event.Harness(name="test-host", version="1"),
        capabilities={},
    )  # type-error
    capability.HostCapabilities(unknown_event=capability.ToolBeforeCapabilities(observe=True))  # type-error
    capability.HostCapabilities(tool_before={"modes": ["observe"]})  # type-error
    capability.ToolBeforeIntercept(modify_summary=capability.Modify.REPLACE)  # type-error
    capability.ToolBeforeIntercept(deny="yes")  # type-error
    capability.ToolBeforeIntercept(modify_input="replace")  # type-error
    capability.ToolBeforeIntercept(elicitation="form")  # type-error
    capability.ToolBeforeCapabilities(intercept=capability.ToolAfterIntercept(message=True))  # type-error
    capability.HostCapabilities(tool_before=capability.ToolAfterCapabilities(observe=True))  # type-error
    capability.ToolBeforeIntercept(flow=capability.FlowContinue(remaining_continuations=1, continuation_count=0))  # type-error
    capability.InjectContext(deliver_at=[capability.Delivery.NOW])  # type-error
    capability.ToolBeforeIntercept(True)  # type-error
