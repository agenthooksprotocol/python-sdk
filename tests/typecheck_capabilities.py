"""Compile-only positive cases for the handwritten Hooks constructor."""

from typing import Any

from agenthooksprotocol import Hooks, capability


def typed_hosts(registration: dict[str, Any]) -> tuple[Hooks, Hooks, Hooks]:
    intercepted = Hooks(
        registration,
        source="urn:typed",
        capabilities=capability.HostCapabilities(
            tool_before=capability.ToolBeforeCapabilities(
                intercept=capability.ToolBeforeIntercept(
                    deny=True, modify_input=capability.Modify.REPLACE
                ),
                observe=True,
            )
        ),
    )
    observed = Hooks(
        registration,
        source="urn:typed",
        capabilities=capability.HostCapabilities(
            tool_before=capability.ToolBeforeCapabilities(observe=True),
            session_start=capability.SessionStartCapabilities(observe=True),
        ),
    )
    elicitation_only = Hooks(
        registration,
        source="urn:typed",
        capabilities=capability.HostCapabilities(
            tool_before=capability.ToolBeforeCapabilities(
                intercept=capability.ToolBeforeIntercept(
                    elicitation=capability.Elicitation.FORM
                )
            )
        ),
    )
    return intercepted, observed, elicitation_only
