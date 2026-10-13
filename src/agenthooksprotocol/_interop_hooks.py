"""Private canonical-fixture setup, not typed application construction.

Fixtures exercise arbitrary wire declarations and rejected responses. Admission
uses the same validated core without making wire mappings a public Hooks input.
"""

from typing import Any, cast, get_args

from .event import EventType, Harness
from .runtime import ProtocolError

from ._hooks import Hooks


def _hooks_for_wire(
    config: dict[str, Any],
    *,
    source: str,
    harness: Harness,
    declarations: dict[str, Any],
    transport: Any,
) -> Hooks:
    if any(name not in get_args(EventType) for name in declarations):
        raise ProtocolError("Unknown canonical fixture event")
    hooks = Hooks.__new__(Hooks)
    hooks._configure(
        config,
        source=source,
        harness=harness,
        declarations=cast(dict[EventType, Any], declarations),
        transport=transport,
    )
    # These declarations originate in external canonical fixtures, not the
    # typed authoring API. Keep their fallible wire parser here, never behind a
    # typed/wire mode switch in Hooks construction.
    for declaration in hooks.capabilities.values():
        if "intercept" in declaration["modes"]:
            hooks.validator.validate("capabilities", declaration["capabilities"])
    hooks.validator.validate(
        "capabilities-response",
        {
            "jsonrpc": "2.0",
            "id": "fixture-manifest",
            "result": {
                "protocolVersion": config["protocolVersion"],
                "manifest": hooks.manifest,
            },
        },
    )
    return hooks
