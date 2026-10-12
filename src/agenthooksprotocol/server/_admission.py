"""Request-time grant admission, without host execution or native authorization."""

from typing import Any

from ..runtime import ProtocolError


def validate_grants(request: dict[str, Any], response: dict[str, Any]) -> None:
    """Reject effects not granted by this exact request's capabilities.

    Event/target/value legality is separately checked by the generated contextual
    response parser. This check never executes, reduces, or authorizes effects.
    """
    capabilities = request["params"]["capabilities"]
    flow = capabilities.get("flow", {})
    remaining = flow.get(
        "remainingContinuations",
        flow.get("maxContinuations", 0) - flow.get("continuationCount", 0),
    )
    for effect in response["result"]["effects"]:
        family = effect["type"]
        if family not in capabilities.get("effects", ()):
            raise ProtocolError("Effect family not granted")
        if family == "modify":
            grant = capabilities.get("modify", {}).get(effect["target"], {})
            if grant.get(effect["operation"]) is not True:
                raise ProtocolError("Modification not granted")
        elif family == "flow":
            operation = effect["operation"]
            if operation not in flow.get("operations", ()):
                raise ProtocolError("Flow operation not granted")
            if operation == "continue":
                if remaining <= 0:
                    raise ProtocolError("Continuation budget exhausted")
        elif family == "inject":
            grant = capabilities.get("inject", {}).get("context", {})
            if (
                effect.get("target") != "context"
                or effect.get("operation") != "append"
                or grant.get("append") is not True
                or effect.get("deliverAt") not in grant.get("deliverAt", ())
            ):
                raise ProtocolError("Context injection not granted")
