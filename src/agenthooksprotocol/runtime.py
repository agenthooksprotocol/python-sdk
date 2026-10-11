"""Canonical validation and side-effect-free atomic boundary evaluation."""

from copy import deepcopy
import json
import os
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from . import generated, _models as models
from .response import response_for_request
from .diagnostics import Code as DiagnosticCode


__all__ = ["ProtocolError", "OperationCancelledError", "BackendRPCError", "Validator"]


class ProtocolError(ValueError):
    pass


class OperationCancelledError(RuntimeError):
    """An explicitly cancelled SDK operation cannot yield execution permission."""

    code = DiagnosticCode.CANCELLED


class BackendRPCError(ProtocolError):
    """A validated, correlated remote RPC error; message/data are not retained."""

    def __init__(self, code: int):
        self.code = code
        super().__init__("Backend returned a JSON-RPC error")


def _validate_intercept_response(validator, request, response):
    if isinstance(response, dict) and "error" in response:
        validator.validate("json-rpc-message", response)
        if (
            response.get("id") != request["id"]
            or "result" in response
            or "method" in response
        ):
            raise ProtocolError("Invalid JSON-RPC error envelope")
        raise BackendRPCError(response["error"]["code"])
    validator.validate("intercept-response", response)
    parsed = response_for_request(request["params"]["event"]["type"], response)
    if not parsed["ok"]:
        raise ProtocolError("Contextual response contract rejected the response")
    return parsed["value"]


class Validator:
    def __init__(self, directory: str | Path | None = None) -> None:
        directory = directory or os.environ.get("AHP_SCHEMA_DIR")
        if directory is None:
            bundle = json.loads(Path(__file__).with_name("schemas.json").read_text())
            schemas = {schema["$id"].rsplit("/", 1)[-1]: schema for schema in bundle}
        else:
            schemas = {
                p.name: json.loads(p.read_text())
                for p in Path(directory).glob("*.schema.json")
            }
        if not schemas:
            raise ProtocolError("Canonical schemas unavailable")
        registry = Registry().with_resources(
            (s["$id"], Resource.from_contents(s)) for s in schemas.values()
        )
        self.validators = {
            n: Draft202012Validator(
                s, registry=registry, format_checker=FormatChecker()
            )
            for n, s in schemas.items()
        }

    def validate(self, kind: str, value: Any) -> Any:
        if kind == "form-answer":
            # MCP requestedSchema is validated separately; never resolve remote
            # schemas or populate defaults while validating submitted content.
            Draft202012Validator(
                value["schema"], registry=Registry(), format_checker=FormatChecker()
            ).validate(value["value"])
            return value
        if kind in ("mcp-elicitation#request", "mcp-elicitation#result"):
            name, fragment = kind.split("#")
            root = self.validators[name + ".schema.json"]
            body = root.evolve(
                schema={"$ref": root.schema["$id"] + "#/$defs/" + fragment}
            )
            if not body.is_valid(value):
                raise ProtocolError("Canonical schema rejected " + kind)
            return value
        if kind in ("intercept-request", "observe-notification"):
            from .lifecycle import _content_items

            event = value.get("params", {}).get("event", {})
            if isinstance(event, dict) and any(
                isinstance(item, dict)
                and isinstance(item.get("body"), dict)
                and item["body"].get("ref") == "ahp:owned:pending"
                for item in _content_items(event)
            ):
                raise ProtocolError(
                    "Pending local attachment references cannot enter wire messages"
                )
        codec = getattr(generated, "parse_" + kind.replace("-", "_"), None)
        if codec is None:
            raise ProtocolError("Generated codec unavailable: " + kind)
        if not self.validators[kind + ".schema.json"].is_valid(value):
            error = next(self.validators[kind + ".schema.json"].iter_errors(value))
            raise ProtocolError(
                "Canonical schema rejected "
                + kind
                + ": "
                + "/".join(map(str, error.path))
            )
        if not codec(value)["ok"]:
            raise ProtocolError("Generated codec rejected " + kind)
        return value


def _json_equal(left: Any, right: Any) -> bool:
    """JSON equality: booleans are not numbers; object member order is irrelevant."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[k], right[k]) for k in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def _modification_paths(event):
    targets = {"input": ("tool", "input")} if "tool" in event else {}
    if event["type"] == "workspace.change.before":
        targets["workspace"] = ("workspace", "change")
    for target, event_type, path in [
        ("prompt", "turn.start", ("items",)),
        ("output", "tool.after", ("items",)),
        ("request", "model.request.before", ("items",)),
        ("response", "model.response.after", ("items",)),
        ("response", "turn.finish.before", ("items",)),
        ("content", "context.compact.before", ("items",)),
        ("instructions", "context.compact.before", ("instructions",)),
        ("summary", "context.compact.after", ("summary",)),
    ]:
        if event["type"] == event_type:
            targets[target] = path
    return targets


def _merge_effect_value(effect, previous):
    """Merge only the target type selected by the generated correlated effect."""
    if isinstance(
        effect,
        (
            models.ContextCompactBeforeModifyEffect,
            models.ContextCompactAfterModifyEffect,
            models.TurnStartModifyEffect,
            models.ModelRequestBeforeModifyEffect,
            models.ModelResponseAfterModifyEffect,
            models.ToolAfterModifyEffect,
            models.TurnFinishBeforeModifyEffect,
            models.UserMessageInboundModifyEffect,
            models.UserMessageOutboundModifyEffect,
        ),
    ):
        return previous + effect.value
    elif isinstance(effect, models.WorkspaceChangeBeforeModifyEffect):
        return models.WorkspaceChange.from_dict({**previous, **effect.value})
    elif isinstance(
        effect,
        (models.ToolBeforeModifyEffect, models.ToolPermissionRequestModifyEffect),
    ):
        # Caller-defined object T: temporary shallow JSON, validated
        # against the declared codec before atomic publication.
        return {**previous, **effect.value}
    else:
        raise ProtocolError("Unsupported typed merge target")


def _apply_response(
    request,
    response,
    validator,
    *,
    native_authorize=None,
    native_approve=None,
    validate_operation=None,
    validate_candidate=None,
    include_staged=False,
    content=None,
):
    """Stage a complete response; neither argument is mutated on failure."""
    validator.validate("intercept-request", request)
    response = _validate_intercept_response(validator, request, response)
    request = models.InterceptRequest.from_dict(request)
    params = request.params
    if response["id"] != request["id"] or request["id"] != params["event"]["id"]:
        raise ProtocolError("Correlation mismatch")
    if response["result"]["protocolVersion"] != params["protocolVersion"]:
        raise ProtocolError("Protocol version mismatch")
    effects, caps, event = (
        response.result.effects,
        params.capabilities,
        params.event,
    )
    if effects is None:
        raise ProtocolError("Generated response lacks the neutral effects default")
    if any(not isinstance(effect, models._WireModel) for effect in effects):
        raise ProtocolError("Unknown effects do not convey authority")
    if (
        content is None
        and event["type"] == "user.elicitation.request"
        and any(effect.type in ("return", "deny", "modify") for effect in effects)
    ):
        raise ProtocolError(
            "Elicitation effects require an authenticated request context"
        )
    if (
        content is None
        and event["type"] == "user.elicitation.result"
        and any(effect.type == "modify" for effect in effects)
    ):
        raise ProtocolError(
            "Elicitation result edits require the original request context"
        )
    for effect in effects:
        if isinstance(
            effect,
            (
                models.ReturnTextEffect,
                models.ContextCompactBeforeModifyEffect,
                models.ContextCompactAfterModifyEffect,
            ),
        ):
            target = (
                "instructions"
                if isinstance(effect, models.ReturnTextEffect)
                else effect.target
            )
            selected = getattr(event, target, None)
            if selected is None or any(
                not isinstance(part, models.TextBodyPart) for part in selected
            ):
                raise ProtocolError("Compaction effects require selected inline text")
            if any(not isinstance(part, models.TextBodyPart) for part in effect.value):
                raise ProtocolError("Compaction values require inline text parts")
    state_model = {
        "tool.before": models.ToolState,
        "tool.permission.request": models.ToolState,
        "model.request.before": models.MessagesState,
        "context.compact.before": models.TextState,
        "user.elicitation.request": models.ElicitResultState,
    }.get(event.type, models.InterceptRequestParamsState)
    state = (
        state_model.from_dict(params.state)
        if params.state is not None
        else state_model(permission="none", candidate=None)
    )
    original = deepcopy(event.get("tool", {}).get("input", event.get("input", {})))
    effective = deepcopy(original)
    effective_event = deepcopy(event)
    targets = _modification_paths(event)
    permission = state.permission
    denied, candidate = permission == "deny", state.candidate
    if validate_operation is not None:
        validate_operation(effective_event)
    if validate_candidate is not None:
        validate_candidate(candidate)
    messages = []
    injections = deepcopy(state.get("injections", []))
    flow = state.get("flow")
    if flow == "none":
        flow = None
    continuation_instructions = deepcopy(state.get("instructions", []))
    new_continuation = False
    flow_caps = caps.get("flow", {})
    remaining = flow_caps.get(
        "remainingContinuations",
        flow_caps.get("maxContinuations", 0) - flow_caps.get("continuationCount", 0),
    )
    for effect in effects:
        kind = effect.type
        if (
            kind
            not in {
                "allow",
                "deny",
                "ask",
                "modify",
                "return",
                "message",
                "flow",
                "inject",
            }
            or kind not in caps.effects
        ):
            raise ProtocolError("Unsupported effect")
        if kind == "modify":
            operation = effect.operation
            support = caps.get("modify", {}).get(effect.target, {})
            if (
                effect.target not in targets
                and (content is None or effect.target not in content.targets)
                or operation not in ("replace", "merge")
                or support.get(operation) is not True
            ):
                raise ProtocolError("Unsupported modification")
        if kind == "flow":
            support = caps.get("flow", {})
            if effect.operation not in ("stop", "continue") or effect[
                "operation"
            ] not in support.get("operations", []):
                raise ProtocolError("Unsupported flow")
            if effect.operation == "continue" and remaining <= 0:
                raise ProtocolError("Continuation budget exhausted")
        if kind == "inject":
            support = caps.get("inject", {}).get("context", {})
            if (
                getattr(effect, "target", None) != "context"
                or effect.get("operation") != "append"
                or support.get("append") is not True
                or effect.get("deliverAt") not in support.get("deliverAt", [])
            ):
                raise ProtocolError("Unsupported injection")

    def validate_content_result(value):
        if validate_candidate is not None:
            validate_candidate(models.ElicitResultCandidate(value=value))

    bound = (
        content.stage(request, effects, validate_result=validate_content_result)
        if content is not None
        else None
    )
    for effect in effects:
        if (
            effect.type != "modify"
            or content is not None
            and getattr(effect, "target", None) in content.targets
        ):
            continue
        value = deepcopy(effect.value)
        path = targets[effect.target]
        parent = effective_event
        for key in path[:-1]:
            parent = parent[key]
        previous = parent.get(path[-1])
        if effect.operation == "merge":
            value = _merge_effect_value(effect, previous)
        parent[path[-1]] = value
        intermediate = deepcopy(request)
        intermediate["params"]["event"] = effective_event
        validator.validate("intercept-request", intermediate)
        if validate_operation is not None:
            validate_operation(effective_event)
        if effect.target == "input":
            effective = deepcopy(value)
    staged_request = deepcopy(request)
    staged_request["params"]["event"] = effective_event
    validator.validate("intercept-request", staged_request)
    if (
        not _json_equal(effective_event, event)
        or bound is not None
        and bound["changed"]
    ):
        candidate = None
        if permission == "allow":
            permission = "none"
    for effect in effects:
        kind = effect.type
        if kind == "deny":
            denied = True
        elif kind == "ask":
            permission = "ask"
        elif kind == "allow" and permission != "ask":
            permission = "allow"
        elif kind == "return":
            candidate_model = {
                models.ReturnToolEffect: models.ToolCandidate,
                models.ReturnMessagesEffect: models.MessagesCandidate,
                models.ReturnTextEffect: models.TextCandidate,
                models.ReturnElicitResultEffect: models.ElicitResultCandidate,
            }[type(effect)]
            candidate = candidate_model(value=deepcopy(effect.value))
            if validate_candidate is not None:
                validate_candidate(candidate)
        elif kind == "message":
            messages.append(effect.text)
        elif kind == "inject":
            injections.append(deepcopy(effect))
        elif kind == "flow":
            if effect.operation == "continue":
                new_continuation = True
                if "instruction" in effect:
                    continuation_instructions.append(effect.instruction)
            if flow != "stop":
                flow = effect.operation

    # Host access policy is independent of hook prompt suppression. It gates
    # execution AND supplied-result delivery, and allow cannot bypass it.
    def host_decision(callback):
        value = callback(deepcopy(effective_event))
        if value is not None and type(value) is not bool:
            raise ProtocolError(
                "Host authorization must return true, false, or pending (None)"
            )
        return value

    access = True
    approved = permission == "allow"
    if not denied and flow != "stop":
        if native_authorize is not None:
            access = host_decision(native_authorize)
        if access is False:
            denied = True
        elif access is True and permission == "none":
            if native_approve is not None:
                approved = host_decision(native_approve)
                if approved is False:
                    denied = True
            else:
                # A configured access guard with no approval callback represents
                # a host with no additional ordinary prompt. Without either host
                # callback, an absent hook override does not create authorization.
                approved = native_authorize is not None
    decision = "deny" if denied else "ask" if permission == "ask" else "allow"
    authorized = (
        decision == "allow" and access is True and approved is True and flow != "stop"
    )
    result = {
        "decision": decision,
        "executed": event["type"] == "tool.before" and authorized and candidate is None,
        "input": effective,
        "messages": messages,
    }
    if decision == "allow" and flow != "stop" and not authorized:
        result["authorization"] = "pending"
    if candidate is not None and authorized:
        result["result"] = candidate["value"]
    if flow is not None:
        result["flow"] = flow
        if continuation_instructions or any(
            k in flow_caps
            for k in ("remainingContinuations", "maxContinuations", "continuationCount")
        ):
            result["continuationInstructions"] = continuation_instructions
            result["continuationRemaining"] = (
                remaining - 1 if flow == "continue" and new_continuation else remaining
            )
    if injections:
        result["injections"] = injections
    if (
        any(e.type == "modify" and e.target != "input" for e in effects)
        or event["type"] == "task.change.before"
    ):
        result["event"] = effective_event
    if bound is not None:
        if (
            event.type == "user.elicitation.result"
            and bound["changed"]
            and validate_candidate is not None
        ):
            validate_candidate(
                models.ElicitResultCandidate(value=bound["values"]["result"])
            )
        result["content"] = bound["values"]
        result["_content_updates"] = bound["updates"]
        result["event"] = effective_event
    if include_staged:
        # Settlement data is not host authorization or an execution claim.
        result["permission"] = "deny" if denied else permission
        result["candidate"] = deepcopy(candidate)
        result["event"] = effective_event
    return result
