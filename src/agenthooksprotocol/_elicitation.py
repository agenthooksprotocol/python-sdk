"""MCP 2025-11-25 binding for selected serialized JSON text.

The validator and authenticated principal are supplied by the host.
`principal` is the transport-authenticated hook identity, not elicitation.server.
"""

import json
from copy import deepcopy
from decimal import Decimal
from . import _models
from .response import response_for_request

__all__ = []


def validate_exchange(request, result, resolve, validate, principal, effect=None):
    """Validate complete MCP bodies and enforce the pending boundary's grants.

    Returns unchanged payloads and explicit provenance; URL acceptance is *not*
    proof that an external workflow completed. `effect`, if supplied by a hook,
    must be return/deny on the request or modify on the result boundary.
    """
    if not isinstance(principal, str) or not principal:
        raise ValueError("Authenticated principal required")
    for envelope in (request, result):
        validate("intercept-request", envelope)
        if envelope["id"] != envelope["params"]["event"]["id"]:
            raise ValueError("Request/event ID mismatch")
    validate_correlation(request, result)
    req = request["params"]["event"]["elicitation"]
    res = result["params"]["event"]["elicitation"]
    if (
        request["params"]["event"]["type"] != "user.elicitation.request"
        or result["params"]["event"]["type"] != "user.elicitation.result"
    ):
        raise ValueError("Wrong elicitation boundary")
    payload = read_selected(req, "request", resolve, validate)
    answer = read_selected(res, "result", resolve, validate)
    if req["mode"] != res["mode"] or req["server"] != res["server"]:
        raise ValueError("Normalized metadata mismatch")
    if payload is None or answer is None:
        if effect is not None:
            raise ValueError("Effects require selected bodies")
        return {
            "selection": {
                "request": selection(req, "request"),
                "result": selection(res, "result"),
            },
            "bodyValidation": "not-selected",
            "provenance": {"kind": "mcp", "authenticatedSource": principal},
            "externalCompletion": False,
        }
    validate_answer(payload, answer, validate)
    mode = payload.get("mode", "form")
    if (
        req["mode"] != mode
        or res["mode"] != mode
        or req["server"] != res["server"]
        or res["action"] != answer["action"]
    ):
        raise ValueError("Normalized metadata mismatch")
    if (mode == "url" or answer["action"] != "accept") and "content" in answer:
        raise ValueError("Content is only permitted for accepted forms")
    provenance = {"kind": "mcp", "authenticatedSource": principal}
    if effect is not None:
        validate("effect", effect)
        kind = effect.get("type")
        boundary = result if kind == "modify" else request
        validate_mode(mode, boundary["params"]["capabilities"].get("elicitation"))
        if (
            kind not in ("return", "deny", "modify")
            or kind not in boundary["params"]["capabilities"]["effects"]
        ):
            raise ValueError("Effect not granted at this boundary")
        if kind == "modify" and (
            effect.get("target") != "content"
            or not boundary["params"]["capabilities"]
            .get("modify", {})
            .get("content", {})
            .get(effect.get("operation"), False)
        ):
            raise ValueError("Modify target/operation not granted")
        # An automated answer must never acquire human provenance.
        provenance = {"kind": "hook", "authenticatedSource": principal, "effect": kind}
    return deepcopy(
        {
            "request": payload,
            "result": answer,
            "provenance": provenance,
            "externalCompletion": False,
        }
    )


def validate_answer(request, answer, validate):
    """Validate submitted data, not schema defaults (which are annotations)."""
    validate("mcp-elicitation#result", answer)
    mode = request.get("mode", "form")
    if (mode == "url" or answer["action"] != "accept") and "content" in answer:
        raise ValueError("Content is only permitted for accepted forms")
    if mode == "form" and answer["action"] == "accept":
        validate(
            "form-answer",
            {"schema": request["requestedSchema"], "value": answer.get("content", {})},
        )


def validate_mode(mode, capabilities=None, origin="ahp"):
    """MCP's legacy empty form advertisement applies only at an MCP boundary."""
    if origin not in ("ahp", "mcp") or mode not in ("form", "url"):
        raise ValueError("Unknown origin or elicitation mode")
    caps = deepcopy(capabilities) if capabilities is not None else {}
    if not isinstance(caps, dict) or any(
        not isinstance(caps[k], dict) for k in ("form", "url") if k in caps
    ):
        raise ValueError("Invalid elicitation capabilities")
    if origin == "mcp" and capabilities == {}:
        caps = {"form": {}}
    if mode not in caps:
        raise ValueError("Elicitation mode not registered")
    return {key: value for key, value in caps.items() if key in ("form", "url")}


def apply_effects(
    request, result, resolve, validate, principal, effects, validate_result=None
):
    """Stage a request return/deny or result content modification atomically.

    No input is mutated. Nothing is published until the whole effect list and
    final MCP result validate. Hosts serialize the returned complete result into
    ordinary inline text. A request phase has result=None.
    """
    if (
        not isinstance(principal, str)
        or not principal
        or not isinstance(effects, list)
        or not effects
    ):
        raise ValueError("Authenticated effects required")
    validate("intercept-request", request)
    if (
        request["id"] != request["params"]["event"]["id"]
        or request["params"]["event"]["type"] != "user.elicitation.request"
    ):
        raise ValueError("Invalid request boundary")
    if result is not None:
        validate_correlation(request, result)
    meta = request["params"]["event"]["elicitation"]
    payload = read_selected(meta, "request", resolve, validate)
    if payload is None:
        raise ValueError("Effects require selected request body")
    if meta["mode"] != payload.get("mode", "form"):
        raise ValueError("Mode mismatch")
    boundary = request if result is None else result
    staged = (
        None
        if result is None
        else validate_exchange(request, result, resolve, validate, principal)["result"]
    )
    caps = boundary["params"]["capabilities"]
    validate_mode(meta["mode"], caps.get("elicitation"))
    correlated = response_for_request(
        boundary["params"]["event"]["type"],
        {
            "jsonrpc": "2.0",
            "id": boundary["id"],
            "result": {
                "protocolVersion": boundary["params"]["protocolVersion"],
                "effects": effects,
            },
        },
    )
    if not correlated["ok"]:
        raise ValueError("Invalid contextual MCP effects")
    effects = correlated["value"].result.effects
    kinds = []
    for effect in effects:
        validate("effect", effect)
        kind = effect["type"]
        if kind not in caps["effects"] or kind not in (
            ("return", "deny") if result is None else ("modify",)
        ):
            raise ValueError("Effect not granted at this boundary")
        if kind in ("return", "deny"):
            if kinds:
                raise ValueError("Conflicting terminal effects")
            staged = (
                deepcopy(effect.value)
                if kind == "return"
                else _models.McpElicitationElicitResult(action="decline")
            )
        else:
            operation = effect["operation"]
            if (
                effect["target"] != "content"
                or caps.get("modify", {}).get("content", {}).get(operation) is not True
            ):
                raise ValueError("Modify target/operation not granted")
            content = (
                deepcopy(effect.value)
                if operation == "replace"
                else {**staged.content, **effect.value}
            )
            staged = _models.McpElicitationElicitResult.from_dict(
                {**staged, "content": content}
            )
        validate_answer(payload, staged, validate)
        if validate_result is not None:
            validate_result(staged)
        kinds.append(kind)
    return {
        "request": payload,
        "result": staged,
        "provenance": {
            "kind": "hook",
            "authenticatedSource": principal,
            "effects": kinds,
        },
        "externalCompletion": False,
    }


def selection(meta, stage):
    return meta.get(stage, {}).get("selection", "omit")


def read_selected(meta, stage, resolve, validate):
    """Parse selected inline text only. Selected gaps fail closed by default."""
    item = meta.get(stage)
    if item is None:
        return None
    validate("content-item", item)
    if item["kind"] != "text" or item["mediaType"] != "text/plain":
        raise ValueError("MCP payload must be serialized ordinary text")
    if item["selection"] != "body":
        return None
    if "text" not in item:
        raise ValueError("Selected body unavailable (fail closed)")

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError("Duplicate JSON key")
            out[k] = v
        return out

    def invalid(_):
        raise ValueError("Non JSON number")

    payload = json.loads(
        item["text"],
        object_pairs_hook=pairs,
        parse_float=Decimal,
        parse_constant=invalid,
    )
    validate("mcp-elicitation#" + stage, payload)
    if stage == "result":
        payload = _models.McpElicitationElicitResult.from_dict(payload)
    elif meta["mode"] == "form":
        payload = _models.McpElicitationElicitRequestFormParams.from_dict(payload)
    elif meta["mode"] == "url":
        payload = _models.McpElicitationElicitRequestURLParams.from_dict(payload)
    else:
        raise ValueError("Unknown MCP request mode")
    if stage == "request" and meta["mode"] != payload.get("mode", "form"):
        raise ValueError("Mode mismatch")
    if stage == "result":
        if meta["action"] != payload["action"]:
            raise ValueError("Action mismatch")
        if (
            meta["mode"] == "url" or payload["action"] != "accept"
        ) and "content" in payload:
            raise ValueError("Forbidden content")
    return payload


def validate_correlation(request, result):
    """Bind a result to one source-scoped request before resolving any bytes."""
    req, res = request["params"]["event"], result["params"]["event"]
    if (
        not isinstance(res.get("parentEventId"), str)
        or res["parentEventId"] != req["id"]
        or res["source"] != req["source"]
        or res.get("session", {}).get("id") != req.get("session", {}).get("id")
    ):
        raise ValueError("Elicitation parent/source/session mismatch")
