"""Canonical request dispatch shared by every public server transport.

Callbacks receive event-specific contexts with lossless generated wire models.
Capabilities describe a harness, not a backend; no discovery callback is exposed.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .. import _models as models
from .._outcomes import decode_event
from ..generated import PROTOCOL_VERSION
from ..runtime import ProtocolError, Validator, _validate_intercept_response
from ._admission import validate_grants
from ._handlers import *  # noqa: F403 - explicit event-specific public facade
from ._handlers import (
    InterceptHandlers,
    ObserveHandlers,
    _INTERCEPT_CONTEXTS,
    _OBSERVE_CONTEXTS,
    __all__ as _handler_exports,
)
from ._json import loads


@dataclass(slots=True, kw_only=True)
class Handlers:
    """Declarative, event-specific callbacks shared by all server transports."""

    intercept: InterceptHandlers = field(default_factory=InterceptHandlers)
    observe: ObserveHandlers = field(default_factory=ObserveHandlers)
    _engine: Engine | None = field(default=None, init=False, repr=False, compare=False)

    async def __call__(self, body: bytes) -> dict[str, Any] | None:
        """Dispatch a UTF-8 JSON message; return a response dict or None."""
        if self._engine is None:
            self._engine = Engine(self)
        return await self._engine.handle(body)

    async def process(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        """Validate and dispatch an already decoded canonical request."""
        if self._engine is None:
            self._engine = Engine(self)
        return await self._engine.process(request)


__all__ = ["Handlers", "Engine", "HTTPError", *_handler_exports]


class HTTPError(Exception):
    """An explicit transport failure; ASGI emits its body even for non-2xx status."""

    def __init__(
        self,
        status: int,
        body: bytes = b"",
        *,
        content_type: bytes = b"text/plain; charset=utf-8",
    ) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body
        self.content_type = content_type


def _error(code, message, id=None, data=None):
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": error}


class _CallbackError(Exception):
    """A backend callback raised; mapped to ``backend_internal_error``."""


async def _invoke(callback, context):
    try:
        result = callback(context)
        if inspect.isawaitable(result):
            result = await result
    except HTTPError:
        raise
    except Exception as exc:  # noqa: BLE001 - contain callback failures, not cancellation
        raise _CallbackError from exc
    return result


def _encode(value):
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")


class Engine:
    """Validate and dispatch one JSON-RPC message (batches are unsupported).

    ``harness_manifest`` is an optional *static harness* manifest. It is never
    synthesized from backend callbacks. Cancellation always propagates.
    """

    def __init__(
        self,
        handler: Handlers,
        *,
        validator: Validator | None = None,
        harness_manifest: dict[str, Any] | None = None,
    ) -> None:
        self.handler = handler
        self.validator = validator if validator is not None else Validator()
        self.harness_manifest = deepcopy(harness_manifest)

    async def handle(self, body: bytes) -> dict[str, Any] | None:
        try:
            message = loads(body.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            return _error(-32700, "Parse error")
        return await self.process(message)

    async def process(self, message: Any) -> dict[str, Any] | None:
        """Shared dispatch for decoded messages and byte-oriented transports."""
        if not isinstance(message, dict):
            return _error(-32600, "Invalid Request")
        # Only a valid JSON-RPC envelope can claim notification semantics.
        notification = (
            message.get("jsonrpc") == "2.0"
            and isinstance(message.get("method"), str)
            and "id" not in message
        )
        id = message.get("id")
        if (
            message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
            or ("id" in message and (type(id) not in (str, int) and id is not None))
        ):
            return _error(-32600, "Invalid Request")
        method = message["method"]
        kinds = {
            "hooks/intercept": "intercept-request",
            "hooks/observe": "observe-notification",
        }
        if method == "hooks/capabilities" and self.harness_manifest is not None:
            kinds[method] = "capabilities-request"
        if method not in kinds:
            return None if notification else _error(-32601, "Method not found", id)
        params = message.get("params")
        version = params.get("protocolVersion") if isinstance(params, dict) else None
        if isinstance(version, str) and version != PROTOCOL_VERSION:
            # Notifications are never answered, and their semantics are not processed.
            if notification:
                return None
            return _error(
                -32001,
                "Unsupported AHP protocol version",
                id,
                {"supported": [PROTOCOL_VERSION]},
            )
        event = params.get("event") if isinstance(params, dict) else None
        event_type = event.get("type") if isinstance(event, dict) else None
        if (
            method == "hooks/intercept"
            and not notification
            and isinstance(event_type, str)
            and event_type not in _INTERCEPT_CONTEXTS
        ):
            return _error(-32002, "Unsupported event", id)
        try:
            self.validator.validate(kinds[method], message)
            if method == "hooks/intercept" and id != message["params"]["event"]["id"]:
                raise ProtocolError("Correlation mismatch")
        except ProtocolError:
            return None if notification else _error(-32602, "Invalid params", id)
        try:
            # The engine owns a detached snapshot: callback mutation cannot change
            # correlation, contextual validation, or request-time grants.
            original = deepcopy(message)
            params = original.get("params", {})
            event_type = params.get("event", {}).get("type")
            field_name = (
                event_type.replace(".", "_") if isinstance(event_type, str) else ""
            )
            if method == "hooks/observe":
                context_type = _OBSERVE_CONTEXTS.get(event_type)
                callback = (
                    getattr(self.handler.observe, field_name, None)
                    if context_type is not None
                    else None
                )
                if callback is None:
                    callback = self.handler.observe.any
                if callback is not None and context_type is not None:
                    envelope = models.ObserveNotification.from_dict(deepcopy(original))
                    context = context_type(
                        event=decode_event(deepcopy(params["event"])),
                        params=envelope.params,
                        envelope=envelope,
                        raw=deepcopy(original),
                    )
                    result = await _invoke(callback, context)
                    if result is not None:
                        raise TypeError("observe callbacks must return None")
                return None
            if method == "hooks/intercept":
                callback = getattr(self.handler.intercept, field_name, None)
                spec = _INTERCEPT_CONTEXTS.get(event_type)
                if callback is None or spec is None:
                    return _error(-32002, "Unsupported event", id)
                context_type, reply_type, capabilities_type, state_type = spec
                envelope = models.InterceptRequest.from_dict(deepcopy(original))
                context = context_type(
                    event=decode_event(deepcopy(params["event"])),
                    capabilities=capabilities_type.from_dict(
                        deepcopy(params["capabilities"])
                    ),
                    state=state_type.from_dict(deepcopy(params["state"]))
                    if "state" in params
                    else None,
                    params=envelope.params,
                    envelope=envelope,
                    raw=deepcopy(original),
                )
                result = await _invoke(callback, context)
                if type(result) is not reply_type:
                    raise TypeError("callback must return its event-specific Reply")
                if not isinstance(result.effects, tuple) or any(
                    not isinstance(effect, models._WireModel)
                    for effect in result.effects
                ):
                    raise TypeError(
                        "effects must be a tuple of generated effect models"
                    )
                payload = {
                    "protocolVersion": params["protocolVersion"],
                    "effects": [dict(effect) for effect in result.effects],
                }
                if result.extensions is not None:
                    payload["extensions"] = deepcopy(result.extensions)
                kind = "intercept-response"
            else:
                payload = {
                    "protocolVersion": message["params"]["protocolVersion"],
                    "manifest": deepcopy(self.harness_manifest),
                }
                kind = "capabilities-response"
            response = {"jsonrpc": "2.0", "id": id, "result": payload}
            self.validator.validate(kind, response)
            if kind == "intercept-response":
                _validate_intercept_response(self.validator, original, response)
                validate_grants(original, response)
            _encode(response)
            return response
        except HTTPError:
            if notification:
                return None
            raise
        except _CallbackError:
            # Never echo callback exception text: it may carry secrets.
            return (
                None if notification else _error(-32004, "Backend internal error", id)
            )
        except Exception:  # noqa: BLE001 - SDK invariant failures, not cancellation
            return None if notification else _error(-32603, "Internal error", id)
