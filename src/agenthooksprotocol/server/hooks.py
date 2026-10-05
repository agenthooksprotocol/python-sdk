"""Canonical request dispatch shared by every public server transport.

Callbacks receive generated TypedDict wire values, not a parallel event model.
Capabilities describe a harness, not a backend; no discovery callback is exposed.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from ..generated import Effect, InterceptRequest, ObserveNotification
from ..runtime import ProtocolError, Validator
from ._json import loads


@dataclass
class InterceptResult:
    effects: Sequence[Effect | Mapping[str, Any]] = field(default_factory=list)
    extensions: dict[str, Any] | None = None


@dataclass
class Handler:
    intercept: Callable[[InterceptRequest], Awaitable[InterceptResult]] | None = None
    observe: Callable[[ObserveNotification], Awaitable[None]] | None = None
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


def error(code, message, id=None):
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def encode(value):
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
        handler: Handler,
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
            return error(-32700, "Parse error")
        return await self.process(message)

    async def process(self, message: Any) -> dict[str, Any] | None:
        """Shared dispatch for decoded messages and byte-oriented transports."""
        if not isinstance(message, dict):
            return error(-32600, "Invalid Request")
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
            return error(-32600, "Invalid Request")
        method = message["method"]
        kinds = {
            "hooks/intercept": "intercept-request",
            "hooks/observe": "observe-notification",
        }
        if method == "hooks/capabilities" and self.harness_manifest is not None:
            kinds[method] = "capabilities-request"
        if method not in kinds:
            return None if notification else error(-32601, "Method not found", id)
        try:
            self.validator.validate(kinds[method], message)
            if method == "hooks/intercept" and id != message["params"]["event"]["id"]:
                raise ProtocolError("Correlation mismatch")
        except ProtocolError:
            return None if notification else error(-32602, "Invalid params", id)
        try:
            if method == "hooks/observe":
                if self.handler.observe is not None:
                    await self.handler.observe(message)
                return None
            if method == "hooks/intercept":
                if self.handler.intercept is None:
                    return error(-32601, "Method not found", id)
                # Preserve correlation even if a callback edits its request.
                version = message["params"]["protocolVersion"]
                result = await self.handler.intercept(message)
                if not isinstance(result, InterceptResult):
                    raise TypeError("intercept must return InterceptResult")
                payload = {
                    "protocolVersion": version,
                    "effects": [dict(effect) for effect in result.effects],
                }
                if result.extensions is not None:
                    payload["extensions"] = result.extensions
                kind = "intercept-response"
            else:
                payload = {
                    "protocolVersion": message["params"]["protocolVersion"],
                    "manifest": deepcopy(self.harness_manifest),
                }
                kind = "capabilities-response"
            response = {"jsonrpc": "2.0", "id": id, "result": payload}
            self.validator.validate(kind, response)
            encode(response)
            return response
        except HTTPError:
            if notification:
                return None
            raise
        except Exception:  # noqa: BLE001 - contain callback/store failures, not cancellation
            return None if notification else error(-32603, "Internal error", id)
