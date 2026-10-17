"""Endpoint-scoped registration metadata and harness-owned secret resolution."""

from copy import deepcopy
from dataclasses import dataclass, field
import inspect
import re
from typing import Any, Protocol

import anyio

from .runtime import OperationCancelledError, ProtocolError


class HeaderFailure(ProtocolError):
    """Invalid configuration or unavailable metadata, without secret diagnostics."""


@dataclass(frozen=True)
class HeaderContext:
    backend: dict[str, Any] = field(repr=False)
    destination: str
    source: str = field(repr=False)
    cancellation: anyio.CancelScope = field(repr=False)
    deadline: float
    purpose: str = "event"


class HeaderResolver(Protocol):
    async def resolve(self, context: HeaderContext) -> str: ...


def _value(value: Any, *, secret: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (secret and not value)
        or any(char in value for char in "\r\n\x00")
    ):
        raise HeaderFailure("Invalid HTTP header value")
    try:
        value.encode("latin-1")
    except UnicodeError:
        raise HeaderFailure("Unsupported HTTP header encoding") from None
    return value


def validate_headers(headers: Any, *, sources: bool = True) -> dict[str, Any]:
    if not isinstance(headers, dict):
        raise HeaderFailure("HTTP headers must be a map")
    normalized = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not re.fullmatch(
            r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name
        ):
            raise HeaderFailure("Invalid HTTP header name")
        key = name.lower()
        if isinstance(value, str):
            _value(value)
        elif sources and isinstance(value, dict):
            recognized = [key for key in ("valueEnv", "valueRef") if key in value]
            if len(recognized) != 1:
                raise HeaderFailure("Invalid HTTP header source")
            source = recognized[0]
            reference = value[source]
            if (
                source not in ("valueEnv", "valueRef")
                or not isinstance(reference, str)
                or not reference
            ):
                raise HeaderFailure("Invalid HTTP header source")
            if source == "valueEnv" and not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*", reference
            ):
                raise HeaderFailure("Invalid HTTP header source")
        else:
            raise HeaderFailure("Invalid HTTP header source")
        normalized[key] = deepcopy(value)
    return normalized


async def resolve_headers(
    headers,
    *,
    backend,
    destination,
    resolver=None,
    resolve_credential=None,
    purpose="event",
):
    from .auth import _resolve_secret

    resolved = {}
    with anyio.CancelScope() as cancellation:
        for name, source in headers.items():
            if isinstance(source, str):
                value = source
            else:
                try:
                    if "valueEnv" in source:
                        value = await _resolve_secret(
                            source, "valueEnv", "valueRef", resolve_credential
                        )
                    elif resolver is not None:
                        context = HeaderContext(
                            deepcopy(backend),
                            destination,
                            source["valueRef"],
                            cancellation,
                            anyio.current_effective_deadline(),
                            purpose,
                        )
                        value = resolver.resolve(context)
                        if inspect.isawaitable(value):
                            value = await value
                    else:
                        value = await _resolve_secret(
                            source, "valueEnv", "valueRef", resolve_credential
                        )
                    value = _value(value, secret=True)
                except OperationCancelledError:
                    raise
                except Exception:
                    raise HeaderFailure(
                        "Cannot resolve configured HTTP header"
                    ) from None
            await anyio.lowlevel.checkpoint()
            resolved[name] = value
    if cancellation.cancel_called:
        raise OperationCancelledError("HTTP header resolution cancelled")
    return resolved
