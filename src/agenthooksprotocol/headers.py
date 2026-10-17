"""Endpoint-scoped registration metadata and harness-owned secret resolution."""

from copy import deepcopy
from dataclasses import dataclass, field
import inspect
import os
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


_RESERVED = {
    "authorization",
    "cookie",
    "set-cookie",
    "host",
    "content-type",
    "accept",
    "content-length",
    "content-encoding",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "origin",
    "referer",
}
_MAX_BYTES = 65536


def _value(value: Any, *, secret: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (secret and not value)
        or any(not 0x20 <= ord(char) <= 0x7E for char in value)
    ):
        raise HeaderFailure("Invalid HTTP header value")
    return value


def validate_headers(headers: Any, *, sources: bool = True) -> dict[str, Any]:
    if not isinstance(headers, dict):
        raise HeaderFailure("HTTP headers must be a map")
    seen = set()
    size = 0
    for name, value in headers.items():
        if not isinstance(name, str) or not re.fullmatch(
            r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name
        ):
            raise HeaderFailure("Invalid HTTP header name")
        key = name.lower()
        if (
            key in seen
            or key in _RESERVED
            or key.startswith(("proxy-", "sec-", "ahp-"))
        ):
            raise HeaderFailure("Duplicate or reserved HTTP header name")
        seen.add(key)
        if isinstance(value, str):
            _value(value)
            size += len(name) + len(value) + 4
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
            size += len(name) + len(reference) + 4
        else:
            raise HeaderFailure("Invalid HTTP header source")
        if size > _MAX_BYTES:
            raise HeaderFailure("HTTP header size limit exceeded")
    return deepcopy(headers)


async def resolve_headers(headers, *, backend, destination, resolver=None):
    resolved = {}
    size = 0
    with anyio.CancelScope() as cancellation:
        for name, source in headers.items():
            if isinstance(source, str):
                value = source
            else:
                try:
                    if "valueEnv" in source:
                        value = os.environ.get(source["valueEnv"])
                    elif resolver is not None:
                        context = HeaderContext(
                            deepcopy(backend),
                            destination,
                            source["valueRef"],
                            cancellation,
                            anyio.current_effective_deadline(),
                        )
                        value = resolver.resolve(context)
                        if inspect.isawaitable(value):
                            value = await value
                    else:
                        raise HeaderFailure("HTTP header resolver required")
                    value = _value(value, secret=True)
                except OperationCancelledError:
                    raise
                except Exception:
                    raise HeaderFailure(
                        "Cannot resolve configured HTTP header"
                    ) from None
            await anyio.lowlevel.checkpoint()
            size += len(name) + len(value) + 4
            if size > _MAX_BYTES:
                raise HeaderFailure("HTTP header size limit exceeded")
            resolved[name] = value
    if cancellation.cancel_called:
        raise OperationCancelledError("HTTP header resolution cancelled")
    return resolved
