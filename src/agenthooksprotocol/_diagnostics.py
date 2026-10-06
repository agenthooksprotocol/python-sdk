"""Structured delivery evidence; never backend messages, response data or secrets."""

from __future__ import annotations

from typing import Literal, TypedDict

from .diagnostics import Code
from .runtime import BackendRPCError, ProtocolError


def _is_timeout(exc: Exception | None) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    try:
        import httpx
    except ImportError:
        return False
    return isinstance(exc, httpx.TimeoutException)


class Diagnostic(TypedDict):
    code: Code
    stage: str
    backend: str
    subscription: int | None
    mode: Literal["intercept", "observe"]
    error: str
    failure_policy: str | None
    synthetic_denial: bool


class ContentPreparationError(ProtocolError):
    """Failure preparing selected content, without retaining raw source errors."""

    def __init__(self, message: str, *, cause: Exception | None = None):
        from .auth import AuthenticationFailure, TransportFailure

        self.code = (
            Code.DEADLINE_EXCEEDED
            if _is_timeout(cause)
            else Code.TRANSPORT
            if isinstance(cause, (AuthenticationFailure, TransportFailure, OSError))
            else Code.REMOTE_RPC
            if isinstance(cause, BackendRPCError)
            else Code.PREPARATION
        )
        super().__init__(message)


class ContentPreparationTimeout(TimeoutError):
    """A shorter selected-content phase deadline elapsed."""


def delivery_diagnostic(
    exc: Exception,
    *,
    backend: str,
    subscription: int | None,
    mode: Literal["intercept", "observe"],
    stage: str = "delivery",
    failure_policy: str | None = None,
    synthetic_denial: bool = False,
) -> Diagnostic:
    from .auth import AuthenticationFailure, TransportFailure

    if _is_timeout(exc):
        code = Code.DEADLINE_EXCEEDED
        if isinstance(exc, ContentPreparationTimeout):
            stage = "content"
    elif isinstance(exc, BackendRPCError):
        code = Code.REMOTE_RPC
    elif isinstance(exc, ContentPreparationError):
        code = exc.code
        stage = "content"
    elif isinstance(exc, AuthenticationFailure):
        code = Code.TRANSPORT
        stage = "authentication"
    elif isinstance(exc, TransportFailure):
        code = Code.TRANSPORT
    elif isinstance(exc, ProtocolError):
        code = Code.PROTOCOL_REJECTION
    else:
        code = Code.TRANSPORT
    return {
        "code": code,
        "stage": stage,
        "backend": backend,
        "subscription": subscription,
        "mode": mode,
        "error": type(exc).__name__,
        "failure_policy": failure_policy,
        "synthetic_denial": synthetic_denial,
    }
