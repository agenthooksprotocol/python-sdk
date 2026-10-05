"""Async transport contract. Injected transports are borrowed, never closed."""

from typing import Protocol, Any
from .stdio import StdioTransport
from .http import HTTPTransport


class Transport(Protocol):
    async def request(self, message: dict[str, Any]) -> dict[str, Any]: ...
    async def notify(self, message: dict[str, Any]) -> None: ...
    async def aclose(self) -> None: ...


__all__ = ["Transport", "StdioTransport", "HTTPTransport"]
