"""Invocation-owned immutable attachments, independent of transport storage."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any
import hashlib

from ._content import OwnedContentSource
from .runtime import ProtocolError


class _LazyBytes:
    def __init__(
        self,
        load: Callable[[], Awaitable[bytes]],
        close: Callable[[], Awaitable[None]] | None,
    ) -> None:
        self.load = load
        self.close = close
        self.data: bytes | None = None
        self.offset = 0

    async def read(self, size: int) -> bytes:
        if self.data is None:
            self.data = await self.load()
            if not isinstance(self.data, bytes):
                raise TypeError("Attachment loader must return immutable bytes")
        part = self.data[self.offset : self.offset + size]
        self.offset += len(part)
        return part

    async def aclose(self) -> None:
        try:
            if self.close is not None:
                await self.close()
        finally:
            self.data = None
            self.load = None  # type: ignore[assignment]
            self.close = None


class Attachment(OwnedContentSource):
    """Bind with an input's existing bind_*_source method.

    Ownership transfers on dispatch, once only. A successful result owns the
    attachment until aclose; unsuccessful dispatch closes it automatically.
    Metadata belongs on the input content item, not on the attachment.
    """

    _claimed = False

    @classmethod
    def from_bytes(cls, data: bytes, *, max_bytes: int = 4 * 1024 * 1024) -> Attachment:
        if not isinstance(data, bytes):
            raise TypeError("Attachment requires immutable bytes")

        async def load() -> bytes:
            return data

        result = cls.lazy(load, max_bytes=max_bytes)
        if len(data) > max_bytes:
            raise ValueError("Attachment exceeds max_bytes")
        result._snapshot = data
        return result

    @classmethod
    def lazy(
        cls,
        load: Callable[[], Awaitable[bytes]],
        *,
        aclose: Callable[[], Awaitable[None]] | None = None,
        max_bytes: int = 4 * 1024 * 1024,
        timeout: float = 30.0,
    ) -> Attachment:
        """Evaluate load at most once on demand; close even if never loaded.

        The loader must bound its own allocations. max_bytes bounds accepted
        bytes, and timeout bounds loading. Use an owned stream for streaming.
        """
        if not callable(load) or (aclose is not None and not callable(aclose)):
            raise TypeError("Attachment callbacks must be callable")
        return cls(_LazyBytes(load, aclose), max_bytes=max_bytes, timeout=timeout)


class AttachmentContents:
    """Result-owned content addressed by generated source slot names."""

    def __init__(
        self,
        bindings: Mapping[str, Attachment],
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self._bindings = dict(bindings)
        self._metadata = dict(metadata or {})
        self._closed = False

    async def read(self, slot: str) -> bytes:
        if self._closed:
            raise ProtocolError("Result attachments are closed")
        data = await self._bindings[slot].snapshot()
        item = self._metadata.get(slot, {})
        if any(
            key in item and item[key] != value
            for key, value in (
                ("size", len(data)),
                ("sha256", hashlib.sha256(data).hexdigest()),
            )
        ):
            raise ProtocolError("Attachment metadata disagrees with actual bytes")
        return data

    async def aclose(self) -> None:
        import anyio

        self._closed = True
        try:
            with anyio.CancelScope(shield=True):
                async with anyio.create_task_group() as group:
                    for attachment in set(self._bindings.values()):
                        group.start_soon(attachment.aclose)
        finally:
            self._bindings.clear()
            self._metadata.clear()

    async def __aenter__(self) -> AttachmentContents:
        if self._closed:
            raise ProtocolError("Result attachments are closed")
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()
