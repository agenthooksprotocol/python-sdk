"""Invocation-owned immutable attachments, independent of transport storage."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any
import hashlib

from ._content import OwnedContentSource
from .runtime import ProtocolError


class Attachment(OwnedContentSource):
    """Immutable bytes owned by an inline attachment body.

    Ownership transfers on dispatch, once only. A successful result owns the
    attachment until aclose; unsuccessful dispatch closes it automatically.
    Metadata belongs on the input content item, not on the attachment.
    """

    _claimed = False

    @classmethod
    def from_bytes(cls, data: bytes, *, max_bytes: int = 4 * 1024 * 1024) -> Attachment:
        if not isinstance(data, bytes):
            raise TypeError("Attachment requires immutable bytes")

        result = cls.__new__(cls)
        result.stream = None
        result._initialize(max_bytes, 30.0)
        if len(data) > max_bytes:
            raise ValueError("Attachment exceeds max_bytes")
        result._snapshot = data
        return result

    def _retire_eager(self) -> None:
        """Release untransferred eager edit bytes during synchronous retirement.

        Only internally created from_bytes owners use this path: there is no
        unopened stream or cleanup callback to await.
        """
        if self.stream is not None or getattr(self, "_load", None) is not None:
            raise RuntimeError("Asynchronous sources require aclose")
        self._closed = True
        self._snapshot = None

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
        result = cls.__new__(cls)
        result.stream = None
        result._initialize(max_bytes, timeout)
        result._load = load
        result._cleanup = aclose
        return result

    async def _read_source(self) -> bytes:
        if self.stream is not None:
            return await super()._read_source()
        # The loader's immutable result becomes the attachment snapshot itself.
        # No stream adapter, staging buffer, or second byte owner is involved.
        return await self._load()

    async def _release_source(self) -> None:
        if self.stream is not None:
            await super()._release_source()
            return
        cleanup = getattr(self, "_cleanup", None)
        try:
            if cleanup is not None:
                await cleanup()
        finally:
            self._load = None
            self._cleanup = None


from ._models import _register_attachment_type  # noqa: E402

_register_attachment_type(Attachment)


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
