"""Verified, bounded attachment ingress with explicit caller-owned storage.

``parse(headers, body)`` is an async context manager over a borrowed async byte
iterator. It yields only after EOF, canonical framing and size/hash verification.
It buffers at most max_bytes and never closes the iterator.

``receive(..., authorize=..., storage=...)`` first awaits authorize(credentials),
which returns (201, non-None scope), (401, None), or (403, None). It allocates an
opaque reference and awaits storage.commit(scope=..., ref=..., data=bytes) after
verification. Commit MUST atomically publish immutable bytes, scoped to the
principal, and MUST NOT replace an existing reference. The caller chooses memory,
filesystem, object storage, or another persistence policy; durability is not an
SDK requirement. Failed/cancelled commits must not expose partial data. If a
commit succeeds but the response is lost, an orphan reference is possible; the
storage implementation owns retention and garbage collection.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from email.message import Message
from typing import Any, Protocol
from uuid import uuid4

from ..runtime import ProtocolError, Validator
from ._framing import validate_upload_framing
from .hooks import HTTPError, encode


class Storage(Protocol):
    async def commit(self, *, scope: object, ref: str, data: bytes) -> None:
        """Atomically publish immutable bytes under receiver-allocated ref."""
        ...


@dataclass(frozen=True)
class VerifiedUpload:
    data: bytes
    size: int
    sha256: str


def _headers(headers):
    result = Message()
    pairs = headers.items() if hasattr(headers, "items") else headers
    for key, value in pairs:
        try:
            key = key.decode("ascii") if isinstance(key, bytes) else key
        except UnicodeError as exc:
            raise HTTPError(400, b"Invalid upload headers") from exc
        value = value.decode("latin-1") if isinstance(value, bytes) else value
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or any(c in key + value for c in "\r\n")
        ):
            raise HTTPError(400, b"Invalid upload headers")
        result[key] = value
    return result


@asynccontextmanager
async def parse(
    headers: Any, body: AsyncIterator[bytes], *, max_bytes: int = 4 * 1024 * 1024
) -> AsyncIterator[VerifiedUpload]:
    """Verify exact octets through EOF before yielding a VerifiedUpload."""
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    try:
        headers = _headers(headers)
        declared = headers.get("Content-Length", "")
        if not re.fullmatch(r"0|[1-9][0-9]*", declared):
            raise HTTPError(400, b"Invalid Content-Length")
        size = int(declared)
        if size > max_bytes:
            raise HTTPError(413, b"Upload too large")
        # Reuse the canonical framing validator before consuming any bytes;
        # substitute empty size/hash solely for this framing-only check.
        framing = Message()
        for key, value in headers.items():
            framing[key] = (
                "0"
                if key.lower() == "content-length"
                else hashlib.sha256(b"").hexdigest()
                if key.lower() == "ahp-content-sha256"
                else value
            )
        validate_upload_framing(framing, b"")
        if not re.fullmatch(r"[a-f0-9]{64}", headers.get("AHP-Content-SHA256", "")):
            raise HTTPError(400, b"Invalid upload hash")
        data = bytearray()
        async for chunk in body:
            if not isinstance(chunk, bytes):
                raise HTTPError(400, b"Upload body must contain bytes")
            if len(data) + len(chunk) > max_bytes:
                raise HTTPError(413, b"Upload too large")
            if len(data) + len(chunk) > size:
                raise HTTPError(400, b"Upload length mismatch")
            data.extend(chunk)
        raw = bytes(data)
        validate_upload_framing(headers, raw)
    except (ProtocolError, ValueError, UnicodeError) as exc:
        raise HTTPError(400, b"Invalid upload framing") from exc
    yield VerifiedUpload(raw, len(raw), hashlib.sha256(raw).hexdigest())


async def receive(
    headers: Any,
    body: AsyncIterator[bytes],
    *,
    authorize: Callable[[str | None], Awaitable[tuple[int, object | None]]],
    storage: Storage,
    max_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    """Return a canonical descriptor only after authorization, EOF and commit."""
    headers = _headers(headers)
    if len(headers.get_all("Authorization", [])) > 1:
        raise HTTPError(400, b"Duplicate authorization")
    status, scope = await authorize(headers.get("Authorization"))
    if status != 201 or scope is None:
        raise HTTPError(
            status if status in (401, 403) else 403, b"Upload not authorized"
        )
    async with parse(headers, body, max_bytes=max_bytes) as upload:
        ref = "ahp-attachment:" + uuid4().hex
        descriptor = {"ref": ref, "size": upload.size, "sha256": upload.sha256}
        Validator().validate("content-reference", descriptor)
        await storage.commit(scope=scope, ref=ref, data=upload.data)
        return descriptor


class App:
    """Mountable ASGI upload endpoint. Successful commits return HTTP 201.

    Unexpected storage errors return 500 without disclosing exception details.
    Disconnect and cancellation abort before commit whenever detected during read.
    """

    def __init__(
        self,
        *,
        authorize: Callable[[str | None], Awaitable[tuple[int, object | None]]],
        storage: Storage,
        max_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        self.authorize = authorize
        self.storage = storage
        self.max_bytes = max_bytes

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive_event: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            raise ValueError("Only HTTP scopes are supported")

        async def body():
            while True:
                event = await receive_event()
                if event["type"] == "http.disconnect":
                    raise _Disconnected
                if event["type"] != "http.request":
                    raise HTTPError(400, b"Invalid HTTP body")
                yield event.get("body", b"")
                if not event.get("more_body", False):
                    return

        try:
            if scope["method"] != "POST":
                raise HTTPError(405, b"POST required")
            descriptor = await receive(
                scope.get("headers", []),
                body(),
                authorize=self.authorize,
                storage=self.storage,
                max_bytes=self.max_bytes,
            )
            status, payload, content_type = 201, encode(descriptor), b"application/json"
        except _Disconnected:
            return
        except HTTPError as exc:
            status, payload, content_type = exc.status, exc.body, exc.content_type
        except Exception:  # noqa: BLE001 - contain callback/store failures, not cancellation
            status, payload, content_type = 500, b"Upload failed", b"text/plain"
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", content_type),
                    (b"content-length", str(len(payload)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})


class _Disconnected(Exception):
    pass
