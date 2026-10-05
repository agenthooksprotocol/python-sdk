"""Verify streamed binary upload and caller-owned immutable storage in-process."""

from collections.abc import AsyncIterator
import hashlib
import json
from typing import Any

import anyio
import httpx
from agenthooksprotocol.server import attachments
from agenthooksprotocol.transports.http import HTTPTransport


class Store:
    def __init__(self) -> None:
        self.blobs: dict[tuple[object, str], bytes] = {}

    async def commit(self, *, scope: object, ref: str, data: bytes) -> None:
        key = (scope, ref)
        if key in self.blobs:
            raise ValueError("immutable reference already exists")
        self.blobs[key] = bytes(data)


async def authorize(authorization: str | None) -> tuple[int, object | None]:
    return (
        (201, "upload-principal")
        if authorization == "Bearer upload-only"
        else (403, None)
    )


async def main() -> None:
    data = b"\x00\xff\xfe\x80reviewed content"
    reads = 0

    async def body() -> AsyncIterator[bytes]:
        nonlocal reads
        reads += 1
        yield data[:4]
        yield data[4:]

    store = Store()
    app = attachments.App(authorize=authorize, storage=store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        headers={"Authorization": "Bearer event-only"},
    ) as client:
        transport = HTTPTransport(
            "http://event.test/hooks",
            client=client,
            headers={"Authorization": "Bearer event-only"},
        )
        # Selection must not open or consume an application body stream.
        await transport.upload(
            "http://upload.test/content", body(), selection="metadata"
        )
        assert reads == 0
        descriptor: dict[str, Any] | None = await transport.upload(
            "http://upload.test/content",
            body(),
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            headers={"Authorization": "Bearer upload-only"},
        )
        assert descriptor is not None
        assert store.blobs[("upload-principal", descriptor["ref"])] == data
        assert reads == 1
        print(
            json.dumps(
                {
                    "size": descriptor["size"],
                    "sha256": descriptor["sha256"],
                    "verified": True,
                    "committed": True,
                    "bodyReads": reads,
                }
            )
        )


if __name__ == "__main__":
    anyio.run(main)
