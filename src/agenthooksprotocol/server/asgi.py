"""Dependency-free ASGI HTTP adapter; mount with any ASGI framework/server."""

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from .hooks import Engine, Handler, HTTPError, encode


class App:
    """Serve hooks at the mounted path. Transport authentication belongs in middleware."""

    def __init__(
        self,
        handler: Handler,
        *,
        max_bytes: int = 4 * 1024 * 1024,
        **engine_options: Any,
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.engine = Engine(handler, **engine_options)
        self.max_bytes = max_bytes

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            raise ValueError("Only HTTP scopes are supported")
        try:
            if scope["method"] != "POST":
                raise HTTPError(405, b"POST required")
            body = bytearray()
            while True:
                event = await receive()
                if event["type"] == "http.disconnect":
                    return
                if event["type"] != "http.request":
                    raise HTTPError(400, b"Invalid HTTP body")
                chunk = event.get("body", b"")
                if len(body) + len(chunk) > self.max_bytes:
                    raise HTTPError(413, b"Request too large")
                body.extend(chunk)
                if not event.get("more_body", False):
                    break
            result = await self.engine.handle(bytes(body))
            status, payload, content_type = (
                (204, b"", None)
                if result is None
                else (200, encode(result), b"application/json")
            )
        except HTTPError as exc:
            status, payload, content_type = exc.status, exc.body, exc.content_type
        headers = [(b"content-length", str(len(payload)).encode())]
        if content_type is not None:
            headers.append((b"content-type", content_type))
        await send(
            {"type": "http.response.start", "status": status, "headers": headers}
        )
        await send({"type": "http.response.body", "body": payload})


def app(handler: Handler, **options: Any) -> App:
    return App(handler, **options)
