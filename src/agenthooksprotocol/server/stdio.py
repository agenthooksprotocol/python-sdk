"""Bounded UTF-8 NDJSON over AnyIO byte streams (asyncio and Trio).

``await serve(handler)`` borrows ``sys.stdin.buffer`` / ``sys.stdout.buffer``.
Explicit input/output are borrowed AnyIO ByteReceiveStream/ByteSendStream objects.
No supplied or default stream is ever closed. Default POSIX pipes use cancellable descriptor readiness, without changing flags
or closing descriptors. They require exclusive access and no prior buffered I/O.
Other default streams run in worker threads; cancellation waits for an in-progress
blocking operation rather than leaving an abandoned reader on a borrowed stream.
Messages are processed serially: output.send completes before the next callback.
EOF with an unterminated record is a framing error, not an implicit newline.
"""

import base64
import os
import stat
import sys
from typing import Any

import anyio
from anyio.abc import ByteReceiveStream, ByteSendStream

from ._json import loads
from .hooks import Engine, Handler, HTTPError, encode, error


def _pipe_fd(stream):
    # Never change descriptor flags or close caller-owned descriptors.
    try:
        fd = stream.fileno()
        return (
            fd if os.name == "posix" and stat.S_ISFIFO(os.fstat(fd).st_mode) else None
        )
    except (AttributeError, OSError, ValueError):
        return None


class _Input:
    def __init__(self):
        self.stream = sys.stdin.buffer
        self.fd = _pipe_fd(self.stream)

    async def receive(self, max_bytes):
        if self.fd is not None:
            while True:
                await anyio.wait_readable(self.fd)
                try:
                    data = os.read(self.fd, max_bytes)
                    break
                except BlockingIOError:
                    continue
        else:
            data = await anyio.to_thread.run_sync(self.stream.read1, max_bytes)
        if not data:
            raise anyio.EndOfStream
        return data


class _Output:
    def __init__(self):
        self.stream = sys.stdout.buffer
        self.fd = _pipe_fd(self.stream)

    async def send(self, data):
        if self.fd is not None:
            view = memoryview(data)
            # POSIX guarantees at least 512 bytes of atomic pipe capacity.
            # After writable readiness, a <=512-byte write cannot block when
            # this server has exclusive use of the borrowed output pipe.
            while view:
                await anyio.wait_writable(self.fd)
                try:
                    count = os.write(self.fd, view[:512])
                except BlockingIOError:
                    continue
                if not count:
                    raise OSError("stdout made no progress")
                view = view[count:]
            return

        def write():
            view = memoryview(data)
            while view:
                count = self.stream.write(view)
                if not count:
                    raise OSError("stdout made no progress")
                view = view[count:]
            self.stream.flush()

        await anyio.to_thread.run_sync(write)


def _http_error_response(exc, id):
    try:
        body = loads(exc.body.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        body = None
    if (
        isinstance(body, dict)
        and body.get("jsonrpc") == "2.0"
        and type(body.get("id")) is type(id)
        and body.get("id") == id
        and "result" not in body
        and isinstance(body.get("error"), dict)
        and type(body["error"].get("code")) is int
        and isinstance(body["error"].get("message"), str)
    ):
        return body
    response = error(-32603, "HTTP handler error", id)
    details = {"httpStatus": exc.status}
    try:
        details["body"] = exc.body.decode("utf-8")
    except UnicodeError:
        details["bodyBase64"] = base64.b64encode(exc.body).decode("ascii")
    response["error"]["data"] = details
    return response


async def serve(
    handler: Handler,
    *,
    input: ByteReceiveStream | None = None,
    output: ByteSendStream | None = None,
    max_bytes: int = 4 * 1024 * 1024,
    **engine_options: Any,
) -> None:
    """Serve until EOF. An overlong/unterminated frame raises ValueError.

    Invalid JSON/UTF-8 within a bounded frame produces a JSON-RPC parse error.
    HTTPError bodies preserve correlated JSON-RPC errors; other bodies are
    carried as internal-error data with their HTTP status (binary as base64).
    Output is bounded as well; an oversized response becomes an internal error.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    source = input if input is not None else _Input()
    sink = output if output is not None else _Output()
    engine = Engine(handler, **engine_options)
    pending = bytearray()
    while True:
        try:
            chunk = await source.receive(min(65536, max_bytes + 1 - len(pending)))
        except anyio.EndOfStream:
            if pending:
                raise ValueError("Unterminated NDJSON record") from None
            return
        if not chunk:
            if pending:
                raise ValueError("Unterminated NDJSON record")
            return
        # Reject a stream that does not respect the requested read bound.
        if len(chunk) > min(65536, max_bytes + 1 - len(pending)):
            raise ValueError("Input stream exceeded read bound")
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending = bytearray(rest)
            if len(line) > max_bytes:
                raise ValueError("NDJSON record too large")
            try:
                result = await engine.handle(bytes(line))
            except HTTPError as exc:
                message = loads(line.decode("utf-8"))
                result = (
                    _http_error_response(exc, message["id"])
                    if "id" in message
                    else None
                )
            if result is not None:
                data = encode(result)
                if len(data) > max_bytes:
                    data = encode(error(-32603, "Response too large", result.get("id")))
                    if len(data) > max_bytes:
                        raise ValueError("Output limit cannot fit an error response")
                await sink.send(data + b"\n")
        if len(pending) > max_bytes:
            raise ValueError("NDJSON record too large")
