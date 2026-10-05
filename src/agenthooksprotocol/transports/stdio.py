"""Owned newline JSON subprocesses with cancellation-safe correlation."""

from typing import Any, Sequence
import json
import subprocess
import anyio
from anyio.streams.buffered import BufferedByteReceiveStream
from ..runtime import ProtocolError


class StdioTransport:
    def __init__(
        self,
        command: str,
        args: Sequence[str] = (),
        *,
        lifecycle: str = "persistent",
        cwd: str | None = None,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if lifecycle not in ("persistent", "per_event"):
            raise ValueError("Unknown stdio lifecycle")
        self.command = [command, *args]
        self.cwd = cwd
        self.lifecycle = lifecycle
        self.max_response_bytes = max_response_bytes
        self._lock = anyio.Lock()
        self._process = None
        self._reader = None
        self._closed = False

    async def _ready(self):
        if self._closed:
            raise RuntimeError("Transport is closed")
        if self._process is None:
            self._process = await anyio.open_process(
                self.command,
                cwd=self.cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            self._reader = BufferedByteReceiveStream(self._process.stdout)

    async def _reap(self):
        # Keep the serialization lock until the old process cannot answer again.
        with anyio.CancelScope(shield=True):
            process, self._process = self._process, None
            self._reader = None
            if process is not None:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await process.wait()
                await process.aclose()

    async def _exchange(self, message, response):
        async with self._lock:
            try:
                await self._ready()
                await self._process.stdin.send(
                    json.dumps(message, allow_nan=False, separators=(",", ":")).encode()
                    + b"\n"
                )
                if not response:
                    if self.lifecycle == "per_event":
                        await self._process.wait()
                    return None
                raw = await self._reader.receive_until(b"\n", self.max_response_bytes)
                value = json.loads(raw)
                if not isinstance(value, dict) or value.get("id") != message["id"]:
                    raise ProtocolError("Stdio response correlation mismatch")
                return value
            except BaseException:
                await self._reap()
                raise
            finally:
                if self.lifecycle == "per_event":
                    await self._reap()

    async def request(self, message: dict[str, Any]) -> dict[str, Any]:
        return await self._exchange(message, True)

    async def notify(self, message: dict[str, Any]) -> None:
        await self._exchange(message, False)

    async def aclose(self) -> None:
        async with self._lock:
            self._closed = True
            await self._reap()
