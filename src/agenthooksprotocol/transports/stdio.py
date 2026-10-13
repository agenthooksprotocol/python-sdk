"""Owned newline JSON subprocesses with cancellation-safe correlation.

Each child has one background reader that owns its stdout for the child's
lifetime. Response frames are routed to the waiting request by JSON-RPC ``id``;
unsolicited or uncorrelated frames are discarded with a warning on the
``agenthooksprotocol.transports.stdio`` logger (size only, never content) and are
never consumed as the next response or cause a respawn. A closed stdout or an
overlong record fails the pending request; the child is replaced on next use.

Children receive a minimal base environment (an allowlist of host variables
such as ``PATH``, ``HOME``, locale and temp-directory settings) plus the
registration ``env`` entries, which override base values. The full host
environment is inherited only with ``inherit_environment=True``. Environment
values are never logged.
"""

from collections.abc import Mapping
from typing import Any, Sequence
import json
import logging
import os
import subprocess

import anyio
import sniffio
from anyio.streams.buffered import BufferedByteReceiveStream

from ..runtime import ProtocolError

_log = logging.getLogger(__name__)


def _key(id: Any) -> tuple[str, Any]:
    # JSON-RPC ids are strings or numbers; keep 1 and "1" (and True) distinct.
    return (type(id).__name__, id)


class _Slot:
    def __init__(self) -> None:
        self.event = anyio.Event()
        self.value: dict[str, Any] | None = None
        self.error: Exception | None = None

    def resolve(self, value=None, error=None) -> None:
        if not self.event.is_set():
            self.value, self.error = value, error
            self.event.set()

    async def wait(self) -> dict[str, Any]:
        await self.event.wait()
        if self.error is not None:
            raise self.error
        assert self.value is not None
        return self.value


def _spawn(function) -> Any:
    """Start a detached task on the running AnyIO backend; return a handle."""
    if sniffio.current_async_library() == "trio":
        import trio

        trio.lowlevel.spawn_system_task(function)
        return None
    import asyncio

    return asyncio.get_running_loop().create_task(function())


class _Child:
    def __init__(self, process, max_bytes: int) -> None:
        self.process = process
        self.max_bytes = max_bytes
        self.pending: dict[tuple[str, Any], _Slot] = {}
        self.failure: Exception | None = None
        self.scope = anyio.CancelScope()
        self.done = anyio.Event()
        # The asyncio Task must stay referenced while it runs.
        self.task = _spawn(self._read)

    def register(self, id: Any) -> _Slot:
        if self.failure is not None:
            raise self.failure
        slot = self.pending[_key(id)] = _Slot()
        return slot

    def unregister(self, id: Any) -> None:
        self.pending.pop(_key(id), None)

    def _fail(self, error: Exception) -> None:
        self.failure = error
        for slot in self.pending.values():
            slot.resolve(error=error)

    async def _read(self) -> None:
        try:
            with self.scope:
                stream = BufferedByteReceiveStream(self.process.stdout)
                while True:
                    try:
                        raw = await stream.receive_until(b"\n", self.max_bytes)
                    except (anyio.EndOfStream, anyio.IncompleteRead):
                        self._fail(ProtocolError("Stdio backend closed stdout"))
                        return
                    except anyio.DelimiterNotFound:
                        raw = None
                    if raw is None or len(raw) > self.max_bytes:
                        # An overlong record breaks the bound; stop reading this child.
                        self._fail(ProtocolError("Stdio response too large"))
                        return
                    self._route(raw)
        except Exception as exc:  # noqa: BLE001 - a detached reader must not crash the loop
            self._fail(ProtocolError("Stdio reader failed"))
            _log.warning("AHP stdio reader stopped: %s", type(exc).__name__)
        finally:
            if self.failure is None:
                self._fail(ProtocolError("Stdio transport closed"))
            self.done.set()

    def _route(self, raw: bytes) -> None:
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            value = None
        slot = None
        if isinstance(value, dict) and type(value.get("id")) in (str, int):
            slot = self.pending.pop(_key(value["id"]), None)
        if slot is None:
            # Frame contents may carry secrets: report shape, never content.
            _log.warning(
                "AHP stdio discarded an unsolicited or uncorrelated frame (%d bytes)",
                len(raw),
            )
            return
        slot.resolve(value=value)

    async def aclose(self) -> None:
        process = self.process
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        self.scope.cancel()
        await self.done.wait()
        await process.wait()
        await process.aclose()


_BASE_ENVIRONMENT = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
)
_WINDOWS_BASE_ENVIRONMENT = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
)


def child_environment(
    env: Mapping[str, str] | None = None,
    *,
    inherit_environment: bool = False,
    host: Mapping[str, str] | None = None,
    windows: bool | None = None,
) -> dict[str, str]:
    """Return the environment for a stdio backend process.

    The base is the host allowlist (or the full host environment when
    ``inherit_environment`` is true); ``env`` entries are applied literally on
    top. Windows variable names match case-insensitively.
    """
    host = os.environ if host is None else host
    windows = os.name == "nt" if windows is None else windows
    if inherit_environment:
        result = dict(host)
    else:
        allowed = set(_BASE_ENVIRONMENT)
        if windows:
            allowed.update(_WINDOWS_BASE_ENVIRONMENT)
        result = {
            name: value
            for name, value in host.items()
            if (name.upper() if windows else name) in allowed
            or (name.upper() if windows else name).startswith("LC_")
        }
    for name, value in (env or {}).items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("stdio env names and values must be strings")
        if windows:
            for existing in [k for k in result if k.upper() == name.upper()]:
                del result[existing]
        result[name] = value
    return result


class StdioTransport:
    def __init__(
        self,
        command: str,
        args: Sequence[str] = (),
        *,
        lifecycle: str = "persistent",
        cwd: str | None = None,
        max_response_bytes: int = 4 * 1024 * 1024,
        env: Mapping[str, str] | None = None,
        inherit_environment: bool = False,
    ) -> None:
        if lifecycle not in ("persistent", "per_event"):
            raise ValueError("Unknown stdio lifecycle")
        self.command = [command, *args]
        self.cwd = cwd
        # Resolve once; values stay out of repr/logs.
        self._env = child_environment(env, inherit_environment=inherit_environment)
        self.lifecycle = lifecycle
        self.max_response_bytes = max_response_bytes
        self._lock = anyio.Lock()
        self._child: _Child | None = None
        self._closed = False

    @property
    def _process(self):
        return None if self._child is None else self._child.process

    async def _ready(self) -> _Child:
        if self._closed:
            raise RuntimeError("Transport is closed")
        if self._child is not None and self._child.done.is_set():
            # The child closed or broke its stdout framing: replace it.
            await self._reap()
        if self._child is None:
            process = await anyio.open_process(
                self.command,
                cwd=self.cwd,
                env=self._env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            self._child = _Child(process, self.max_response_bytes)
        return self._child

    async def _reap(self):
        # Keep the serialization lock until the old process cannot answer again.
        with anyio.CancelScope(shield=True):
            child, self._child = self._child, None
            if child is not None:
                await child.aclose()

    async def _exchange(self, message, response):
        async with self._lock:
            child = None
            try:
                child = await self._ready()
                slot = child.register(message["id"]) if response else None
                await child.process.stdin.send(
                    json.dumps(message, allow_nan=False, separators=(",", ":")).encode()
                    + b"\n"
                )
                if slot is None:
                    if self.lifecycle == "per_event":
                        await child.process.wait()
                    return None
                return await slot.wait()
            except BaseException:
                await self._reap()
                raise
            finally:
                if response and child is not None:
                    child.unregister(message["id"])
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
