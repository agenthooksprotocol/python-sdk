"""Owned newline JSON subprocesses with cancellation-safe correlation.

Children receive a minimal base environment (an allowlist of host variables
such as ``PATH``, ``HOME``, locale and temp-directory settings) plus the
registration ``env`` entries, which override base values. The full host
environment is inherited only with ``inherit_environment=True``. Environment
values are never logged.
"""

from collections.abc import Mapping
from typing import Any, Sequence
import json
import os
import subprocess
import anyio
from anyio.streams.buffered import BufferedByteReceiveStream
from ..runtime import ProtocolError


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
                env=self._env,
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
