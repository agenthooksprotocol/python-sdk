"""Actual loopback HTTP callbacks and independent event/upload auth (S12/S14).

The standard-library HTTP adapter is example host code. Protocol dispatch and
verified attachment admission use the same public SDK engines as ASGI/stdio.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from threading import Thread
from typing import Any

import anyio
from agenthooksprotocol import HookResult, Hooks, capability, effect, event, tool
from agenthooksprotocol.wire import JsonValue, InterceptRequest
from agenthooksprotocol.server import attachments, hooks
from agenthooksprotocol.transports.http import HTTPTransport
from upload import Store, authorize


async def intercept(request: InterceptRequest) -> hooks.InterceptResult:
    return hooks.InterceptResult(effects=[effect.Allow()])


async def main() -> None:
    handler, store = hooks.Handler(intercept=intercept), Store()
    event_auth_correct: list[bool] = []
    upload_auth_correct: list[bool] = []

    class HTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            status = 200
            if self.path == "/hooks":
                valid = self.headers.get("Authorization") == "Bearer event-only"
                event_auth_correct.append(valid)
                if not valid:
                    status, result = 401, {"error": "Unauthorized"}
                else:

                    async def dispatch() -> Any:
                        return await handler.process(json.loads(data))

                    result = anyio.run(dispatch)
            elif self.path == "/content":
                upload_auth_correct.append(
                    self.headers.get("Authorization") == "Bearer upload-only"
                )

                async def body() -> AsyncIterator[bytes]:
                    yield data

                async def receive() -> Any:
                    return await attachments.receive(
                        self.headers, body(), authorize=authorize, storage=store
                    )

                try:
                    result, status = anyio.run(receive), 201
                except hooks.HTTPError as error:
                    result, status = {"error": "Unauthorized"}, error.status
            else:
                status, result = 404, {"error": "Not found"}
            encoded = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), HTTPHandler)
    worker = Thread(target=server.serve_forever)
    worker.start()
    name = "AHP_EXAMPLE_EVENT_TOKEN"
    previous = os.environ.get(name)
    os.environ[name] = "event-only"
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with Path(__file__).with_name("registration.json").open() as file:
            config = json.load(file)
        config["hooks"][0]["transport"]["url"] = base + "/hooks"
        config["hooks"][0]["authentication"] = {"type": "bearer", "tokenEnv": name}
        async with Hooks(
            config,
            source="urn:example:comparison",
            capabilities={
                "tool.before": capability.Declaration(
                    modes=[capability.Mode.INTERCEPT], grants=[capability.Allow()]
                ),
            },
        ) as harness:
            result: HookResult[JsonValue, JsonValue, JsonValue] = await harness.tool_before(
                event.ToolBeforeInput(
                    call_id="call-1",
                    path=tool.Path.NATIVE,
                    name="shell",
                    origin=tool.Origin.NATIVE,
                    input={"command": "echo original", "timeoutMs": 1000},
                )
            )
            assert result.decision == "allow" and result.accepted_response is not None
        uploader = HTTPTransport(
            base + "/hooks", headers={"Authorization": "Bearer event-only"}
        )
        try:
            descriptor = await uploader.upload(
                base + "/content",
                b"reviewed",
                headers={"Authorization": "Bearer upload-only"},
            )
            assert (
                descriptor is not None
                and store.blobs[("upload-principal", descriptor.ref)] == b"reviewed"
            )
        finally:
            await uploader.aclose()
        assert event_auth_correct == [True] and upload_auth_correct == [True]
        print(
            json.dumps(
                {
                    "S12": {"actualHTTP": True, "correlated": True},
                    "S14": {
                        "eventCredentialBound": True,
                        "uploadCredentialIsolated": True,
                    },
                }
            )
        )
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous
        await anyio.to_thread.run_sync(server.shutdown)
        server.server_close()
        await anyio.to_thread.run_sync(worker.join)


if __name__ == "__main__":
    anyio.run(main)
