"""AHP JSON-RPC error codes for requests and silence for notifications."""

import json
import unittest

import anyio

from agenthooksprotocol.generated import PROTOCOL_VERSION
from agenthooksprotocol.server import asgi, hooks, stdio

from test_public_server import Input, Output, call_app, notification, request, wire


def boom(_):
    raise RuntimeError("credential-secret")


class ServerErrorCodeTests(unittest.TestCase):
    def both(self, function):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(function, backend=backend)

    def test_intercept_handler_failure_is_backend_internal_error(self):
        async def run():
            async def async_boom(_):
                raise RuntimeError("credential-secret")

            for callback in (boom, async_boom):
                handler = hooks.Handlers(
                    intercept=hooks.InterceptHandlers(tool_before=callback)
                )
                result = await handler.process(request())
                self.assertEqual(
                    result,
                    {
                        "jsonrpc": "2.0",
                        "id": "event-1",
                        "error": {"code": -32004, "message": "Backend internal error"},
                    },
                )
                self.assertNotIn("credential-secret", json.dumps(result))

        self.both(run)

    def test_missing_intercept_handler_is_unsupported_event(self):
        async def run():
            result = await hooks.Handlers().process(request())
            self.assertEqual(result["id"], "event-1")
            self.assertEqual(result["error"]["code"], -32002)
            unknown = request()
            unknown["params"]["event"]["type"] = "com.example.unknown"
            result = await hooks.Handlers().process(unknown)
            self.assertEqual(result["error"]["code"], -32002)

        self.both(run)

    def test_missing_capabilities_handler_is_method_not_found(self):
        async def run():
            value = {
                "jsonrpc": "2.0",
                "id": "discovery",
                "method": "hooks/capabilities",
                "params": {"protocolVersion": PROTOCOL_VERSION},
            }
            result = await hooks.Handlers().process(value)
            self.assertEqual(result["error"]["code"], -32601)

        self.both(run)

    def test_unsupported_protocol_version_lists_supported(self):
        async def run():
            called = []

            def intercept(_):
                called.append(True)
                return hooks.ToolBeforeReply()

            handler = hooks.Handlers(
                intercept=hooks.InterceptHandlers(tool_before=intercept)
            )
            value = request()
            value["params"]["protocolVersion"] = "1999-01-01"
            result = await handler.process(value)
            self.assertEqual(
                result,
                {
                    "jsonrpc": "2.0",
                    "id": "event-1",
                    "error": {
                        "code": -32001,
                        "message": "Unsupported AHP protocol version",
                        "data": {"supported": [PROTOCOL_VERSION]},
                    },
                },
            )
            engine = hooks.Engine(hooks.Handlers(), harness_manifest={})
            discovery = {
                "jsonrpc": "2.0",
                "id": "discovery",
                "method": "hooks/capabilities",
                "params": {"protocolVersion": "1999-01-01"},
            }
            self.assertEqual((await engine.process(discovery))["error"]["code"], -32001)
            self.assertEqual(called, [])

        self.both(run)

    def test_notifications_never_receive_a_response(self):
        async def run():
            seen = []

            def observe(ctx):
                seen.append(ctx)

            failing = hooks.Handlers(observe=hooks.ObserveHandlers(tool_before=boom))
            observed = hooks.Handlers(
                observe=hooks.ObserveHandlers(tool_before=observe)
            )
            unsupported = notification()
            unsupported["params"]["protocolVersion"] = "1999-01-01"
            unknown_event = notification()
            unknown_event["params"]["event"]["type"] = "com.example.unknown"
            intercept_without_id = request()
            del intercept_without_id["id"]
            cases = [
                (failing, notification()),
                (hooks.Handlers(), notification()),
                (observed, unsupported),
                (observed, unknown_event),
                (hooks.Handlers(), intercept_without_id),
                (hooks.Handlers(), {"jsonrpc": "2.0", "method": "unknown"}),
                (
                    hooks.Handlers(),
                    {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}},
                ),
            ]
            for handler, value in cases:
                self.assertIsNone(await handler.process(value))
                sent = await call_app(asgi.App(handler), wire(value))
                self.assertEqual(sent[0]["status"], 204)
                self.assertEqual(sent[1]["body"], b"")
                sink = Output()
                await stdio.serve(
                    handler, input=Input(wire(value) + b"\n"), output=sink
                )
                self.assertEqual(sink.data, b"")
            self.assertEqual(seen, [])

        self.both(run)

    def test_stdio_http_error_is_backend_internal_error(self):
        async def run():
            async def intercept(_):
                raise hooks.HTTPError(503, b"retry later")

            sink = Output()
            await stdio.serve(
                hooks.Handlers(
                    intercept=hooks.InterceptHandlers(tool_before=intercept)
                ),
                input=Input(wire(request()) + b"\n"),
                output=sink,
            )
            self.assertEqual(json.loads(sink.data)["error"]["code"], -32004)

        self.both(run)


if __name__ == "__main__":
    unittest.main()
