"""Catch-all observer and the top-level stdio ``serve`` export."""

import copy
import json
import os
import unittest
from pathlib import Path

import anyio

from agenthooksprotocol import server
from agenthooksprotocol.server import asgi, hooks, stdio

from test_public_server import Input, Output, call_app, notification, wire


ROOT = Path(os.environ.get("AHP_TEST_ROOT", Path(__file__).resolve().parents[2]))
SESSION_START = json.loads(
    (
        ROOT
        / "agent-hooks-protocol/fixtures/draft/http/observe-session-start.valid.json"
    ).read_text()
)


def session_start():
    return copy.deepcopy(SESSION_START)


class CatchAllObserverTests(unittest.TestCase):
    def both(self, function):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(function, backend=backend)

    def test_any_runs_only_without_a_per_event_observer(self):
        async def run():
            specific, fallback = [], []

            def tool_before(ctx: hooks.ToolBeforeObserveContext) -> None:
                specific.append(ctx.event.type)

            async def any_event(ctx: hooks.AnyObserveContext) -> None:
                await anyio.lowlevel.checkpoint()
                fallback.append((type(ctx), ctx.event.type, ctx.raw))

            handler = hooks.Handlers(
                observe=hooks.ObserveHandlers(tool_before=tool_before, any=any_event)
            )
            self.assertIsNone(await handler.process(notification()))
            self.assertIsNone(await handler.process(session_start()))
            self.assertEqual(specific, ["tool.before"])
            self.assertEqual(
                fallback,
                [(hooks.SessionStartObserveContext, "session.start", session_start())],
            )

        self.both(run)

    def test_any_is_silent_on_every_transport(self):
        async def run():
            seen = []

            def boom(ctx):
                seen.append(ctx.event.type)
                raise RuntimeError("credential-secret")

            handler = hooks.Handlers(observe=hooks.ObserveHandlers(any=boom))
            self.assertIsNone(await handler(wire(session_start())))
            sent = await call_app(asgi.App(handler), wire(session_start()))
            self.assertEqual((sent[0]["status"], sent[1]["body"]), (204, b""))
            sink = Output()
            await stdio.serve(
                handler, input=Input(wire(session_start()) + b"\n"), output=sink
            )
            self.assertEqual(sink.data, b"")
            self.assertEqual(seen, ["session.start"] * 3)

        self.both(run)

    def test_any_is_not_an_intercept_fallback(self):
        async def run():
            def any_event(ctx):
                raise AssertionError("observers never answer requests")

            value = notification()
            value["id"] = value["params"]["event"]["id"]
            value["method"] = "hooks/intercept"
            value["params"]["capabilities"] = {"effects": ["deny"]}
            handler = hooks.Handlers(observe=hooks.ObserveHandlers(any=any_event))
            self.assertEqual((await handler.process(value))["error"]["code"], -32002)

        self.both(run)

    def test_serve_is_exported_from_server(self):
        self.assertIs(server.serve, stdio.serve)
        self.assertIn("serve", server.__all__)


if __name__ == "__main__":
    unittest.main()
