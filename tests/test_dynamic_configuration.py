"""Dynamic configuration is an ordinary request-scoped server handler."""

from contextvars import ContextVar
from copy import deepcopy
from datetime import timedelta
import json
import unittest

import anyio

from agenthooksprotocol import Configuration, content, event, subscription
from agenthooksprotocol.runtime import OperationCancelledError
from agenthooksprotocol.server import asgi, hooks, stdio
from test_public_server import Input, Output, call_app, request as intercept_request
from test_server_configuration import discovery


def configuration(timeout_ms=750):
    return Configuration(
        subscriptions=[
            subscription.Intercept(
                events=[event.TOOL_BEFORE],
                timeout=timedelta(milliseconds=timeout_ms),
                failure_policy=subscription.FailurePolicy.FAIL_OPEN,
                content=content.metadata(),
            )
        ]
    )


class DynamicConfigurationTests(unittest.TestCase):
    def both(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_request_context_and_application_identity_are_preserved(self):
        async def run():
            tenant = ContextVar("tenant", default="untrusted")
            seen = []

            def configure(ctx: hooks.ConfigurationContext) -> Configuration:
                seen.append((tenant.get(), deepcopy(ctx.raw)))
                self.assertEqual(ctx.envelope.id, ctx.raw["id"])
                self.assertEqual(ctx.params.protocol_version, "draft")
                self.assertEqual(ctx.envelope["extra"], {"opaque": True})
                # These are request evidence, not the engine's response authority.
                ctx.raw["id"] = "changed"
                ctx.envelope["id"] = "changed"
                ctx.params["protocolVersion"] = "changed"
                return configuration(500 if tenant.get() == "first" else 900)

            handler = hooks.Handlers(configuration=configure)
            value = discovery()
            value["extra"] = {"opaque": True}
            original = deepcopy(value)
            for name, timeout in (("first", 500), ("second", 900)):
                token = tenant.set(name)
                try:
                    result = await handler.process(value)
                finally:
                    tenant.reset(token)
                self.assertEqual(result["id"], original["id"])
                self.assertEqual(result["result"]["protocolVersion"], "draft")
                self.assertEqual(
                    result["result"]["configuration"]["subscriptions"][0]["timeoutMs"],
                    timeout,
                )
            self.assertEqual(value, original)
            self.assertEqual([name for name, _ in seen], ["first", "second"])

        self.both(run)

    def test_callable_objects_and_awaitable_results_are_not_copied(self):
        async def run():
            class Provider:
                def __init__(self):
                    self.calls = 0

                def __deepcopy__(self, memo):
                    raise AssertionError("Do not copy application callback state")

                def __call__(self, context):
                    self.calls += 1

                    async def resolve():
                        await anyio.sleep(0)
                        return configuration(self.calls * 100)

                    return resolve()

            provider = Provider()
            engine = hooks.Engine(hooks.Handlers(configuration=provider))
            for expected in (100, 200):
                result = await engine.process(discovery())
                self.assertEqual(
                    result["result"]["configuration"]["subscriptions"][0]["timeoutMs"],
                    expected,
                )
            self.assertEqual(provider.calls, 2)

        self.both(run)

    def test_custom_awaitable_result_is_awaited(self):
        async def run():
            class Value:
                def __await__(self):
                    async def resolve():
                        await anyio.sleep(0)
                        return configuration()

                    return resolve().__await__()

            handler = hooks.Handlers(configuration=lambda ctx: Value())
            result = await handler.process(discovery())
            self.assertEqual(result["result"]["configuration"], configuration())

        self.both(run)

    def test_invalid_requests_and_other_methods_do_not_invoke_handler(self):
        async def run():
            calls = []

            def configure(ctx):
                calls.append(ctx)
                return configuration()

            handler = hooks.Handlers(configuration=configure)
            invalid = []
            value = discovery()
            del value["params"]["protocolVersion"]
            invalid.append(value)
            value = discovery()
            value["params"]["protocolVersion"] = "unsupported"
            invalid.append(value)
            value = discovery()
            value["id"] = False
            invalid.append(value)
            value = discovery()
            del value["id"]
            invalid.append(value)
            value = discovery()
            value["method"] = "unknown"
            invalid.append(value)
            for value in invalid:
                result = await handler.process(value)
                self.assertTrue(result is None or "error" in result)
            await handler.process(intercept_request())
            self.assertEqual(calls, [])
            self.assertEqual(
                (await hooks.Handlers().process(discovery()))["error"]["code"], -32601
            )

        self.both(run)

    def test_callback_failures_and_invalid_results_are_sanitized(self):
        async def run():
            invalid = configuration()
            invalid.subscriptions[0]["timeoutMs"] = 0
            invalid_json = configuration()
            invalid_json["opaque"] = object()

            def failed(ctx):
                raise ValueError("private tenant secret")

            def http_failed(ctx):
                raise hooks.HTTPError(403, b"private tenant secret")

            async def async_failed(ctx):
                await anyio.sleep(0)
                raise RuntimeError("private tenant secret")

            callbacks = [
                failed,
                http_failed,
                async_failed,
                lambda ctx: None,
                lambda ctx: {},
                lambda ctx: invalid,
                lambda ctx: invalid_json,
            ]
            for callback in callbacks:
                result = await hooks.Handlers(configuration=callback).process(
                    discovery()
                )
                self.assertEqual(
                    result,
                    {
                        "jsonrpc": "2.0",
                        "id": "config-1",
                        "error": {"code": -32004, "message": "Backend internal error"},
                    },
                )
                self.assertNotIn("secret", json.dumps(result))

        self.both(run)

    def test_results_and_static_declarations_are_detached(self):
        async def run():
            source = configuration()
            dynamic = hooks.Handlers(configuration=lambda ctx: source)
            first = await dynamic.process(discovery())
            first["result"]["configuration"]["subscriptions"].clear()
            self.assertEqual(
                (await dynamic.process(discovery()))["result"]["configuration"], source
            )
            source.subscriptions[0]["timeoutMs"] = 800
            self.assertEqual(
                (await dynamic.process(discovery()))["result"]["configuration"][
                    "subscriptions"
                ][0]["timeoutMs"],
                800,
            )

            source = configuration()
            engine = hooks.Engine(hooks.Handlers(configuration=source))
            source.subscriptions.clear()
            self.assertEqual(
                (await engine.process(discovery()))["result"]["configuration"],
                configuration(),
            )
            # Preserve the existing static keyword's mapping input at runtime.
            mapping = dict(configuration())
            engine = hooks.Engine(hooks.Handlers(), configuration=mapping)
            mapping["subscriptions"].clear()
            self.assertEqual(
                (await engine.process(discovery()))["result"]["configuration"],
                configuration(),
            )

        self.both(run)

    def test_conflicting_sources_are_rejected_by_every_adapter(self):
        async def run():
            for source in (configuration(), lambda ctx: configuration()):
                handler = hooks.Handlers(configuration=source)
                with self.assertRaisesRegex(ValueError, "not both"):
                    hooks.Engine(handler, configuration=configuration())
                with self.assertRaisesRegex(ValueError, "not both"):
                    asgi.App(handler, configuration=configuration())
                with self.assertRaisesRegex(ValueError, "not both"):
                    await stdio.serve(
                        handler,
                        configuration=configuration(),
                        input=Input(b""),
                        output=Output(),
                    )
            # None is absence, not a competing source.
            hooks.Engine(
                hooks.Handlers(configuration=configuration()), configuration=None
            )

        self.both(run)

    def test_native_cancellation_retires_callback_without_response(self):
        async def run():
            retired = False

            async def configure(ctx):
                nonlocal retired
                try:
                    await anyio.sleep_forever()
                finally:
                    retired = True

            handler = hooks.Handlers(configuration=configure)
            with anyio.move_on_after(0.01) as scope:
                await handler.process(discovery())
                self.fail("cancelled callback must not produce an error response")
            self.assertTrue(scope.cancel_called)
            self.assertTrue(retired)

            def cancelled(ctx):
                raise OperationCancelledError("cancelled")

            with self.assertRaises(OperationCancelledError):
                await hooks.Handlers(configuration=cancelled).process(discovery())

        self.both(run)

    def test_http_and_stdio_use_same_dynamic_routing_including_keyword(self):
        async def run():
            seen = []

            async def configure(ctx):
                seen.append(ctx.envelope.id)
                return configuration()

            for keyword in (False, True):
                handler = hooks.Handlers(configuration=None if keyword else configure)
                options = {"configuration": configure} if keyword else {}
                request = discovery("http")
                sent = await call_app(
                    asgi.App(handler, **options), json.dumps(request).encode()
                )
                self.assertEqual(sent[0]["status"], 200)
                http_response = json.loads(sent[1]["body"])
                output = Output()
                await stdio.serve(
                    handler,
                    input=Input(json.dumps(discovery("stdio")).encode() + b"\n"),
                    output=output,
                    **options,
                )
                stdio_response = json.loads(output.data)
                self.assertEqual(http_response["result"], stdio_response["result"])
                self.assertEqual(stdio_response["id"], "stdio")
            self.assertEqual(seen, ["http", "stdio", "http", "stdio"])

        self.both(run)

    def test_application_authentication_precedes_dynamic_callback(self):
        async def run():
            tenant = ContextVar("tenant")
            seen = []

            def configure(ctx):
                seen.append(tenant.get())
                return configuration()

            app = asgi.App(hooks.Handlers(configuration=configure))

            async def authenticated(scope, receive, send):
                if (b"authorization", b"Bearer approved") not in scope["headers"]:
                    await send(
                        {"type": "http.response.start", "status": 401, "headers": []}
                    )
                    await send({"type": "http.response.body", "body": b""})
                    return
                token = tenant.set("verified-by-application")
                try:
                    await app(scope, receive, send)
                finally:
                    tenant.reset(token)

            payload = json.dumps(discovery()).encode()
            self.assertEqual((await call_app(authenticated, payload))[0]["status"], 401)
            self.assertEqual(seen, [])
            self.assertEqual(
                (
                    await call_app(
                        authenticated,
                        payload,
                        headers=[(b"authorization", b"Bearer approved")],
                    )
                )[0]["status"],
                200,
            )
            self.assertEqual(seen, ["verified-by-application"])

        self.both(run)
