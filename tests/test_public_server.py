"""Public server contracts on both AnyIO backends, without an ASGI framework."""

import hashlib
import json
import unittest
from contextlib import aclosing

import anyio

from agenthooksprotocol.runtime import Validator
from agenthooksprotocol.server import asgi, attachments, hooks, stdio


def request():
    return {
        "jsonrpc": "2.0",
        "id": "event-1",
        "method": "hooks/intercept",
        "params": {
            "protocolVersion": "draft",
            "event": {
                "id": "event-1",
                "source": "https://harness.example/runtime",
                "type": "tool.before",
                "time": "2026-08-24T08:51:14Z",
                "session": {"id": "session-1"},
                "call": {"id": "call-1"},
                "path": "native",
                "tool": {
                    "name": "write_file",
                    "kind": "file_write",
                    "origin": "native",
                    "input": {"path": "é.txt"},
                },
            },
            "capabilities": {"effects": ["deny"]},
        },
    }


def notification():
    value = request()
    del value["id"]
    value["method"] = "hooks/observe"
    del value["params"]["capabilities"]
    return value


def wire(value):
    return json.dumps(value, ensure_ascii=False).encode()


class Input:
    def __init__(self, data, chunk=7):
        self.data = data
        self.chunk = chunk
        self.closed = False

    async def receive(self, max_bytes):
        await anyio.lowlevel.checkpoint()
        if not self.data:
            raise anyio.EndOfStream
        size = min(max_bytes, self.chunk)
        data, self.data = self.data[:size], self.data[size:]
        return data

    async def aclose(self):
        self.closed = True


class Output:
    def __init__(self):
        self.data = b""
        self.closed = False

    async def send(self, data):
        await anyio.lowlevel.checkpoint()
        self.data += data

    async def aclose(self):
        self.closed = True


async def call_app(app, data=b"", *, headers=(), method="POST", events=None):
    events = (
        list(events) if events is not None else [{"type": "http.request", "body": data}]
    )
    sent = []

    async def receive():
        return events.pop(0)

    async def send(event):
        sent.append(event)

    await app({"type": "http", "method": method, "headers": headers}, receive, send)
    return sent


def upload_headers(data):
    return {
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(data)),
        "AHP-Content-SHA256": hashlib.sha256(data).hexdigest(),
        "Authorization": "Bearer upload",
    }


class PublicServerTests(unittest.TestCase):
    def both(self, function):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(function, backend=backend)

    def test_canonical_handler_and_transport_parity(self):
        async def run():
            seen = []

            async def intercept(value):
                Validator().validate("intercept-request", value)
                seen.append(value)
                return hooks.InterceptResult(
                    effects=[{"type": "deny", "reason": "é policy"}]
                )

            handler = hooks.Handler(intercept=intercept)
            direct = await handler(wire(request()))
            Validator().validate("intercept-response", direct)
            self.assertEqual(direct["id"], request()["id"])
            http = await call_app(asgi.App(handler), wire(request()))
            self.assertEqual(http[0]["status"], 200)
            self.assertEqual(json.loads(http[1]["body"]), direct)
            source, sink = Input(wire(request()) + b"\n"), Output()
            await stdio.serve(handler, input=source, output=sink)
            self.assertEqual(json.loads(sink.data), direct)
            self.assertEqual(await handler.process(request()), direct)
            self.assertEqual(len(seen), 4)
            self.assertFalse(source.closed or sink.closed)

        self.both(run)

    def test_notification_suppression_and_validation(self):
        async def run():
            seen = []

            async def observe(value):
                seen.append(value)

            handler = hooks.Handler(observe=observe)
            valid = notification()
            malformed = {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
            unknown = {"jsonrpc": "2.0", "method": "other"}
            missing_id = request()
            del missing_id["id"]
            for value in (valid, malformed, unknown, missing_id):
                self.assertIsNone(await handler(wire(value)))
                http = await call_app(asgi.App(handler), wire(value))
                self.assertEqual(http[0]["status"], 204)
                self.assertEqual(http[1]["body"], b"")
            self.assertEqual(len(seen), 2)
            source, sink = (
                Input(wire(malformed) + b"\n" + wire(valid) + b"\n"),
                Output(),
            )
            await stdio.serve(handler, input=source, output=sink)
            self.assertEqual(sink.data, b"")
            invalid = {"jsonrpc": "wrong", "method": "hooks/observe"}
            self.assertEqual((await handler(wire(invalid)))["error"]["code"], -32600)
            with_id = notification()
            with_id["id"] = "unexpected"
            self.assertEqual((await handler(wire(with_id)))["error"]["code"], -32602)

        self.both(run)

    def test_strict_utf8_json_and_unknown_method(self):
        async def run():
            handler = hooks.Handler()
            for data in (b"\xff", b'{"a":1,"a":2}', b'{"n":NaN}', b"{"):
                self.assertEqual((await handler(data))["error"]["code"], -32700)
            for value in ([], None, {"jsonrpc": "2.0", "method": "x", "id": True}):
                self.assertEqual((await handler(wire(value)))["error"]["code"], -32600)
            for method in ("unknown", "hooks/capabilities"):
                result = await handler(
                    wire({"jsonrpc": "2.0", "id": "x", "method": method})
                )
                self.assertEqual(result["error"]["code"], -32601)
            source, sink = Input(b"\xff\n"), Output()
            await stdio.serve(handler, input=source, output=sink)
            self.assertEqual(json.loads(sink.data)["error"]["code"], -32700)

        self.both(run)

    def test_invalid_results_and_correlation(self):
        async def run():
            for result in (
                None,
                hooks.InterceptResult(effects=[{"type": "not-an-effect"}]),
            ):

                async def intercept(_, result=result):
                    return result

                self.assertEqual(
                    (await hooks.Handler(intercept=intercept)(wire(request())))[
                        "error"
                    ]["code"],
                    -32603,
                )
            called = []

            async def intercept(_):
                called.append(True)
                return hooks.InterceptResult()

            value = request()
            value["id"] = "different"
            self.assertEqual(
                (await hooks.Handler(intercept=intercept)(wire(value)))["error"][
                    "code"
                ],
                -32602,
            )
            self.assertEqual(called, [])

        self.both(run)

    def test_http_error_body_limits_disconnect(self):
        async def run():
            async def intercept(_):
                raise hooks.HTTPError(429, b"retry later", content_type=b"text/plain")

            app = asgi.App(hooks.Handler(intercept=intercept))
            sent = await call_app(app, wire(request()))
            self.assertEqual(sent[0]["status"], 429)
            self.assertEqual(sent[1]["body"], b"retry later")
            sent = await call_app(asgi.App(hooks.Handler(), max_bytes=2), b"123")
            self.assertEqual(sent[0]["status"], 413)
            self.assertTrue(sent[1]["body"])
            sent = await call_app(app, method="GET")
            self.assertEqual(sent[0]["status"], 405)
            self.assertEqual(
                await call_app(app, events=[{"type": "http.disconnect"}]), []
            )

        self.both(run)

    def test_cancellation_propagates_and_streams_stay_open(self):
        async def run():
            entered = anyio.Event()

            async def intercept(_):
                entered.set()
                await anyio.sleep_forever()

            source, sink = Input(wire(request()) + b"\n"), Output()
            async with anyio.create_task_group() as tasks:

                async def serve():
                    await stdio.serve(
                        hooks.Handler(intercept=intercept), input=source, output=sink
                    )

                tasks.start_soon(serve)
                await entered.wait()
                tasks.cancel_scope.cancel()
            self.assertFalse(source.closed or sink.closed)
            self.assertEqual(sink.data, b"")

        self.both(run)

    def test_stdio_framing_and_backpressure(self):
        async def run():
            for data in (b"12345", b"12345\n", b"{}"):
                source, sink = Input(data), Output()
                with self.assertRaises(ValueError):
                    await stdio.serve(
                        hooks.Handler(), input=source, output=sink, max_bytes=4
                    )
                self.assertFalse(source.closed or sink.closed)
            called, entered, release = [], anyio.Event(), anyio.Event()

            async def intercept(_):
                called.append(True)
                return hooks.InterceptResult()

            class SlowOutput(Output):
                async def send(self, data):
                    entered.set()
                    await release.wait()
                    await super().send(data)

            sink = SlowOutput()
            async with anyio.create_task_group() as tasks:

                async def serve():
                    await stdio.serve(
                        hooks.Handler(intercept=intercept),
                        input=Input((wire(request()) + b"\n") * 2, chunk=65536),
                        output=sink,
                    )

                tasks.start_soon(serve)
                await entered.wait()
                self.assertEqual(called, [True])
                release.set()
            self.assertEqual(len(called), 2)
            self.assertEqual(len(sink.data.splitlines()), 2)

        self.both(run)

    def test_upload_verified_eof_authorization_commit_order(self):
        async def run():
            events, stored = [], {}
            data = b"\x00\xffopaque"

            async def body():
                events.append("read")
                yield data[:3]
                yield data[3:]
                events.append("eof")

            async def authorize(credentials):
                self.assertEqual(credentials, "Bearer upload")
                events.append("authorize")
                return 201, "scope"

            class Store:
                async def commit(self, *, scope, ref, data):
                    events.append("commit")
                    if (scope, ref) in stored:
                        raise ValueError("immutable")
                    stored[scope, ref] = data

            descriptor = await attachments.receive(
                upload_headers(data), body(), authorize=authorize, storage=Store()
            )
            events.append("response")
            self.assertEqual(events, ["authorize", "read", "eof", "commit", "response"])
            self.assertEqual(stored["scope", descriptor["ref"]], data)
            Validator().validate("content-reference", descriptor)
            other = await attachments.receive(
                upload_headers(data), body(), authorize=authorize, storage=Store()
            )
            self.assertNotEqual(other["ref"], descriptor["ref"])
            async with attachments.parse(upload_headers(data), body()) as upload:
                self.assertEqual(upload.data, data)
                self.assertEqual(upload.sha256, descriptor["sha256"])

        self.both(run)

    def test_upload_rejects_framing_hash_size_before_commit(self):
        async def run():
            data = b"abc"
            variants = []
            for key, value in (
                ("Content-Length", "2"),
                ("Content-Length", "4"),
                ("Content-Length", "03"),
                ("AHP-Content-SHA256", "0" * 64),
                ("Content-Type", "text/plain"),
                ("Content-Encoding", "gzip"),
                ("Transfer-Encoding", "chunked"),
                ("AHP-Content-Ref", "chosen-by-sender"),
                ("AHP-Subscription", "wrong-scope"),
            ):
                variants.append({**upload_headers(data), key: value})
            variants.append(
                list(upload_headers(data).items()) + [("content-length", "3")]
            )
            variants.append(
                list(upload_headers(data).items()) + [("authorization", "evil")]
            )
            calls = []

            class Store:
                async def commit(self, **kwargs):
                    calls.append(kwargs)

            async def authorize(_):
                return 201, "scope"

            async def body():
                yield data

            for headers in variants:
                with self.assertRaises(attachments.HTTPError) as raised:
                    async with aclosing(body()) as source:
                        await attachments.receive(
                            headers, source, authorize=authorize, storage=Store()
                        )
                self.assertEqual(raised.exception.status, 400)
            with self.assertRaises(attachments.HTTPError) as raised:
                await attachments.receive(
                    upload_headers(data),
                    body(),
                    authorize=authorize,
                    storage=Store(),
                    max_bytes=2,
                )
            self.assertEqual(raised.exception.status, 413)
            self.assertEqual(calls, [])

        self.both(run)

    def test_upload_auth_denial_commit_failure_and_http_response(self):
        async def run():
            read, commits = [], []
            data = b"content"

            async def body():
                read.append(True)
                yield data

            async def deny(_):
                return 401, None

            async def allow(_):
                return 201, "scope"

            class Store:
                async def commit(self, **kwargs):
                    commits.append(kwargs)
                    raise RuntimeError("secret storage failure")

            with self.assertRaises(attachments.HTTPError) as raised:
                await attachments.receive(
                    upload_headers(data), body(), authorize=deny, storage=Store()
                )
            self.assertEqual(raised.exception.status, 401)
            self.assertEqual(read, [])
            app = attachments.App(authorize=allow, storage=Store())
            sent = await call_app(app, data, headers=list(upload_headers(data).items()))
            self.assertEqual(sent[0]["status"], 500)
            self.assertNotIn(b"secret", sent[1]["body"])
            self.assertEqual(len(commits), 1)
            self.assertEqual(
                await call_app(
                    app,
                    headers=list(upload_headers(data).items()),
                    events=[{"type": "http.disconnect"}],
                ),
                [],
            )
            self.assertEqual(len(commits), 1)

            class GoodStore:
                async def commit(self, **kwargs):
                    commits.append(kwargs)

            sent = await call_app(
                attachments.App(authorize=allow, storage=GoodStore()),
                data,
                headers=list(upload_headers(data).items()),
            )
            self.assertEqual(sent[0]["status"], 201)
            descriptor = json.loads(sent[1]["body"])
            self.assertEqual(descriptor["ref"], commits[-1]["ref"])

        self.both(run)

    def test_upload_cancellation_during_read_or_commit(self):
        async def run():
            for stage in ("read", "commit"):
                entered, calls = anyio.Event(), []

                async def body():
                    if stage == "read":  # noqa: B023 - group joins before next iteration
                        entered.set()  # noqa: B023 - group joins before next iteration
                        await anyio.sleep_forever()
                    yield b"abc"

                async def authorize(_):
                    return 201, "scope"

                class Store:
                    async def commit(self, **kwargs):
                        calls.append("commit")  # noqa: B023 - group joins before next iteration
                        entered.set()  # noqa: B023 - group joins before next iteration
                        await anyio.sleep_forever()

                async def receive():
                    await attachments.receive(
                        upload_headers(b"abc"),
                        body(),
                        authorize=authorize,
                        storage=Store(),
                    )
                    calls.append("response")  # noqa: B023 - group joins before next iteration

                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(receive)
                    await entered.wait()
                    tasks.cancel_scope.cancel()
                self.assertNotIn("response", calls)
                if stage == "read":
                    self.assertEqual(calls, [])

        self.both(run)

    def test_stdio_default_streams_are_borrowed(self):
        async def run():
            import io
            from types import SimpleNamespace
            from unittest.mock import patch

            source, sink = io.BytesIO(wire(request()) + b"\n"), io.BytesIO()

            async def intercept(_):
                return hooks.InterceptResult()

            with (
                patch.object(stdio.sys, "stdin", SimpleNamespace(buffer=source)),
                patch.object(stdio.sys, "stdout", SimpleNamespace(buffer=sink)),
            ):
                await stdio.serve(hooks.Handler(intercept=intercept))
            self.assertFalse(source.closed or sink.closed)
            self.assertEqual(json.loads(sink.getvalue())["id"], "event-1")

        self.both(run)

    def test_failed_observers_never_reply(self):
        async def run():
            for exception in (
                RuntimeError("failure"),
                hooks.HTTPError(503, b"unavailable"),
            ):

                async def observe(_, exception=exception):
                    raise exception

                app = asgi.App(hooks.Handler(observe=observe))
                sent = await call_app(app, wire(notification()))
                self.assertEqual(sent[0]["status"], 204)
                self.assertEqual(sent[1]["body"], b"")

        self.both(run)

    def test_parse_borrows_iterator_and_requires_eof(self):
        async def run():
            consumed = []

            class Body:
                closed = False

                def __aiter__(self):
                    return self

                async def __anext__(self):
                    consumed.append(True)
                    if len(consumed) == 1:
                        return b"abc"
                    # Even when declared bytes have arrived, trailing data is forbidden.
                    if len(consumed) == 2:
                        return b"x"
                    raise StopAsyncIteration

                async def aclose(self):
                    self.closed = True

            body = Body()
            with self.assertRaises(hooks.HTTPError):
                async with attachments.parse(upload_headers(b"abc"), body):
                    self.fail("yielded before EOF")
            self.assertFalse(body.closed)
            self.assertEqual(len(consumed), 2)

        self.both(run)

    def test_static_harness_manifest_is_opt_in_and_copied(self):
        async def run():
            manifest = {
                "events": [
                    {
                        "event": "task.change.after",
                        "modes": ["observe"],
                        "capabilities": {"effects": []},
                    }
                ],
                "gaps": [],
                "transports": ["http", "stdio"],
                "authentication": ["bearer"],
                "toolPaths": ["native"],
                "contentCategories": ["text"],
                "limits": {
                    "maxUploadBytes": 1024,
                    "maxContinuations": 4,
                    "minTimeoutMs": 1,
                    "maxTimeoutMs": 30000,
                },
                "managedPolicy": {"scopes": ["user"], "disableable": True},
                "correlationIdentityFields": ["id", "source", "session.id"],
            }
            value = {
                "jsonrpc": "2.0",
                "id": "discovery",
                "method": "hooks/capabilities",
                "params": {"protocolVersion": "draft"},
            }
            engine = hooks.Engine(hooks.Handler(), harness_manifest=manifest)
            manifest["gaps"].append({"invalid": "caller mutation"})
            result = await engine.process(value)
            Validator().validate("capabilities-response", result)
            self.assertEqual(result["result"]["manifest"]["gaps"], [])
            self.assertEqual(
                (await hooks.Handler().process(value))["error"]["code"], -32601
            )
            malformed = hooks.Engine(hooks.Handler(), harness_manifest={})
            self.assertEqual((await malformed.process(value))["error"]["code"], -32603)

        self.both(run)

    def test_upload_does_not_send_success_before_commit_finishes(self):
        async def run():
            entered, release, sent = anyio.Event(), anyio.Event(), []
            data = b"abc"

            async def authorize(_):
                return 201, "scope"

            class Store:
                async def commit(self, **kwargs):
                    entered.set()
                    await release.wait()

            async def receive():
                return {"type": "http.request", "body": data}

            async def send(event):
                sent.append(event)

            app = attachments.App(authorize=authorize, storage=Store())
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(
                    app,
                    {
                        "type": "http",
                        "method": "POST",
                        "headers": list(upload_headers(data).items()),
                    },
                    receive,
                    send,
                )
                await entered.wait()
                self.assertEqual(sent, [])
                release.set()
            self.assertEqual(sent[0]["status"], 201)

        self.both(run)

    def test_stdio_preserves_non_success_http_error_bodies(self):
        async def run():
            canonical = {
                "jsonrpc": "2.0",
                "id": "event-1",
                "error": {
                    "code": -32001,
                    "message": "policy",
                    "data": {"reason": "denied"},
                },
            }
            for body, expected in (
                (wire(canonical), canonical),
                (b"retry later", None),
                (b"\xff", None),
            ):

                async def intercept(_, body=body):
                    raise hooks.HTTPError(503, body)

                sink = Output()
                await stdio.serve(
                    hooks.Handler(intercept=intercept),
                    input=Input(wire(request()) + b"\n"),
                    output=sink,
                )
                result = json.loads(sink.data)
                if expected is not None:
                    self.assertEqual(result, expected)
                else:
                    self.assertEqual(result["id"], "event-1")
                    self.assertEqual(result["error"]["data"]["httpStatus"], 503)
                    self.assertEqual(
                        result["error"]["data"].get(
                            "body", result["error"]["data"].get("bodyBase64")
                        ),
                        "retry later" if body == b"retry later" else "/w==",
                    )

        self.both(run)

    def test_default_posix_pipe_reads_cancel_without_closing_descriptors(self):
        import io
        import os
        from types import SimpleNamespace
        from unittest.mock import patch

        if os.name != "posix":
            self.skipTest("POSIX pipe readiness")

        async def run():
            read_fd, write_fd = os.pipe()
            source = os.fdopen(read_fd, "rb", buffering=0)
            try:
                with (
                    patch.object(stdio.sys, "stdin", SimpleNamespace(buffer=source)),
                    patch.object(
                        stdio.sys, "stdout", SimpleNamespace(buffer=io.BytesIO())
                    ),
                ):
                    async with anyio.create_task_group() as tasks:
                        tasks.start_soon(stdio.serve, hooks.Handler())
                        await anyio.sleep(0.01)
                        tasks.cancel_scope.cancel()
                self.assertFalse(source.closed)
                os.fstat(read_fd)
                os.write(write_fd, b"still owned")
                self.assertEqual(os.read(read_fd, 11), b"still owned")
            finally:
                source.close()
                os.close(write_fd)

        self.both(run)
