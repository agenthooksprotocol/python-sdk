import os
import unittest
from unittest.mock import patch

import anyio
import httpx

from agenthooksprotocol.auth import AuthenticatedHTTPTransport
from agenthooksprotocol.headers import HeaderFailure, validate_headers
from agenthooksprotocol.runtime import ProtocolError
from test_registration_auth import Provider, BINDING, intercept_request


URL = "https://event.test/hooks"


def transport(client, metadata=None, **kwargs):
    backend = {
        "id": "policy",
        "transport": {"type": "http", "url": URL, "headers": metadata or {}},
    }
    if kwargs.pop("authenticated", False):
        backend["authentication"] = BINDING
    return AuthenticatedHTTPTransport(URL, backend=backend, client=client, **kwargs)


class RegistrationHeaderTests(unittest.TestCase):
    def test_validation(self):
        invalid = [
            None,
            [],
            {"X": None},
            {"X": 1},
            {"X": []},
            {"X": {}},
            {"X": {"valueEnv": "X", "valueRef": "x"}},
            {"X": {"valueEnv": "X\n"}},
            {"X": {"valueEnv": "1X"}},
            {"X": {"valueRef": ""}},
            {"X": {"unknown": "x"}},
            {"X": "a", "x": "a"},
            {"X\n": "x"},
            {"X é": "x"},
            {"": "x"},
        ]
        for char in ("\r", "\n", "\t", "\x00", "\x7f", "é"):
            invalid.append({"X": "secret" + char})
        for name in (
            "Authorization",
            "Proxy-Foo",
            "Cookie",
            "Set-Cookie",
            "Host",
            "Content-Type",
            "Accept",
            "Content-Length",
            "Content-Encoding",
            "Connection",
            "Keep-Alive",
            "Transfer-Encoding",
            "TE",
            "Trailer",
            "Upgrade",
            "Expect",
            "Origin",
            "Referer",
            "Sec-Foo",
            "AHP-Foo",
        ):
            invalid.append({name.swapcase(): "secret"})
        for headers in invalid:
            with (
                self.subTest(headers=headers),
                self.assertRaises(HeaderFailure) as caught,
            ):
                validate_headers(headers)
            self.assertNotIn("secret", str(caught.exception))
        self.assertEqual(validate_headers({"X": ""}), {"X": ""})
        validate_headers({"X": {"valueEnv": "KEY", "extension": True}})
        with self.assertRaises(HeaderFailure):
            validate_headers({"X": "x" * 65536})

    def test_emitted_merge_and_rotation(self):
        async def run():
            seen, contexts = [], []

            class Resolver:
                async def resolve(self, context):
                    contexts.append(context)
                    return "ref-" + str(len(contexts))

            async def handle(request):
                seen.append(request)
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle),
                headers={"X-Client": "do-not-inherit"},
            ) as client:
                sdk = transport(
                    client,
                    {
                        "X-Tenant": "registered",
                        "X-Env": {"valueEnv": "HEADER_KEY"},
                        "X-Ref": {"valueRef": "vault/key"},
                        "X-Empty": "",
                        "X-Literal": "${UNCHANGED}",
                    },
                    headers={"x-tenant": "default", "X-Default": "kept"},
                    header_resolver=Resolver(),
                )
                with (
                    anyio.fail_after(3),
                    patch.dict(os.environ, {"HEADER_KEY": "env-1"}),
                ):
                    await sdk.notify({"method": "hooks/observe"})
                    os.environ["HEADER_KEY"] = "env-2"
                    await sdk.notify({"method": "hooks/observe"})
                self.assertEqual([r.headers["x-env"] for r in seen], ["env-1", "env-2"])
                self.assertEqual([r.headers["x-ref"] for r in seen], ["ref-1", "ref-2"])
                self.assertEqual(seen[0].headers["x-tenant"], "registered")
                self.assertEqual(seen[0].headers["x-default"], "kept")
                self.assertEqual(seen[0].headers["x-literal"], "${UNCHANGED}")
                self.assertNotIn("x-client", seen[0].headers)
                self.assertNotIn(b"vault/key", seen[0].content)
                self.assertEqual(contexts[0].destination, URL)
                self.assertEqual(contexts[0].backend["id"], "policy")
                self.assertEqual(contexts[0].purpose, "event")
                self.assertLess(contexts[0].deadline, float("inf"))
                self.assertNotIn("vault/key", repr(contexts[0]))

        anyio.run(run)

    def test_challenge_reuses_resolved_headers(self):
        async def run():
            seen, calls = [], []

            class Resolver:
                async def resolve(self, context):
                    calls.append(context)
                    return "resolved-secret"

            async def handle(request):
                seen.append(request)
                if len(seen) == 1:
                    return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": "same",
                        "result": {"protocolVersion": "draft", "effects": []},
                    },
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                sdk = transport(
                    client,
                    {"X-Key": {"valueRef": "vault"}},
                    authenticated=True,
                    auth_provider=Provider(),
                    header_resolver=Resolver(),
                )
                await sdk.request(intercept_request())
                self.assertEqual(len(calls), 1)
                self.assertEqual(
                    [r.headers["x-key"] for r in seen], ["resolved-secret"] * 2
                )
                self.assertEqual(
                    [r.headers["authorization"] for r in seen],
                    ["Bearer old-secret", "Bearer new-secret"],
                )

        anyio.run(run)

    def test_resolution_failures_send_nothing(self):
        async def run():
            seen = []

            async def handle(request):
                seen.append(request)
                return httpx.Response(204)

            class Resolver:
                def __init__(self, value):
                    self.value = value

                async def resolve(self, context):
                    if isinstance(self.value, Exception):
                        raise self.value
                    return self.value

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                for value in (
                    None,
                    "",
                    42,
                    "secret\n",
                    "secret\t",
                    "é",
                    ValueError("sensitive"),
                ):
                    sdk = transport(
                        client,
                        {"X-Key": {"valueRef": "sensitive"}},
                        header_resolver=Resolver(value),
                    )
                    with self.assertRaises(HeaderFailure) as caught:
                        await sdk.notify({"method": "hooks/observe"})
                    self.assertNotIn("sensitive", str(caught.exception))
                with patch.dict(os.environ, {}, clear=True):
                    for source in (
                        {"valueEnv": "MISSING"},
                        {"valueRef": "unsupported"},
                    ):
                        with self.assertRaises(HeaderFailure):
                            await transport(client, {"X-Key": source}).notify(
                                {"method": "hooks/observe"}
                            )
                self.assertEqual(seen, [])

        anyio.run(run)

    def test_cancellation_and_deadline(self):
        async def run():
            seen = []

            class Resolver:
                async def resolve(self, context):
                    await anyio.sleep_forever()

            async def handle(request):
                seen.append(request)
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                sdk = transport(
                    client, {"X-Key": {"valueRef": "vault"}}, header_resolver=Resolver()
                )
                with self.assertRaises(TimeoutError):
                    with anyio.fail_after(0.01):
                        await sdk.notify({"method": "hooks/observe"})
                self.assertEqual(seen, [])

        anyio.run(run)

    def test_redirect_and_backend_isolation(self):
        async def run():
            seen = []

            async def handle(request):
                seen.append(request)
                return httpx.Response(302, headers={"Location": URL + "/other"})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle), follow_redirects=True
            ) as client:
                with self.assertRaises(ProtocolError):
                    await transport(client, {"X-Key": "metadata"}).notify(
                        {"method": "hooks/observe"}
                    )
                self.assertEqual(len(seen), 1)
                with self.assertRaises(ProtocolError):
                    await transport(client).notify({"method": "hooks/observe"})
                self.assertNotIn("x-key", seen[1].headers)
                self.assertNotIn("x-key", client.headers)

        anyio.run(run)

    def test_programmatic_defaults_rejected_on_registration_path(self):
        for headers in (
            {"Authorization": "secret"},
            {"X": "a", "x": "b"},
            {"X": "bad\n"},
        ):
            with self.assertRaises(HeaderFailure):
                transport(None, headers=headers)

    def test_public_registration_and_static_rejection(self):
        from agenthooksprotocol import Hooks, event
        from test_public_hooks import config, capabilities

        async def run():
            registration = config()
            registration["hooks"][0]["transport"] = {
                "type": "http",
                "url": URL,
                "headers": {"X-Tenant": "public"},
            }
            seen = []

            async def handle(request):
                seen.append(request)
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                hooks = Hooks(
                    registration,
                    source="urn:test",
                    harness=event.Harness(name="test", version="1"),
                    capabilities=capabilities(),
                )
                await hooks._ensure_ready()
                registered = hooks._transports["org.example.hook"]
                registered._client = client
                await registered.notify({"method": "hooks/observe"})
                self.assertEqual(seen[0].headers["x-tenant"], "public")
                await hooks.aclose()
            registration["hooks"][0]["transport"]["headers"] = {
                "Authorization": "sensitive"
            }
            with self.assertRaises(HeaderFailure):
                Hooks(
                    registration,
                    source="urn:test",
                    harness=event.Harness(name="test", version="1"),
                    capabilities=capabilities(),
                )

        anyio.run(run)

    def test_upload_and_provider_discovery_do_not_receive_event_headers(self):
        async def run():
            seen = []

            async def handle(request):
                await request.aread()
                seen.append(request)
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:

                class DiscoveryProvider:
                    async def credential(self, context):
                        await client.get(URL + "/discovery")
                        return None

                sdk = transport(
                    client,
                    {"X-Key": {"valueEnv": "SECRET"}},
                    auth_provider=DiscoveryProvider(),
                )
                with patch.dict(os.environ, {"SECRET": "event-only"}):
                    await sdk.notify({"method": "hooks/observe"})
                with self.assertRaises(ProtocolError):
                    await sdk.upload(URL + "/upload", b"body")
                self.assertEqual(
                    [r.headers.get("x-key") for r in seen],
                    [None, "event-only", None, None],
                )

        anyio.run(run)

    def test_resolver_self_cancellation_fails_closed(self):
        from agenthooksprotocol.runtime import OperationCancelledError

        async def run():
            class Resolver:
                async def resolve(self, context):
                    context.cancellation.cancel()
                    return "secret"

            sdk = transport(
                None, {"X-Key": {"valueRef": "vault"}}, header_resolver=Resolver()
            )
            with self.assertRaises(OperationCancelledError):
                await sdk.notify({"method": "hooks/observe"})
            self.assertIsNone(sdk._client)

        anyio.run(run)

    def test_endpoint_change_and_resolved_size_fail_before_io(self):
        async def run():
            sdk = transport(None, {"X-Tenant": "private"})
            sdk.url = URL + "/other"
            with self.assertRaises(HeaderFailure):
                await sdk.notify({"method": "hooks/observe"})
            self.assertIsNone(sdk._client)
            with patch.dict(os.environ, {"KEY": "x" * 65536}):
                sdk = transport(None, {"X-Key": {"valueEnv": "KEY"}})
                with self.assertRaises(HeaderFailure):
                    await sdk.notify({"method": "hooks/observe"})
                self.assertIsNone(sdk._client)

        anyio.run(run)
