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
            {"X\n": "x"},
            {"X é": "x"},
            {"": "x"},
        ]
        for char in ("\r", "\n", "\x00"):
            invalid.append({"X": "secret" + char})
        for headers in invalid:
            with (
                self.subTest(headers=headers),
                self.assertRaises(HeaderFailure) as caught,
            ):
                validate_headers(headers)
            self.assertNotIn("secret", str(caught.exception))
        self.assertEqual(validate_headers({"X": ""}), {"x": ""})
        validate_headers({"X": {"valueEnv": "KEY", "extension": True}})
        validate_headers({"X": "x" * 65536})
        self.assertEqual(validate_headers({"X": "first", "x": "last"}), {"x": "last"})

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

    def test_existing_no_redirect_behavior_and_backend_isolation(self):
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
        for headers in ({"X": "bad\n"},):
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
                "headers": {
                    "X-Tenant": "public",
                    "Authorization": "Bearer abc123",
                    "Cookie": "key=value",
                    "X-Label": "café",
                },
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
                self.assertEqual(seen[0].headers["authorization"], "Bearer abc123")
                self.assertEqual(seen[0].headers["x-label"], "café")
                await hooks.aclose()
            registration["hooks"][0]["transport"]["headers"] = {
                "Authorization": "sensitive\n"
            }
            with self.assertRaises(HeaderFailure):
                Hooks(
                    registration,
                    source="urn:test",
                    harness=event.Harness(name="test", version="1"),
                    capabilities=capabilities(),
                )

        anyio.run(run)

    def test_upload_receives_headers_but_provider_discovery_does_not(self):
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
                    [None, "event-only", None, "event-only"],
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

    def test_generated_header_types_round_trip(self):
        from agenthooksprotocol._models import HttpHeaderSource, HttpTransport
        from agenthooksprotocol.runtime import Validator
        from test_public_hooks import config

        endpoint = HttpTransport(
            url=URL,
            headers={
                "X-Tenant": "team",
                "X-Key": HttpHeaderSource(value_env="API_KEY"),
            },
        )
        self.assertEqual(endpoint.headers["X-Key"].value_env, "API_KEY")
        registration = config()
        registration["hooks"][0]["transport"] = dict(endpoint)
        Validator().validate("registration", registration)

    def test_injected_http_transport_preserves_programmatic_metadata(self):
        from agenthooksprotocol import Hooks, event
        from agenthooksprotocol.transports import HTTPTransport
        from test_public_hooks import config, capabilities

        async def run():
            registration = config()
            registration["hooks"][0]["transport"] = {
                "type": "http",
                "url": URL,
                "headers": {"X-Tenant": "registered"},
            }
            seen = []

            async def handle(request):
                seen.append(request)
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                injected = HTTPTransport(
                    URL,
                    client=client,
                    headers={"x-tenant": "default", "X-Default": "kept"},
                )
                hooks = Hooks(
                    registration,
                    source="urn:test",
                    harness=event.Harness(name="test", version="1"),
                    capabilities=capabilities(),
                    transport=injected,
                )
                await hooks._ensure_ready()
                await hooks._transports["org.example.hook"].notify(
                    {"method": "hooks/observe"}
                )
                self.assertEqual(seen[0].headers["x-tenant"], "registered")
                self.assertEqual(seen[0].headers["x-default"], "kept")
                await hooks.aclose()
                self.assertFalse(client.is_closed)
                self.assertEqual(injected.headers["x-tenant"], "default")

        anyio.run(run)

    def test_configured_credentials_override_defaults_and_suppress_oauth(self):
        async def run():
            seen = []

            class ForbiddenProvider:
                async def credential(self, context):
                    raise AssertionError("OAuth must not run")

                async def challenge(self, context, challenge):
                    raise AssertionError("OAuth challenge must not run")

            async def handle(request):
                await request.aread()
                seen.append(request)
                return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                sdk = transport(
                    client,
                    {
                        "Authorization": "ignored",
                        "aUtHoRiZaTiOn": "Bearer abc123",
                        "Cookie": "session=literal-secret",
                        "X-Api-Key": "literal-key",
                        "Content-Type": "custom/type",
                        "Origin": "https://custom.test",
                        "X-Label": "café",
                        "AHP-Custom": "override",
                    },
                    authenticated=True,
                    auth_provider=ForbiddenProvider(),
                    headers={"X-Api-Key": "default"},
                )
                with self.assertRaises(ProtocolError):
                    await sdk.request(intercept_request())
                with self.assertRaises(ProtocolError):
                    await sdk.upload(
                        URL + "/upload", b"body", authentication={"type": "oauth"}
                    )
                self.assertEqual(len(seen), 2)
                for request in seen:
                    self.assertEqual(request.headers["authorization"], "Bearer abc123")
                    self.assertEqual(
                        request.headers["cookie"], "session=literal-secret"
                    )
                    self.assertEqual(request.headers["x-api-key"], "literal-key")
                    self.assertEqual(request.headers["content-type"], "custom/type")
                    self.assertEqual(request.headers["x-label"], "café")
                    self.assertEqual(request.headers["origin"], "https://custom.test")
                self.assertNotIn("authorization", client.headers)

        anyio.run(run)

    def test_existing_secret_resolver_for_authorization_and_fail_closed(self):
        async def run():
            seen, calls = [], []

            async def resolve(reference):
                calls.append(reference)
                return "Bearer abc123"

            async def handle(request):
                await request.aread()
                seen.append(request)
                if request.url.path.endswith("/upload"):
                    import hashlib

                    return httpx.Response(
                        201,
                        json={
                            "ref": "uploaded",
                            "size": len(request.content),
                            "sha256": hashlib.sha256(request.content).hexdigest(),
                        },
                    )
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                sdk = transport(
                    client,
                    {"Authorization": {"valueRef": "vault/key"}},
                    resolve_credential=resolve,
                )
                await sdk.notify({"method": "hooks/observe"})
                receipt = await sdk.upload(URL + "/upload", b"body")
                self.assertEqual(receipt.ref, "uploaded")
                self.assertEqual(calls, ["vault/key", "vault/key"])
                self.assertTrue(
                    all(r.headers["authorization"] == "Bearer abc123" for r in seen)
                )
                sdk = transport(
                    client,
                    {"Authorization": {"valueEnv": "MISSING_HEADER"}},
                    auth_provider=Provider(),
                )
                with (
                    patch.dict(os.environ, {}, clear=True),
                    self.assertRaises(HeaderFailure),
                ):
                    await sdk.notify({"method": "hooks/observe"})
                self.assertEqual(len(seen), 2)

        anyio.run(run)
