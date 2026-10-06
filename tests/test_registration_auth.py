"""Provider boundary tests; no auth workers or token-endpoint mocks required."""

import json
import os
import unittest
from unittest.mock import patch

import anyio
import httpx

from agenthooksprotocol.auth import (
    AuthenticatedHTTPTransport,
    BearerCredential,
    EnvironmentAuthProvider,
)
from agenthooksprotocol.runtime import ProtocolError


BINDING = {"type": "bearer", "tokenRef": "host/key"}
BACKEND = {"id": "backend", "authentication": BINDING, "extra": {"kept": True}}


class Provider:
    def __init__(self):
        self.contexts = []
        self.challenges = []
        self.closed = False

    async def credential(self, context):
        self.contexts.append(context)
        if context.binding is None:
            return None
        return BearerCredential("old-secret", identity="version-1")

    async def challenge(self, context, challenge):
        self.challenges.append(challenge)
        return BearerCredential("new-secret", identity="version-2")

    async def aclose(self):
        self.closed = True


class RegistrationAuthTests(unittest.TestCase):
    def test_challenge_retry_preserves_body_context_and_identity(self):
        async def run():
            provider = Provider()
            seen = []
            message = {
                "jsonrpc": "2.0",
                "id": "same",
                "method": "hooks/intercept",
                "params": {},
            }

            async def handle(request):
                seen.append(request)
                if len(seen) == 1:
                    message["params"]["mutated"] = True
                    return httpx.Response(
                        401, headers={"WWW-Authenticate": 'Bearer realm="ahp"'}
                    )
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": "same",
                        "result": {"protocolVersion": "draft", "effects": []},
                    },
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle),
                headers={"X-Leak": "bad"},
                cookies={"secret": "bad"},
                auth=("user", "password"),
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend=BACKEND,
                    auth_provider=provider,
                    client=client,
                )
                await transport.request(message)
                self.assertEqual(len(seen), 2)
                self.assertEqual(seen[0].content, seen[1].content)
                self.assertEqual(json.loads(seen[1].content)["params"], {})
                self.assertEqual(seen[0].headers["authorization"], "Bearer old-secret")
                self.assertEqual(seen[1].headers["authorization"], "Bearer new-secret")
                self.assertNotIn("cookie", seen[0].headers)
                self.assertNotIn("x-leak", seen[0].headers)
                context = provider.contexts[0]
                self.assertEqual(context.backend, BACKEND)
                self.assertEqual(context.binding, BINDING)
                self.assertEqual(context.destination, "https://event.test")
                self.assertEqual(context.purpose, "event")
                self.assertEqual(provider.challenges[0].attempted_identity, "version-1")
                self.assertTrue(provider.challenges[0].retry_allowed)
                self.assertNotIn("secret", repr(BearerCredential("old-secret")))
                await transport.aclose()
                self.assertFalse(client.is_closed)
                self.assertFalse(provider.closed)

        anyio.run(run)

    def test_bounded_retry_and_unsafe_operations(self):
        async def run():
            for method, status, challenge, expected in [
                ("request", 401, "Bearer", 2),
                ("request", 403, "Bearer", 1),
                ("request", 401, "Basic", 1),
                ("notify", 401, "Bearer", 1),
            ]:
                seen = []
                provider = Provider()

                async def handle(request):
                    seen.append(request)
                    return httpx.Response(
                        status, headers={"WWW-Authenticate": challenge}
                    )

                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handle)
                ) as client:
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend=BACKEND,
                        auth_provider=provider,
                        client=client,
                    )
                    with self.assertRaises(ProtocolError):
                        await getattr(transport, method)(
                            {"id": "same", "method": "hooks/intercept"}
                        )
                    self.assertEqual(len(seen), expected)
                    self.assertEqual(len(provider.challenges), expected)
                    self.assertFalse(provider.challenges[-1].retry_allowed)

        anyio.run(run)

    def test_anonymous_success_and_explicit_discovery(self):
        async def run():
            for reject in (False, True):
                seen = []
                provider = Provider()

                async def handle(request):
                    seen.append(request)
                    if reject and len(seen) == 1:
                        return httpx.Response(
                            401, headers={"WWW-Authenticate": "Bearer"}
                        )
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
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend={"id": "anonymous"},
                        auth_provider=provider,
                        client=client,
                    )
                    await transport.request({"id": "same", "method": "hooks/intercept"})
                    self.assertNotIn("authorization", seen[0].headers)
                    self.assertEqual(len(provider.challenges), int(reject))
                    if reject:
                        self.assertIsNone(provider.challenges[0].attempted_identity)
                        self.assertEqual(
                            seen[1].headers["authorization"], "Bearer new-secret"
                        )

        anyio.run(run)

    def test_upload_binding_isolated_and_never_replayed(self):
        async def run():
            for binding in (None, {"type": "bearer", "tokenRef": "upload/key"}):
                provider = Provider()
                seen = []

                async def handle(request):
                    await request.aread()
                    seen.append(request)
                    return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})

                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handle)
                ) as client:
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend=BACKEND,
                        auth_provider=provider,
                        client=client,
                    )
                    with self.assertRaises(ProtocolError):
                        await transport.upload(
                            "https://upload.test", b"body", authentication=binding
                        )
                    self.assertEqual(len(seen), 1)
                    self.assertEqual(provider.contexts[0].binding, binding)
                    self.assertEqual(provider.contexts[0].purpose, "upload")
                    self.assertEqual(
                        provider.contexts[0].destination, "https://upload.test"
                    )
                    self.assertEqual(
                        "authorization" in seen[0].headers, binding is not None
                    )
                    self.assertFalse(provider.challenges[0].retry_allowed)

        anyio.run(run)

    def test_missing_unknown_and_provider_errors_fail_closed(self):
        async def run():
            class Broken(Provider):
                async def credential(self, context):
                    raise ValueError("leaked-secret")

            for provider in (EnvironmentAuthProvider(), Broken()):
                transport = AuthenticatedHTTPTransport(
                    "https://event.test", backend=BACKEND, auth_provider=provider
                )
                with self.assertRaises(ProtocolError) as error:
                    await transport.request({"id": "same", "method": "hooks/intercept"})
                self.assertNotIn("leaked-secret", str(error.exception))
                self.assertIsNone(transport._client)
            with self.assertRaises(ProtocolError):
                AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"authentication": {"type": "unknown"}},
                    auth_provider=Provider(),
                )

        anyio.run(run)

    def test_environment_and_host_reference_adapter(self):
        async def run():
            seen = []

            async def handle(request):
                seen.append(request.headers["authorization"])
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": "same",
                        "result": {"protocolVersion": "draft", "effects": []},
                    },
                )

            with patch.dict(os.environ, {"AHP_TEST_TOKEN": "environment-secret"}):
                for binding, provider in [
                    (
                        {"type": "bearer", "tokenEnv": "AHP_TEST_TOKEN"},
                        EnvironmentAuthProvider(),
                    ),
                    (BINDING, EnvironmentAuthProvider(lambda ref: "reference-secret")),
                ]:
                    async with httpx.AsyncClient(
                        transport=httpx.MockTransport(handle)
                    ) as client:
                        transport = AuthenticatedHTTPTransport(
                            "https://event.test",
                            backend={"authentication": binding},
                            auth_provider=provider,
                            client=client,
                        )
                        await transport.request(
                            {"id": "same", "method": "hooks/intercept"}
                        )
            self.assertEqual(
                seen, ["Bearer environment-secret", "Bearer reference-secret"]
            )

        anyio.run(run)

    def test_provider_obeys_operation_cancellation(self):
        async def run():
            finished = anyio.Event()

            class Waiting(Provider):
                async def credential(self, context):
                    try:
                        await anyio.sleep_forever()
                    finally:
                        finished.set()

            transport = AuthenticatedHTTPTransport(
                "https://event.test", backend=BACKEND, auth_provider=Waiting()
            )
            with anyio.move_on_after(0.01) as scope:
                await transport.request({"id": "same", "method": "hooks/intercept"})
            self.assertTrue(scope.cancelled_caught)
            self.assertTrue(finished.is_set())
            self.assertIsNone(transport._client)

        for backend in ("asyncio", "trio"):
            anyio.run(run, backend=backend)

    def test_oauth_binding_forwarded_without_exchanging_client_secret(self):
        async def run():
            for flow in ("client_credentials", "authorization_code_pkce"):
                binding = {
                    "type": "oauth",
                    "flow": flow,
                    "issuer": "https://issuer.test",
                    "resource": "https://event.test",
                    "clientId": "host",
                    "clientSecretRef": "storage/client-secret",
                    "scopes": ["events"],
                }
                provider = Provider()

                async def handle(request):
                    self.assertEqual(
                        request.headers["authorization"], "Bearer old-secret"
                    )
                    self.assertNotIn("storage/client-secret", str(request.headers))
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
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend={"id": "oauth", "authentication": binding},
                        auth_provider=provider,
                        client=client,
                    )
                    await transport.request({"id": "same", "method": "hooks/intercept"})
                self.assertEqual(provider.contexts[0].binding, binding)
            with self.assertRaises(ProtocolError):
                AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"authentication": {"type": "oauth", "flow": "unknown"}},
                    auth_provider=Provider(),
                )

        anyio.run(run)

    def test_arbitrary_effectful_request_cannot_retry(self):
        async def run():
            provider = Provider()
            seen = []

            async def handle(request):
                seen.append(request)
                return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend=BACKEND,
                    auth_provider=provider,
                    client=client,
                )
                with self.assertRaises(ProtocolError):
                    await transport.request(
                        {"id": "same", "method": "arbitrary/effect"}
                    )
            self.assertEqual(len(seen), 1)
            self.assertFalse(provider.challenges[0].retry_allowed)

        anyio.run(run)

    def test_canonical_rpc_errors_are_distinct_and_redacted(self):
        from agenthooksprotocol.runtime import BackendRPCError
        from agenthooksprotocol.transports.http import HTTPTransport

        async def run():
            async def handle(request):
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": "same",
                        "error": {
                            "code": -32603,
                            "message": "backend-secret",
                            "data": "private",
                        },
                    },
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                for transport in (
                    HTTPTransport("https://event.test", client=client),
                    AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend=BACKEND,
                        auth_provider=Provider(),
                        client=client,
                    ),
                ):
                    with self.assertRaises(BackendRPCError) as error:
                        await transport.request(
                            {"id": "same", "method": "hooks/intercept"}
                        )
                    self.assertNotIn("backend-secret", str(error.exception))
                    self.assertNotIn("private", str(error.exception))

        anyio.run(run)

    def test_sanitized_failure_categories(self):
        from agenthooksprotocol.auth import AuthenticationFailure, TransportFailure
        from agenthooksprotocol.runtime import BackendRPCError
        import traceback

        async def run():
            cases = [
                (httpx.ReadTimeout("credential-secret"), TimeoutError),
                (httpx.ConnectError("credential-secret"), TransportFailure),
                (httpx.Response(503, content=b"credential-secret"), TransportFailure),
                (httpx.Response(200, content=b"credential-secret"), ProtocolError),
                (
                    httpx.Response(
                        400,
                        json={
                            "jsonrpc": "2.0",
                            "id": "same",
                            "error": {"code": -32603, "message": "credential-secret"},
                        },
                    ),
                    BackendRPCError,
                ),
            ]
            # Cover initial send and send after a challenge; timeout remains a
            # timeout at both stages and the auth retry budget remains bounded.
            for outcome, category in cases:
                for retry in (False, True):
                    attempts = []

                    async def handle(request):
                        attempts.append(request)
                        if retry and len(attempts) == 1:
                            return httpx.Response(
                                401, headers={"WWW-Authenticate": "Bearer"}
                            )
                        if isinstance(outcome, Exception):
                            raise outcome
                        return outcome

                    async with httpx.AsyncClient(
                        transport=httpx.MockTransport(handle)
                    ) as client:
                        transport = AuthenticatedHTTPTransport(
                            "https://event.test",
                            backend=BACKEND,
                            auth_provider=Provider(),
                            client=client,
                        )
                        with self.assertRaises(category) as caught:
                            await transport.request(
                                {"id": "same", "method": "hooks/intercept"}
                            )
                        self.assertIs(type(caught.exception), category)
                        self.assertNotIn(
                            "credential-secret",
                            "".join(traceback.format_exception(caught.exception)),
                        )
                        self.assertEqual(len(attempts), 2 if retry else 1)

            class Broken(Provider):
                async def credential(self, context):
                    raise ValueError("credential-secret")

            transport = AuthenticatedHTTPTransport(
                "https://event.test", backend=BACKEND, auth_provider=Broken()
            )
            with self.assertRaises(AuthenticationFailure) as caught:
                await transport.request({"id": "same", "method": "hooks/intercept"})
            self.assertNotIn(
                "credential-secret",
                "".join(traceback.format_exception(caught.exception)),
            )

        anyio.run(run)

    def test_upload_http_and_malformed_response_categories(self):
        from agenthooksprotocol.auth import TransportFailure

        async def run():
            for status, category in [(503, TransportFailure), (201, ProtocolError)]:

                async def handle(request):
                    await request.aread()
                    return httpx.Response(status, content=b"credential-secret")

                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handle)
                ) as client:
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend=BACKEND,
                        auth_provider=Provider(),
                        client=client,
                    )
                    with self.assertRaises(category) as caught:
                        await transport.upload("https://upload.test", b"body")
                    self.assertIs(type(caught.exception), category)
                    self.assertNotIn("credential-secret", str(caught.exception))

        anyio.run(run)

    def test_terminal_challenge_cancellation_propagates(self):
        async def run():
            from agenthooksprotocol import OperationCancelledError

            class Cancelling(Provider):
                async def challenge(self, context, challenge):
                    if not challenge.retry_allowed:
                        context.cancellation.cancel()
                        return None
                    return await super().challenge(context, challenge)

            calls = []

            async def reject(request):
                calls.append(request)
                return httpx.Response(401, headers={"www-authenticate": "Bearer"})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(reject)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend=BACKEND,
                    auth_provider=Cancelling(),
                    client=client,
                )
                with self.assertRaises(OperationCancelledError):
                    await transport.request({"id": "same", "method": "hooks/intercept"})
                self.assertEqual(len(calls), 2)

        for backend in ("asyncio", "trio"):
            anyio.run(run, backend=backend)
