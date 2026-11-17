"""Runtime parity cases at the HTTP boundary, not only provider unit tests."""

import traceback
import unittest
from dataclasses import FrozenInstanceError

import anyio
import httpx
from test_registration_auth import intercept_request

from agenthooksprotocol.auth import (
    AuthChallenge,
    AuthContext,
    AuthenticationFailure,
    AuthenticatedHTTPTransport,
    BearerCredential,
    RoutingAuthProvider,
    normalize_auth_target,
)

BEARER = {"type": "bearer", "tokenRef": "vault/event"}
OAUTH = {
    "type": "oauth",
    "flow": "client_credentials",
    "issuer": "https://issuer.test",
    "resource": "https://resource.test",
    "clientId": "host",
    "scopes": ["events"],
}
MESSAGE = intercept_request()
SUCCESS = {
    "jsonrpc": "2.0",
    "id": "same",
    "result": {"protocolVersion": "draft", "effects": []},
}


class Provider:
    def __init__(self, token="secret"):
        self.token = token
        self.identity = object()
        self.contexts = []
        self.challenges = []

    async def credential(self, context):
        self.contexts.append(context)
        return BearerCredential(self.token, self.identity) if self.token else None

    async def challenge(self, context, challenge):
        self.challenges.append(challenge)
        return (
            BearerCredential("replacement", object())
            if challenge.retry_allowed
            else None
        )


class RoutingTests(unittest.TestCase):
    def run_async(self, run):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_mixed_bearer_oauth_and_attempt_owner(self):
        async def run():
            bearer, oauth = Provider("bearer"), Provider("oauth")
            router = RoutingAuthProvider(bearer=bearer, oauth=oauth)
            for binding, provider, initial in (
                (BEARER, bearer, "bearer"),
                (OAUTH, oauth, "oauth"),
            ):
                seen = []

                async def handle(request):
                    seen.append(request.headers["authorization"])
                    if len(seen) == 1:
                        # Replacing a configured route must not hijack the attempt.
                        router.oauth = Provider("wrong")
                        router.bearer = Provider("wrong")
                        return httpx.Response(
                            401, headers={"www-authenticate": "Bearer"}
                        )
                    return httpx.Response(200, json=SUCCESS)

                router.bearer, router.oauth = bearer, oauth
                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handle)
                ) as client:
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend={"id": "test", "authentication": binding},
                        auth_provider=router,
                        client=client,
                    )
                    await transport.request(MESSAGE)
                    self.assertFalse(client.is_closed)
                self.assertEqual(seen, ["Bearer " + initial, "Bearer replacement"])
                self.assertIs(
                    provider.challenges[-1].attempted_identity, provider.identity
                )
            self.assertEqual(len(bearer.contexts), 1)
            self.assertEqual(len(oauth.contexts), 1)

        self.run_async(run)

    def test_missing_bearer_secret_and_oauth_no_credential_fail_closed(self):
        async def run():
            seen = []

            async def handle(request):
                seen.append(request)
                return httpx.Response(200, json=SUCCESS)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                for binding in (BEARER, OAUTH):
                    router = RoutingAuthProvider(
                        bearer=Provider(None),
                        oauth=Provider(None),
                        discover=Provider("fallback"),
                    )
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend={"authentication": binding},
                        auth_provider=router,
                        client=client,
                    )
                    with self.assertRaises(AuthenticationFailure) as caught:
                        await transport.request(MESSAGE)
                    self.assertEqual(caught.exception.code, "credential_unavailable")
                self.assertEqual(seen, [])

        self.run_async(run)

    def test_explicit_authorization_bypasses_all_provider_machinery(self):
        async def run():
            provider = Provider()

            async def handle(request):
                self.assertEqual(request.headers["authorization"], "Bearer explicit")
                return httpx.Response(200, json=SUCCESS)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"authentication": OAUTH},
                    headers={"Authorization": "Bearer explicit"},
                    auth_provider=RoutingAuthProvider(oauth=provider),
                    client=client,
                )
                await transport.request(MESSAGE)
            self.assertEqual(provider.contexts, [])
            self.assertEqual(provider.challenges, [])

        self.run_async(run)

    def test_unconfigured_challenge_and_bounded_replay(self):
        async def run():
            discovery = Provider(token=None)
            seen = []

            async def handle(request):
                seen.append(request)
                return httpx.Response(401, headers={"www-authenticate": "Bearer"})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"id": "unbound"},
                    auth_provider=RoutingAuthProvider(discover=discovery),
                    client=client,
                )
                with self.assertRaises(Exception):
                    await transport.request(MESSAGE)
            self.assertNotIn("authorization", seen[0].headers)
            self.assertEqual(len(seen), 2)
            self.assertEqual(len(discovery.contexts), 1)
            self.assertIsNone(discovery.challenges[0].attempted_identity)
            self.assertFalse(discovery.challenges[1].retry_allowed)

        self.run_async(run)

    def test_redaction_and_classification(self):
        async def run():
            class Broken(Provider):
                async def credential(self, context):
                    raise ValueError("callback=https://secret.test/?token=secret")

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(lambda request: httpx.Response(500))
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"authentication": OAUTH},
                    auth_provider=RoutingAuthProvider(oauth=Broken()),
                    client=client,
                )
                with self.assertRaises(AuthenticationFailure) as caught:
                    await transport.request(MESSAGE)
                error = caught.exception
                self.assertEqual(error.code, "provider_failed")
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)
                self.assertNotIn("secret", "".join(traceback.format_exception(error)))

        self.run_async(run)

    def test_deadline_cancel_does_not_become_auth_failure(self):
        async def run():
            class Blocked(Provider):
                async def credential(self, context):
                    await anyio.sleep_forever()

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(lambda request: httpx.Response(500))
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"authentication": OAUTH},
                    auth_provider=RoutingAuthProvider(oauth=Blocked()),
                    client=client,
                )
                with self.assertRaises(TimeoutError):
                    with anyio.fail_after(0.01):
                        await transport.request(MESSAGE)

        self.run_async(run)

    def test_destination_namespace_purpose_and_extension_isolation(self):
        async def run():
            with anyio.CancelScope() as scope:
                raw = {**OAUTH, "x-host": {"list": ["value"]}}
                context = AuthContext(
                    {"id": "backend"}, raw, "https://event.test/path", "event", scope
                )
                target = normalize_auth_target(context, namespace="alice")
                raw["x-host"]["list"].append("changed")
                self.assertEqual(target.binding["x-host"]["list"], ("value",))
                with self.assertRaises(TypeError):
                    target.binding["new"] = "bad"
                with self.assertRaises(FrozenInstanceError):
                    target.namespace = "changed"
                for destination, purpose, namespace in (
                    (context.destination + "/next", "event", "alice"),
                    (context.destination, "upload", "alice"),
                    (context.destination, "event", "bob"),
                ):
                    other = normalize_auth_target(
                        AuthContext(context.backend, raw, destination, purpose, scope),
                        namespace=namespace,
                    )
                    self.assertNotEqual(target.identity, other.identity)
                self.assertNotEqual(target.typed_binding.resource, target.destination)
                provider = RoutingAuthProvider(oauth=Provider())
                credential = await provider.credential(context)
                other_context = AuthContext(
                    context.backend, raw, context.destination, "upload", scope
                )
                with self.assertRaises(AuthenticationFailure):
                    await provider.challenge(
                        other_context,
                        AuthChallenge(
                            401, {}, context.destination, credential.identity, True
                        ),
                    )

        self.run_async(run)

    def test_invalid_and_unsupported_targets(self):
        async def run():
            with anyio.CancelScope() as scope:
                for binding, code in (
                    ({"type": "other"}, "unsupported_binding"),
                    ({"type": "bearer", "tokenRef": 42}, "invalid_configuration"),
                    (
                        {**OAUTH, "issuer": "https://user:password@issuer.test"},
                        "invalid_configuration",
                    ),
                    # OAuth identifiers are HTTPS-only, rejected at binding validation.
                    ({**OAUTH, "issuer": "http://issuer.test"}, "invalid_configuration"),
                    ({**OAUTH, "resource": "http://resource.test"}, "invalid_configuration"),
                ):
                    with self.assertRaises(AuthenticationFailure) as caught:
                        normalize_auth_target(
                            AuthContext(
                                {}, binding, "https://event.test", "event", scope
                            )
                        )
                    self.assertEqual(caught.exception.code, code)

        self.run_async(run)

    def test_reference_store_is_async_and_fail_closed(self):
        async def run():
            lookups, requests = [], []

            async def resolve(reference):
                await anyio.lowlevel.checkpoint()
                lookups.append(reference)
                return "store-secret" if reference == "vault/event" else None

            async def handle(request):
                requests.append(request)
                self.assertEqual(
                    request.headers["authorization"], "Bearer store-secret"
                )
                return httpx.Response(200, json=SUCCESS)

            from agenthooksprotocol.auth import BearerAuthProvider

            router = RoutingAuthProvider(
                bearer=BearerAuthProvider(resolve_credential=resolve)
            )
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                for reference in ("vault/event", "missing"):
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend={
                            "authentication": {"type": "bearer", "tokenRef": reference}
                        },
                        auth_provider=router,
                        client=client,
                    )
                    if reference == "missing":
                        with self.assertRaises(AuthenticationFailure) as caught:
                            await transport.request(MESSAGE)
                        self.assertEqual(
                            caught.exception.code, "credential_unavailable"
                        )
                    else:
                        await transport.request(MESSAGE)
            self.assertEqual(lookups, ["vault/event", "missing"])
            self.assertEqual(len(requests), 1)

        self.run_async(run)

    def test_purpose_isolation_and_effectful_no_replay(self):
        async def run():
            for binding in (None, BEARER):
                bearer, oauth, discover = (
                    Provider("upload-secret"),
                    Provider("event-secret"),
                    Provider(token=None),
                )
                router = RoutingAuthProvider(
                    bearer=bearer, oauth=oauth, discover=discover
                )
                seen = []

                async def handle(request):
                    await request.aread()
                    seen.append(request)
                    if str(request.url) == "https://event.test":
                        return httpx.Response(200, json=SUCCESS)
                    return httpx.Response(401, headers={"www-authenticate": "Bearer"})

                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(handle)
                ) as client:
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend={"id": "test", "authentication": OAUTH},
                        auth_provider=router,
                        client=client,
                    )
                    await transport.request(MESSAGE)
                    from agenthooksprotocol.runtime import ProtocolError

                    with self.assertRaises(ProtocolError):
                        await transport.upload(
                            "https://upload.test", b"body", authentication=binding
                        )
                self.assertEqual(len(seen), 2)
                self.assertEqual(
                    seen[0].headers["authorization"], "Bearer event-secret"
                )
                self.assertEqual(
                    seen[1].headers.get("authorization"),
                    "Bearer upload-secret" if binding else None,
                )
                owner = bearer if binding else discover
                self.assertFalse(owner.challenges[-1].retry_allowed)
                self.assertEqual(oauth.challenges, [])
                if binding:
                    self.assertEqual(bearer.contexts[-1].purpose, "upload")

        self.run_async(run)

    def test_classified_recovery_survives_transport_without_secret_chain(self):
        async def run():
            class Rejected(Provider):
                async def credential(self, context):
                    try:
                        raise ValueError("secret callback code")
                    except ValueError as error:
                        raise AuthenticationFailure(
                            "secret token", code="refresh_rejected", recovery="login"
                        ) from error

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(lambda request: httpx.Response(500))
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"authentication": OAUTH},
                    auth_provider=RoutingAuthProvider(oauth=Rejected()),
                    client=client,
                )
                with self.assertRaises(AuthenticationFailure) as caught:
                    await transport.request(MESSAGE)
                self.assertEqual(caught.exception.code, "refresh_rejected")
                self.assertEqual(caught.exception.recovery, "login")
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("secret", repr(caught.exception))

        self.run_async(run)

    def test_both_oauth_flows_without_host_provider_are_typed_unsupported(self):
        async def run():
            for flow in ("authorization_code_pkce", "client_credentials"):
                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(
                        lambda request: self.fail("unsupported flow sent HTTP")
                    )
                ) as client:
                    transport = AuthenticatedHTTPTransport(
                        "https://event.test",
                        backend={"authentication": {**OAUTH, "flow": flow}},
                        auth_provider=RoutingAuthProvider(),
                        client=client,
                    )
                    with self.assertRaises(AuthenticationFailure) as caught:
                        await transport.request(MESSAGE)
                    self.assertEqual(caught.exception.code, "unsupported_binding")

        self.run_async(run)

    def test_unbound_cached_credentials_are_sent_before_unsafe_calls(self):
        async def run():
            provider = Provider("cached")
            seen = []

            async def handle(request):
                seen.append(request)
                self.assertEqual(request.headers["authorization"], "Bearer cached")
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"id": "unbound"},
                    auth_provider=RoutingAuthProvider(discover=provider),
                    client=client,
                )
                notification = {**MESSAGE}
                notification.pop("id", None)
                await transport.notify(notification)
                from agenthooksprotocol.runtime import ProtocolError

                with self.assertRaises(ProtocolError):
                    await transport.upload("https://upload.test", b"body")
            self.assertEqual(len(seen), 2)
            self.assertEqual(
                [c.purpose for c in provider.contexts], ["event", "upload"]
            )
            self.assertEqual(provider.challenges, [])

        self.run_async(run)

    def test_explicit_authorization_overrides_malformed_binding(self):
        async def run():
            provider = Provider()

            async def handle(request):
                self.assertEqual(request.headers["authorization"], "Bearer explicit")
                return httpx.Response(200, json=SUCCESS)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    "https://event.test",
                    backend={"authentication": {"type": "unknown"}},
                    headers={"Authorization": "Bearer explicit"},
                    auth_provider=RoutingAuthProvider(discover=provider),
                    client=client,
                )
                await transport.request(MESSAGE)
            self.assertEqual(provider.contexts, [])
            self.assertEqual(provider.challenges, [])

        self.run_async(run)
