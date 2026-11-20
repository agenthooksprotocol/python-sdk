"""Discovery tests cross the real httpx host boundary on asyncio and Trio."""

import unittest

import anyio
import httpx

from agenthooksprotocol.auth import (
    AuthChallenge,
    AuthenticationFailure,
    AuthTarget,
    OAuthBinding,
)
from agenthooksprotocol._oauth_discovery import (
    MAX_RESPONSE_BYTES,
    discover,
    safe_request,
)
from agenthooksprotocol._oauth_types import OAuthClientConfiguration, OperationBudget
from agenthooksprotocol.oauth import ManagedOAuthProvider
from agenthooksprotocol.runtime import OperationCancelledError
from agenthooksprotocol._scope_decision import DecisionFailure, classify

RESOURCE = "https://resource.test/api/events"
ISSUER = "https://issuer.test/tenant"
PR_PATH = "https://resource.test/.well-known/oauth-protected-resource/api/events"
PR_ROOT = "https://resource.test/.well-known/oauth-protected-resource"
AS_PATH = "https://issuer.test/.well-known/oauth-authorization-server/tenant"
OIDC_INSERT = "https://issuer.test/.well-known/openid-configuration/tenant"
OIDC_APPEND = "https://issuer.test/tenant/.well-known/openid-configuration"


class HostNetwork:
    def __init__(self, client, denied=()):
        self.client = client
        self.denied = denied
        self.allowed = []
        self.sent = []

    async def authorize(self, url, purpose, budget):
        if any(value in url for value in self.denied):
            raise AuthenticationFailure(code="untrusted_destination")
        self.allowed.append((url, purpose))

    async def send(self, request, purpose, budget):
        assert (str(request.url), purpose) in self.allowed
        self.sent.append(str(request.url))
        return await self.client.send(request, stream=True, follow_redirects=False)


class Policy:
    def __init__(self, *, resource_value=RESOURCE, **changes):
        self.resource_value = resource_value
        self.configuration = OAuthClientConfiguration(
            issuer=ISSUER,
            client_id="local-client",
            flow="client_credentials",
            scopes=("read",),
            token_endpoint_auth_method="client_secret_basic",
            client_secret="local-test-secret",
        )
        if changes:
            from dataclasses import replace

            self.configuration = replace(self.configuration, **changes)
        self.requirements = None

    async def resource(self, target, budget):
        return self.resource_value

    async def select(self, target, resource, issuers, required_scopes, budget):
        self.requirements = required_scopes
        return self.configuration


def target(binding=None, destination=RESOURCE):
    return AuthTarget("test", "backend", destination, "event", None, binding)


def challenge(value):
    return AuthChallenge(401, {"WWW-Authenticate": value}, RESOURCE, None, True)


def documents():
    return {
        PR_PATH: {
            "resource": RESOURCE,
            "authorization_servers": [ISSUER],
            "scopes_supported": ["admin"],
        },
        AS_PATH: {
            "issuer": ISSUER,
            "token_endpoint": "https://issuer.test/token",
            "grant_types_supported": ["client_credentials"],
        },
    }


class OAuthDiscoveryTests(unittest.TestCase):
    def both(self, operation):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(operation, backend=backend)

    async def run_discovery(
        self,
        docs=None,
        *,
        auth=None,
        policy=None,
        denied=(),
        binding=None,
        destination=RESOURCE,
    ):
        docs = documents() if docs is None else docs

        def handle(request):
            value = docs.get(str(request.url))
            if isinstance(value, httpx.Response):
                return value
            return (
                httpx.Response(404)
                if value is None
                else httpx.Response(200, json=value)
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            network = HostNetwork(client, denied)
            try:
                result = await discover(
                    target(binding, destination),
                    auth,
                    network,
                    policy or Policy(),
                    OperationBudget.after(2),
                )
            except DecisionFailure as failure:
                # The provider's error boundary classifies decide's outcomes.
                code, recovery, scopes = classify(failure)
                raise AuthenticationFailure(
                    code=code, recovery=recovery, required_scopes=scopes
                ) from None
            return result, network

    def test_path_then_root_and_oauth_oidc_order(self):
        async def run():
            docs = documents()
            docs[PR_ROOT] = docs.pop(PR_PATH)
            docs[PR_ROOT]["resource"] = "https://resource.test"
            docs[OIDC_APPEND] = docs.pop(AS_PATH)
            result, network = await self.run_discovery(
                docs,
                policy=Policy(resource_value="https://resource.test"),
            )
            self.assertEqual(result.resource, "https://resource.test")
            self.assertEqual(
                network.sent, [PR_PATH, PR_ROOT, AS_PATH, OIDC_INSERT, OIDC_APPEND]
            )
            self.assertIn(("https://issuer.test/token", "token"), network.allowed)

        self.both(run)

    def test_resource_is_bound_to_successful_discovery_candidate(self):
        async def run():
            # Local permission for a path resource cannot bless root metadata
            # that incorrectly identifies that path resource.
            docs = documents()
            docs[PR_ROOT] = docs.pop(PR_PATH)
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(docs)
            docs[PR_ROOT]["resource"] = "https://resource.test"
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(docs)
            # A challenge's arbitrary metadata URL is bound to the actual
            # request URL, not the local policy's different resource.
            url = "https://metadata.test/resource"
            docs[url] = docs.pop(PR_ROOT)
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(
                    docs,
                    auth=challenge(f'Bearer resource_metadata="{url}"'),
                    policy=Policy(resource_value="https://resource.test"),
                )
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(
                    policy=Policy(resource_value="https://resource.test")
                )

        self.both(run)

    def test_well_known_preserves_exact_resource_path_and_query(self):
        async def run():
            for resource, metadata_url in (
                (RESOURCE + "/", PR_PATH + "/"),
                (RESOURCE + "?tenant=one", PR_PATH + "?tenant=one"),
                ("https://resource.test/", PR_ROOT),
            ):
                docs = documents()
                document = docs.pop(PR_PATH)
                document["resource"] = resource
                docs[metadata_url] = document
                result, network = await self.run_discovery(
                    docs,
                    destination=resource,
                    policy=Policy(resource_value=resource),
                )
                self.assertEqual(result.resource, resource)
                self.assertEqual(network.sent[0], metadata_url)
                document["resource"] = resource + "/"
                with self.assertRaises(AuthenticationFailure):
                    await self.run_discovery(
                        docs,
                        destination=resource,
                        policy=Policy(resource_value=resource + "/"),
                    )

        self.both(run)

    def test_endpoint_queries_reject_oauth_parameter_collisions(self):
        async def run():
            for authorization, names in (
                (
                    True,
                    (
                        "client_id",
                        "redirect_uri",
                        "scope",
                        "resource",
                        "response_type",
                        "state",
                        "code_challenge",
                        "code_challenge_method",
                        "response_mode",
                        "nonce",
                    ),
                ),
                (
                    False,
                    (
                        "client_id",
                        "redirect_uri",
                        "scope",
                        "resource",
                        "grant_type",
                        "client_secret",
                        "refresh_token",
                        "code",
                        "code_verifier",
                    ),
                ),
            ):
                key = "authorization_endpoint" if authorization else "token_endpoint"
                policy = Policy(
                    flow="authorization_code_pkce",
                    redirect_uri="https://host.test/callback",
                )
                for name in names + ("%63lient_id",):
                    docs = documents()
                    docs[AS_PATH].update(
                        {
                            "authorization_endpoint": "https://issuer.test/authorize",
                            "code_challenge_methods_supported": ["S256"],
                            "response_types_supported": ["code"],
                            "grant_types_supported": ["authorization_code"],
                        }
                    )
                    docs[AS_PATH][key] = "https://issuer.test/endpoint?" + name + "="
                    with self.subTest(endpoint=key, parameter=name):
                        with self.assertRaises(AuthenticationFailure):
                            await self.run_discovery(docs, policy=policy)
                docs[AS_PATH][key] = "https://issuer.test/endpoint?tenant=one&empty="
                result, _ = await self.run_discovery(docs, policy=policy)
                self.assertEqual(
                    result.authorization_endpoint
                    if authorization
                    else result.token_endpoint,
                    docs[AS_PATH][key],
                )

        self.both(run)

    def test_challenge_parsing_and_local_scopes(self):
        async def run():
            docs = documents()
            url = "https://metadata.test/pr?x=a,b"
            docs[url] = docs.pop(PR_PATH)
            policy = Policy()
            result, network = await self.run_discovery(
                docs,
                auth=challenge(
                    f'Basic realm="a,b", Bearer realm="a\\"b", resource_metadata="{url}", scope="read"'
                ),
                policy=policy,
            )
            self.assertEqual(network.sent[0], url)
            self.assertEqual(result.configuration.scopes, ("read",))
            # A 401's scope only adds requested scopes; it is never required.
            self.assertEqual(policy.requirements, ())
            await self.run_discovery(auth=challenge('Bearer scope="admin"'))
            for header in (
                'Bearer scope="read", scope="read"',
                'Bearer resource_metadata="https://a.test", RESOURCE_METADATA="https://b.test"',
                'Bearer scope="read", Bearer scope="read"',
                'Bearer scope="unterminated',
            ):
                with self.assertRaises(AuthenticationFailure):
                    await self.run_discovery(auth=challenge(header))

        self.both(run)

    def test_challenge_parser_ignores_unknown_schemes_and_accepts_padded_token68(self):
        async def run():
            for header in (
                'Basic dXNlcjpwYXNz==, Bearer scope="read"',
                'Newauth abc==, Bearer scope="read", Digest realm="other"',
                "Bearer abc==",
                "Newauth abc==",
            ):
                with self.subTest(header=header):
                    policy = Policy()
                    result, network = await self.run_discovery(
                        auth=challenge(header), policy=policy
                    )
                    self.assertEqual(result.resource, RESOURCE)
                    # A 401's scope is a requested-scope hint, not required.
                    self.assertEqual(policy.requirements, ())
                    self.assertTrue(network.sent)

        self.both(run)

    def test_bearer_403_requires_insufficient_scope_and_scope_syntax_is_strict(self):
        async def run():
            for header in (
                'Bearer error="access_denied", scope="read"',
                'Basic realm="denied"',
                'Bearer scope="read"',
            ):
                auth = AuthChallenge(
                    403, {"WWW-Authenticate": header}, RESOURCE, None, True
                )
                with self.assertRaises(AuthenticationFailure) as failure:
                    await self.run_discovery(auth=auth)
                self.assertEqual(failure.exception.code, "access_denied")
            for scope in (
                "read  write",
                " read",
                "read ",
                "read\twrite",
                "read\\write",
                'read"write',
            ):
                # HTTP quoted-pair escaping does not make an invalid OAuth scope valid.
                escaped = scope.replace("\\", "\\\\").replace('"', '\\"')
                with self.subTest(scope=scope):
                    with self.assertRaises(AuthenticationFailure):
                        await self.run_discovery(
                            auth=challenge('Bearer scope="' + escaped + '"')
                        )
            policy = Policy(allowed_scopes=("read", "write"))
            result, _ = await self.run_discovery(
                auth=AuthChallenge(
                    403,
                    {
                        "WWW-Authenticate": 'Bearer error=insufficient_scope, scope="write"'
                    },
                    RESOURCE,
                    None,
                    True,
                ),
                policy=policy,
            )
            self.assertEqual(policy.requirements, ("write",))
            self.assertEqual(result.configuration.scopes, ("read",))
            self.assertEqual(result.configuration.allowed_scopes, ("read", "write"))

        self.both(run)

    def test_requested_allowed_and_explicit_required_scopes_are_distinct(self):
        async def run():
            policy = Policy(
                allowed_scopes=("read", "write"), required_scopes=("write",)
            )
            metadata, _ = await self.run_discovery(policy=policy)
            self.assertEqual(policy.requirements, ())
            self.assertEqual(metadata.configuration.scopes, ("read",))
            self.assertEqual(metadata.configuration.required_scopes, ("write",))
            metadata, _ = await self.run_discovery(
                policy=Policy(allowed_scopes=("read", "write")),
                auth=challenge('Bearer scope="write"'),
                binding=OAuthBinding(
                    ISSUER, RESOURCE, "local-client", "client_credentials", ("read",)
                ),
            )
            self.assertEqual(metadata.configuration.scopes, ("read",))
            # A 401 scope outside the ceiling is simply not requested.
            await self.run_discovery(auth=challenge('Bearer scope="write"'))
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.run_discovery(
                    auth=AuthChallenge(
                        403,
                        {
                            "WWW-Authenticate": 'Bearer error="insufficient_scope", scope="write"'
                        },
                        RESOURCE,
                        None,
                        True,
                    )
                )
            self.assertEqual(failure.exception.code, "access_denied")
            self.assertEqual(failure.exception.required_scopes, ("write",))

        self.both(run)

    def test_pkce_literal_loopback_redirects_and_remote_http_rejection(self):
        async def run():
            docs = documents()
            docs[AS_PATH].update(
                authorization_endpoint="https://browser.test/authorize",
                code_challenge_methods_supported=["S256"],
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                token_endpoint_auth_methods_supported=["none"],
            )
            for redirect in (
                "http://127.0.0.1:8123/callback",
                "http://[::1]:8123/callback",
                "https://host.test/callback",
            ):
                with self.subTest(redirect=redirect):
                    metadata, _ = await self.run_discovery(
                        docs,
                        policy=Policy(
                            flow="authorization_code_pkce",
                            redirect_uri=redirect,
                            token_endpoint_auth_method="none",
                            client_secret=None,
                        ),
                    )
                    self.assertEqual(metadata.configuration.redirect_uri, redirect)
                    self.assertIsNone(metadata.configuration.client_secret)
            for redirect in (
                "http://localhost:8123/callback",
                "http://remote.test/callback",
                "http://192.0.2.1/callback",
                "http://127.0.0.1:bad/callback",
                "https://host.test/callback#fragment",
            ):
                with self.subTest(redirect=redirect):
                    with self.assertRaises(AuthenticationFailure):
                        await self.run_discovery(
                            docs,
                            policy=Policy(
                                flow="authorization_code_pkce",
                                redirect_uri=redirect,
                                token_endpoint_auth_method="none",
                                client_secret=None,
                            ),
                        )

        self.both(run)

    def test_exact_resource_issuer_and_unadvertised_selection(self):
        async def run():
            for location, key, value in (
                (PR_PATH, "resource", RESOURCE + "/"),
                (AS_PATH, "issuer", ISSUER + "/"),
            ):
                docs = documents()
                docs[location][key] = value
                with self.assertRaises(AuthenticationFailure):
                    await self.run_discovery(docs)
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(policy=Policy(issuer="https://other.test"))

        self.both(run)

    def test_explicit_binding_stays_with_local_constraints(self):
        async def run():
            binding = OAuthBinding(
                ISSUER, RESOURCE, "local-client", "client_credentials", ("read",)
            )
            _, network = await self.run_discovery(binding=binding)
            self.assertEqual(network.sent, [AS_PATH])
            from dataclasses import replace

            for bad in (
                replace(binding, resource=RESOURCE + "/"),
                replace(binding, client_id="other"),
                replace(binding, scopes=("admin",)),
                replace(binding, flow="authorization_code_pkce"),
            ):
                with self.assertRaises(AuthenticationFailure):
                    await self.run_discovery(binding=bad)

        self.both(run)

    def test_all_destinations_need_local_authorization(self):
        async def run():
            for denied in (
                ("resource.test",),
                ("issuer.test/.well-known",),
                ("/token",),
            ):
                with self.assertRaises(AuthenticationFailure) as caught:
                    await self.run_discovery(denied=denied)
                self.assertEqual(caught.exception.code, "untrusted_destination")
            for url in (
                "http://issuer.test/token",
                "https://user:secret@issuer.test/token",
                "https://issuer.test/token#fragment",
                "https://issuer.test/\\evil",
            ):
                docs = documents()
                docs[AS_PATH]["token_endpoint"] = url
                with self.assertRaises(AuthenticationFailure):
                    await self.run_discovery(docs)
            docs = documents()
            docs[PR_PATH]["authorization_servers"] = [ISSUER + "?query=yes"]
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(docs)

        self.both(run)

    def test_pkce_endpoint_policy_and_capabilities(self):
        async def run():
            docs = documents()
            docs[AS_PATH].update(
                authorization_endpoint="https://browser.test/authorize",
                code_challenge_methods_supported=["S256"],
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                token_endpoint_auth_methods_supported=["none"],
            )
            policy = Policy(
                flow="authorization_code_pkce",
                redirect_uri="https://host.test/callback",
                token_endpoint_auth_method="none",
                client_secret=None,
            )
            result, network = await self.run_discovery(docs, policy=policy)
            self.assertEqual(
                result.authorization_endpoint, "https://browser.test/authorize"
            )
            self.assertIn(
                (result.authorization_endpoint, "authorization"), network.allowed
            )
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(docs, policy=policy, denied=("browser.test",))
            docs[AS_PATH]["code_challenge_methods_supported"] = ["plain"]
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(docs, policy=policy)

        self.both(run)

    def test_redirect_oversize_and_explicit_client_credentials_support(self):
        async def run():
            for response in (
                httpx.Response(302, headers={"location": "https://evil.test"}),
                httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)),
                httpx.Response(200, content=b'{"resource":1,"resource":2}'),
            ):
                docs = documents()
                docs[PR_PATH] = response
                with self.assertRaises(AuthenticationFailure):
                    await self.run_discovery(docs)
            docs = documents()
            del docs[AS_PATH]["grant_types_supported"]
            with self.assertRaises(AuthenticationFailure):
                await self.run_discovery(docs)

        self.both(run)

    def test_root_issuer_and_compressed_metadata(self):
        async def run():
            import gzip
            import json

            docs = documents()
            root = "https://issuer.test"
            docs[PR_PATH]["authorization_servers"] = [root]
            metadata = docs.pop(AS_PATH)
            metadata["issuer"] = root
            docs[root + "/.well-known/openid-configuration"] = httpx.Response(
                200,
                headers={"content-encoding": "gzip"},
                content=gzip.compress(json.dumps(metadata).encode()),
            )
            result, network = await self.run_discovery(docs, policy=Policy(issuer=root))
            self.assertEqual(result.configuration.issuer, root)
            self.assertEqual(
                network.sent[-2:],
                [
                    root + "/.well-known/oauth-authorization-server",
                    root + "/.well-known/openid-configuration",
                ],
            )

        self.both(run)

    def test_cancelled_stream_closes_response_without_closing_client(self):
        async def run():
            closed = []
            scope = anyio.CancelScope()

            class Stream(httpx.AsyncByteStream):
                async def __aiter__(self):
                    scope.cancel()
                    await anyio.sleep_forever()
                    yield b"unreachable"

                async def aclose(self):
                    await anyio.sleep(0)
                    closed.append(True)
                    raise RuntimeError("secret-cleanup-failure")

            def handle(request):
                if request.url.path == "/health":
                    return httpx.Response(200, text="ok")
                return httpx.Response(200, stream=Stream())

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handle)
            ) as client:
                network = HostNetwork(client)
                with scope:
                    try:
                        await safe_request(
                            network,
                            httpx.Request("GET", RESOURCE),
                            "metadata",
                            OperationBudget.after(2),
                        )
                    except anyio.get_cancelled_exc_class() as error:
                        self.assertIsNone(error.__context__)
                    else:
                        self.fail("native cancellation was lost")
                self.assertEqual(closed, [True])
                self.assertFalse(client.is_closed)
                self.assertEqual(
                    (await client.get("https://resource.test/health")).text, "ok"
                )

        self.both(run)

    def test_cleanup_errors_are_bounded_and_do_not_mask_operation_error(self):
        async def run():
            calls = []

            class Response(httpx.Response):
                async def aclose(self):
                    calls.append(True)
                    raise RuntimeError("secret-cleanup")

            class Network:
                async def authorize(self, url, purpose, budget):
                    pass

                async def send(self, request, purpose, budget):
                    return Response(302, headers={"location": "https://evil.test"})

            with self.assertRaises(AuthenticationFailure) as caught:
                await safe_request(
                    Network(),
                    httpx.Request("GET", RESOURCE),
                    "metadata",
                    OperationBudget.after(1),
                )
            self.assertEqual(caught.exception.code, "discovery_failed")
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(calls, [True])

            class SuccessfulNetwork(Network):
                async def send(self, request, purpose, budget):
                    return Response(200, content=b"{}")

            with self.assertRaises(AuthenticationFailure) as caught:
                await safe_request(
                    SuccessfulNetwork(),
                    httpx.Request("GET", RESOURCE),
                    "metadata",
                    OperationBudget.after(1),
                )
            self.assertIsNone(caught.exception.__context__)
            self.assertNotIn("secret", str(caught.exception))

            original = TimeoutError("secret original native timeout")

            class BrokenStream(httpx.AsyncByteStream):
                async def __aiter__(self):
                    raise original
                    yield b"unreachable"

                async def aclose(self):
                    raise RuntimeError("secret-cleanup")

            class BrokenNetwork(Network):
                async def send(self, request, purpose, budget):
                    return httpx.Response(200, stream=BrokenStream())

            with self.assertRaises(TimeoutError) as caught:
                await safe_request(
                    BrokenNetwork(),
                    httpx.Request("GET", RESOURCE),
                    "metadata",
                    OperationBudget.after(1),
                )
            self.assertIsNot(caught.exception, original)
            self.assertEqual(
                str(caught.exception), "Authentication operation timed out"
            )
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)

            class SlowResponse(httpx.Response):
                async def aclose(self):
                    await anyio.sleep_forever()

            class SlowNetwork(Network):
                async def send(self, request, purpose, budget):
                    return SlowResponse(302)

            started = anyio.current_time()
            with self.assertRaises(AuthenticationFailure):
                await safe_request(
                    SlowNetwork(),
                    httpx.Request("GET", RESOURCE),
                    "metadata",
                    OperationBudget.after(5),
                )
            self.assertLess(anyio.current_time() - started, 1.5)

        self.both(run)

    def test_native_cancellation_raised_by_close_is_preserved(self):
        async def run():
            cancellation = None
            with anyio.CancelScope() as scope:
                scope.cancel()
                try:
                    await anyio.sleep(0)
                except anyio.get_cancelled_exc_class() as caught:
                    cancellation = caught
            self.assertIsNotNone(cancellation)

            class Response(httpx.Response):
                async def aclose(self):
                    assert cancellation is not None
                    raise cancellation

            class Network:
                async def authorize(self, url, purpose, budget):
                    pass

                async def send(self, request, purpose, budget):
                    return Response(200, content=b"{}")

            try:
                await safe_request(
                    Network(),
                    httpx.Request("GET", RESOURCE),
                    "metadata",
                    OperationBudget.after(1),
                )
            except anyio.get_cancelled_exc_class() as caught:
                self.assertIs(caught, cancellation)
            else:
                self.fail("native cancellation from response close was swallowed")

        self.both(run)

    def test_direct_helpers_scrub_exception_context_and_translate_httpx_timeouts(self):
        async def run():
            class Network:
                error = RuntimeError("secret-diagnostic")

                async def authorize(self, url, purpose, budget):
                    raise self.error

            network = Network()
            for original, expected in (
                (RuntimeError("secret"), AuthenticationFailure),
                # A read timeout is an ambiguous network failure, not the
                # caller's deadline; a connect timeout provably sent nothing.
                (httpx.ReadTimeout("secret-url"), AuthenticationFailure),
                (httpx.ConnectTimeout("secret-url"), AuthenticationFailure),
                (TimeoutError("secret-token"), TimeoutError),
                (OperationCancelledError("secret-token"), OperationCancelledError),
            ):
                network.error = original
                with self.assertRaises(expected) as caught:
                    await safe_request(
                        network,
                        httpx.Request("GET", RESOURCE),
                        "metadata",
                        OperationBudget.after(1),
                    )
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
                self.assertNotIn("secret", str(caught.exception))

            class FailingPolicy(Policy):
                async def resource(self, target, budget):
                    raise RuntimeError("secret-resource")

            class EmptyStore:
                async def load_binding(self, key, budget):
                    return None

            # The provider is the single sanitising boundary for discovery.
            provider = ManagedOAuthProvider(
                network=network,
                policy=FailingPolicy(),
                store=EmptyStore(),
                namespace="test",
            )
            with self.assertRaises(AuthenticationFailure) as caught:
                await provider.prepare(target(), OperationBudget.after(1))
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)
            self.assertNotIn("secret", str(caught.exception))

        self.both(run)

    def test_timeout_cancellation_and_sanitized_host_failures(self):
        async def run():
            class FailingNetwork:
                async def authorize(self, url, purpose, budget):
                    raise RuntimeError("secret-diagnostic")

            with self.assertRaises(AuthenticationFailure) as caught:
                await safe_request(
                    FailingNetwork(),
                    httpx.Request("GET", RESOURCE),
                    "metadata",
                    OperationBudget.after(1),
                )
            self.assertNotIn("secret", str(caught.exception))

            class SlowNetwork:
                async def authorize(self, url, purpose, budget):
                    await anyio.sleep_forever()

            with self.assertRaises(TimeoutError):
                await safe_request(
                    SlowNetwork(),
                    httpx.Request("GET", RESOURCE),
                    "metadata",
                    OperationBudget.after(0.01),
                )
            with anyio.CancelScope() as scope:
                scope.cancel()
                try:
                    await safe_request(
                        SlowNetwork(),
                        httpx.Request("GET", RESOURCE),
                        "metadata",
                        OperationBudget.after(1),
                    )
                except anyio.get_cancelled_exc_class():
                    pass
                else:
                    self.fail("native cancellation swallowed")

        self.both(run)
