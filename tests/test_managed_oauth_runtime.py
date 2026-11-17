"""Real host-boundary lifecycle tests using vendored canonical vectors.

Source: agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json.
Run: uv run --locked --all-extras python -m unittest discover -s tests -p test_managed_oauth_runtime.py.
"""

import hashlib
import importlib.util
import json
import unittest
from base64 import urlsafe_b64encode
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx
from test_registration_auth import intercept_request

from agenthooksprotocol.auth import (
    AuthenticationFailure,
    AuthChallenge,
    AuthContext,
    AuthTarget,
    OAuthBinding,
    AuthenticatedHTTPTransport,
    RoutingAuthProvider,
)
from agenthooksprotocol.oauth import (
    ManagedOAuthProvider,
    OAuthClientConfiguration,
    OperationBudget,
    PendingLogin,
    Ready,
)

RESOURCE = "https://resource.test/api"
ISSUER = "https://issuer.test"
FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures/sdk-auth-lifecycle.json").read_text()
)


class Store:
    """CAS alone writes records; competing-writer fault injection also holds guard.

    Await before commit preserves old state on cancellation, await after commit
    exercises ambiguous persistence. Locks never reenter; every callback runs
    under its key lock. Cancellation releases locks but does not restore tokens.
    """

    def __init__(self):
        self.records = {}
        self.bindings = {}
        self.locks = {}
        self.transitions = []
        self.coordinated = []
        self.cas_hook = None

    async def load_binding(self, key, budget):
        budget.remaining()
        await anyio.lowlevel.checkpoint()
        return self.bindings.get(key)

    async def save_binding(self, key, metadata, budget):
        budget.remaining()
        await anyio.lowlevel.checkpoint()
        self.bindings[key] = metadata

    async def load(self, key, budget):
        budget.remaining()
        await anyio.lowlevel.checkpoint()
        return self.records.get(key)

    @asynccontextmanager
    async def coordinate(self, key, budget):
        budget.remaining()
        self.coordinated.append(key)
        async with self.locks.setdefault(key, anyio.Lock()):
            store = self

            class Guard:
                async def load(self):
                    await anyio.lowlevel.checkpoint()
                    return store.records.get(key)

                async def compare_and_swap(self, expected_generation, record):
                    await anyio.lowlevel.checkpoint()
                    old = store.records.get(key)
                    if (old.generation if old else None) != expected_generation:
                        return False
                    if (
                        store.cas_hook is not None
                        and await store.cas_hook(key, record) is False
                    ):
                        return False
                    if record is None:
                        store.records.pop(key, None)
                    else:
                        store.records[key] = record
                    store.transitions.append(record)
                    await anyio.lowlevel.checkpoint()
                    return True

            yield Guard()


class Policy:
    def __init__(self, flow="client_credentials"):
        self.configuration = OAuthClientConfiguration(
            issuer=ISSUER,
            client_id="host-client",
            flow=flow,
            scopes=("read",),
            redirect_uri="https://host.test/callback"
            if flow == "authorization_code_pkce"
            else None,
            client_secret="client-secret" if flow == "client_credentials" else None,
            token_endpoint_auth_method="client_secret_basic"
            if flow == "client_credentials"
            else "none",
        )
        self.budgets = []

    async def resource(self, target, budget):
        self.budgets.append(budget)
        await anyio.lowlevel.checkpoint()
        return RESOURCE

    async def select(self, target, resource, issuers, required_scopes, budget):
        self.budgets.append(budget)
        assert resource == RESOURCE and ISSUER in issuers
        allowed = self.configuration.allowed_scopes
        if not set(required_scopes).issubset(
            self.configuration.scopes if allowed is None else allowed
        ):
            raise AuthenticationFailure(code="access_denied")
        return self.configuration


def metadata(request):
    if request.url.host == "resource.test":
        return {
            "resource": RESOURCE,
            "authorization_servers": [ISSUER],
            "scopes_supported": ["irrelevant"],
        }
    return {
        "issuer": ISSUER,
        "token_endpoint": ISSUER + "/token",
        "authorization_endpoint": ISSUER + "/authorize",
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
        ],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
        ],
    }


class Network:
    def __init__(self):
        self.authorized = []
        self.requests = []
        self.budgets = []
        self.tokens = []
        self.token_hook = None
        self.client = httpx.AsyncClient(
            transport=httpx.MockTransport(self.handle), trust_env=False
        )

    async def authorize(self, url, purpose, budget):
        budget.remaining()
        self.budgets.append(budget)
        self.authorized.append((url, purpose))
        await anyio.lowlevel.checkpoint()

    async def send(self, request, purpose, budget):
        assert (str(request.url), purpose) in self.authorized
        self.budgets.append(budget)
        self.requests.append((request, purpose))
        return await self.client.send(request, follow_redirects=False)

    async def handle(self, request):
        if request.method == "GET":
            return httpx.Response(200, json=metadata(request))
        self.tokens.append(parse_qs(request.content.decode()))
        if self.token_hook is not None:
            return await self.token_hook(request)
        return httpx.Response(
            200,
            json={
                "access_token": f"access-{len(self.tokens)}",
                "token_type": "Bearer",
                "expires_in": 60,
                "refresh_token": f"refresh-{len(self.tokens)}",
                "scope": "read",
            },
        )


class VectorPolicy:
    def __init__(self, configuration, resource):
        self.configuration, self.resource_value = configuration, resource

    async def resource(self, target, budget):
        budget.remaining()
        return self.resource_value

    async def select(self, target, resource, issuers, required_scopes, budget):
        budget.remaining()
        assert resource == self.resource_value
        assert self.configuration.issuer in issuers
        return self.configuration


class VectorNetwork(Network):
    def __init__(self, configuration, responses=(), metadata_overrides=None):
        self.configuration = configuration
        self.responses = list(responses)
        self.metadata_overrides = metadata_overrides or {}
        super().__init__()

    async def handle(self, request):
        if request.method == "GET":
            issuer = self.configuration.issuer
            return httpx.Response(
                200,
                json={
                    "issuer": issuer,
                    "token_endpoint": issuer + "/token",
                    "authorization_endpoint": issuer + "/authorize",
                    "grant_types_supported": [
                        "authorization_code",
                        "refresh_token",
                        "client_credentials",
                    ],
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": [
                        "none",
                        "client_secret_basic",
                    ],
                    **self.metadata_overrides,
                },
            )
        self.tokens.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json=self.responses.pop(0))


class ManagedOAuthRuntimeTests(unittest.TestCase):
    def run_async(self, test):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):

                async def run():
                    n, s, policy = Network(), Store(), Policy()
                    now = [1000.0]
                    p = ManagedOAuthProvider(
                        network=n,
                        store=s,
                        policy=policy,
                        namespace="tenant",
                        clock=lambda: now[0],
                        expiry_skew=0,
                        # Keeps tests with never-answering token endpoints fast.
                        commit_timeout=0.5,
                    )
                    target = AuthTarget("tenant", "backend", RESOURCE, "event", None)
                    try:
                        await test(p, n, s, policy, target, now)
                    finally:
                        await n.client.aclose()

                anyio.run(run, backend=backend)

    def test_protocol_primitives_keep_host_httpx_types(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            for request, purpose in n.requests:
                self.assertIsInstance(request, httpx.Request)
                if purpose == "token":
                    self.assertIn("timeout", request.extensions)
                    self.assertEqual(
                        parse_qs(request.content.decode())["resource"], [RESOURCE]
                    )
                    self.assertIn("authorization", request.headers)
            self.assertFalse(n.client.is_closed)

        self.run_async(run)

    def test_pkce_complete_wrong_state_verifier_and_replay(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            budget = OperationBudget.after(5)
            login = await p.prepare(target, budget)
            self.assertIsInstance(login, PendingLogin)
            query = parse_qs(urlsplit(login.authorization_url).query)
            self.assertEqual(query["resource"], [RESOURCE])
            self.assertEqual(query["code_challenge_method"], ["S256"])
            self.assertEqual(query["scope"], ["read"])
            self.assertEqual(await p.prepare(target, budget), login)
            callback = "https://host.test/callback?" + urlencode(
                {"state": query["state"][0], "code": "one-use-code"}
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.complete(
                    target, login, callback.replace(query["state"][0], "wrong"), budget
                )
            self.assertEqual(failure.exception.code, "access_denied")
            self.assertFalse(n.tokens)
            self.assertIsInstance(
                await p.complete(target, login, callback, budget), Ready
            )
            form = n.tokens[0]
            challenge = (
                urlsafe_b64encode(
                    hashlib.sha256(form["code_verifier"][0].encode()).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            self.assertEqual(query["code_challenge"], [challenge])
            self.assertEqual(form["resource"], [RESOURCE])
            self.assertEqual(form["grant_type"], ["authorization_code"])
            with self.assertRaises(AuthenticationFailure):
                await p.complete(target, login, callback, budget)
            self.assertEqual(len(n.tokens), 1)
            self.assertTrue(
                all(b.deadline <= budget.deadline for b in n.budgets + policy.budgets)
            )
            self.assertFalse(n.client.is_closed)

        self.run_async(run)

    def test_client_credentials_expiry_refresh_and_reset(self):
        async def run(p, n, s, policy, target, now):
            first = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(
                (await p.prepare(target, OperationBudget.after(5))).credential,
                first.credential,
            )
            now[0] += 61
            second = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(first.credential.token, second.credential.token)
            self.assertEqual(n.tokens[0]["grant_type"], ["client_credentials"])
            token_request = next(
                request for request, purpose in n.requests if purpose == "token"
            )
            self.assertTrue(token_request.headers["authorization"].startswith("Basic "))
            self.assertNotIn("client_secret", n.tokens[0])
            self.assertEqual(n.tokens[1]["grant_type"], ["refresh_token"])
            self.assertEqual(n.tokens[1]["refresh_token"], ["refresh-1"])
            self.assertTrue(all(form["resource"] == [RESOURCE] for form in n.tokens))
            await p.reset(target, OperationBudget.after(5))
            self.assertFalse(s.records)
            await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])

        self.run_async(run)

    def test_singleflight_across_provider_instances(self):
        async def run(p, n, s, policy, target, now):
            other = ManagedOAuthProvider(
                network=n,
                policy=policy,
                store=s,
                namespace="tenant",
                clock=lambda: now[0],
                expiry_skew=0,
            )
            results = []

            async def prepare(provider):
                results.append(await provider.prepare(target, OperationBudget.after(5)))

            async with anyio.create_task_group() as tasks:
                for index in range(12):
                    tasks.start_soon(prepare, p if index % 2 else other)
            self.assertEqual(len(n.tokens), 1)
            self.assertEqual(len({result.credential.token for result in results}), 1)
            self.assertEqual(
                [record.status for record in s.transitions], ["refreshing", "active"]
            )

        self.run_async(run)

    def test_cc_transient_retains_refresh_and_invalid_grant_never_logs_in(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            old = next(iter(s.records.values())).token
            now[0] += 61

            async def transient(request):
                return httpx.Response(503, json={"error": "temporarily_unavailable"})

            n.token_hook = transient
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.recovery, "retry")
            self.assertEqual(next(iter(s.records.values())).token, old)

            async def rejection(request):
                return httpx.Response(400, json={"error": "invalid_grant"})

            n.token_hook = rejection
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(failure.exception.recovery, "login")
            self.assertNotEqual(failure.exception.code, "interaction_required")
            self.assertFalse(any(record.pending for record in s.records.values()))
            n.token_hook = None
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])

        self.run_async(run)

    def test_cancel_network_preserves_refresh_and_allows_explicit_retry(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            old = next(iter(s.records.values())).token
            now[0] += 61
            entered = anyio.Event()

            async def blocked(request):
                entered.set()
                await anyio.sleep_forever()

            n.token_hook = blocked

            async def refresh():
                await p.prepare(target, OperationBudget.after(5))

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(refresh)
                await entered.wait()
                tasks.cancel_scope.cancel()
            self.assertEqual(next(iter(s.records.values())).token, old)
            self.assertFalse(n.client.is_closed)
            n.token_hook = None
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            self.assertEqual(n.tokens[-1]["refresh_token"], [old.refresh_token])

        self.run_async(run)

    def test_cas_failure_never_overwrites_competing_generation(self):
        async def run(p, n, s, policy, target, now):
            async def competing(key, record):
                if record is not None and record.status == "active":
                    s.records[key] = replace(
                        s.records[key], generation="competing-owner"
                    )
                    return False
                return True

            s.cas_hook = competing
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(target, OperationBudget.after(5))
            record = next(iter(s.records.values()))
            self.assertEqual(record.generation, "competing-owner")
            self.assertEqual(record.status, "refreshing")
            self.assertIsNone(record.token)
            self.assertEqual(len(n.tokens), 1)

        self.run_async(run)

    def test_cancel_store_before_reservation_does_not_send_or_mutate(self):
        async def run(p, n, s, policy, target, now):
            entered = anyio.Event()

            async def blocked(key, record):
                entered.set()
                await anyio.sleep_forever()

            s.cas_hook = blocked

            async def prepare():
                await p.prepare(target, OperationBudget.after(5))

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(prepare)
                await entered.wait()
                tasks.cancel_scope.cancel()
            self.assertFalse(s.records)
            self.assertFalse(n.tokens)
            s.cas_hook = None
            await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(next(iter(s.records.values())).status, "active")

        self.run_async(run)

    def test_namespace_destination_and_upload_isolation(self):
        async def run(p, n, s, policy, target, now):
            # Explicit local audience configuration can cover several delivery
            # destinations; automatic discovery must instead bind each document
            # to its own requested resource under RFC 9728 section 3.3.
            config = policy.configuration
            target = replace(
                target,
                typed_binding=OAuthBinding(
                    ISSUER,
                    RESOURCE,
                    config.client_id,
                    config.flow,
                    config.scopes,
                ),
            )
            for item in [
                target,
                replace(target, destination="https://resource.test/other"),
                replace(target, purpose="upload"),
            ]:
                await p.prepare(item, OperationBudget.after(5))
            other = ManagedOAuthProvider(
                network=n,
                store=s,
                policy=policy,
                namespace="other",
                clock=lambda: now[0],
            )
            await other.prepare(
                replace(target, namespace="other"), OperationBudget.after(5)
            )
            self.assertEqual(len(n.tokens), 4)
            self.assertEqual(len(s.records), 4)
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(
                    replace(target, namespace="other"), OperationBudget.after(5)
                )
            self.assertFalse(n.client.is_closed)

        self.run_async(run)

    def test_deadline_during_network_does_not_restore_refresh_token(self):
        async def run(p, n, s, policy, target, now):
            original_resource = policy.resource
            entered = anyio.Event()

            async def blocked_policy(target, budget):
                entered.set()
                await anyio.sleep_forever()

            policy.resource = blocked_policy
            with self.assertRaises(TimeoutError):
                await p.prepare(target, OperationBudget.after(0.02))
            self.assertTrue(entered.is_set())
            self.assertFalse(s.records)
            self.assertFalse(n.requests)
            policy.resource = original_resource
            await p.prepare(target, OperationBudget.after(5))
            now[0] += 61

            async def blocked(request):
                await anyio.sleep_forever()

            n.token_hook = blocked
            old = next(iter(s.records.values())).token
            with self.assertRaises(TimeoutError):
                await p.prepare(target, OperationBudget.after(0.05))
            record = next(iter(s.records.values()))
            self.assertEqual((record.status, record.token), ("active", old))
            self.assertFalse(n.client.is_closed)

        self.run_async(run)

    def test_expired_pending_login_cannot_exchange(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            login = await p.prepare(target, OperationBudget.after(5))
            state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
            now[0] = login.expires_at + 1
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.complete(
                    target,
                    login,
                    "https://host.test/callback?"
                    + urlencode({"state": state, "code": "old"}),
                    OperationBudget.after(5),
                )
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertFalse(n.tokens)
            self.assertNotEqual(
                (await p.prepare(target, OperationBudget.after(5))).generation,
                login.generation,
            )

        self.run_async(run)

    def test_auth_provider_stale_401_reuses_new_generation(self):
        async def run(p, n, s, policy, target, now):
            binding = {
                "type": "oauth",
                "flow": "client_credentials",
                "issuer": ISSUER,
                "resource": RESOURCE,
                "clientId": "host-client",
                "scopes": ["read"],
            }
            with anyio.CancelScope() as cancellation:
                context = AuthContext(
                    {"id": "backend"}, binding, RESOURCE, "event", cancellation
                )
                first = await p.credential(context)
                challenge = AuthChallenge(401, {}, RESOURCE, first.identity, True)
                second = await p.challenge(context, challenge)
                self.assertNotEqual(first.token, second.token)
                stale = await p.challenge(context, challenge)
                self.assertEqual(stale.token, second.token)
                self.assertEqual(len(n.tokens), 2)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(context, replace(challenge, status=403))
                self.assertEqual(failure.exception.code, "access_denied")
                self.assertIsNone(
                    await p.challenge(context, replace(challenge, retry_allowed=False))
                )
                cached = await p.credential(replace(context, binding=None))
                self.assertEqual(cached.token, second.token)
                with self.assertRaises(AuthenticationFailure):
                    await p.challenge(replace(context, purpose="upload"), challenge)

        self.run_async(run)

    def test_reservation_cas_failure_prevents_network_exchange(self):
        async def run(p, n, s, policy, target, now):
            async def reject(key, record):
                return False

            s.cas_hook = reject
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(target, OperationBudget.after(5))
            self.assertFalse(n.tokens)
            self.assertFalse(s.records)

        self.run_async(run)

    def test_cancel_after_store_reservation_commit_allows_retry(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            entered = anyio.Event()

            async def commit_then_block(key, record):
                s.records[key] = record
                if not entered.is_set():
                    entered.set()
                    await anyio.sleep_forever()
                return False

            s.cas_hook = commit_then_block

            async def prepare():
                await p.prepare(target, OperationBudget.after(5))

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(prepare)
                await entered.wait()
                tasks.cancel_scope.cancel()
            self.assertEqual(next(iter(s.records.values())).status, "refreshing")
            self.assertEqual(len(n.tokens), 1)
            s.cas_hook = None
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            self.assertEqual(len(n.tokens), 2)

        self.run_async(run)

    @unittest.skipUnless(
        importlib.util.find_spec("trustme"),
        "ephemeral TLS test requires --with trustme",
    )
    def test_pkce_full_flow_over_verified_local_tls(self):
        import ssl
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import trustme

        ca = trustme.CA()
        certificate = ca.issue_cert("localhost")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certificate.configure_cert(server_context)
        client_context = ssl.create_default_context()
        ca.configure_trust(client_context)
        forms, deliveries = [], []
        blocked, release = threading.Event(), threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, document=None, status=200, headers=None):
                body = json.dumps(document).encode() if document is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass  # A cancelled borrowed-client request closed this socket.

            def do_GET(self):
                host = (
                    "resource.test"
                    if "oauth-protected-resource" in self.path
                    else "issuer.test"
                )
                self.reply(
                    metadata(httpx.Request("GET", "https://" + host + self.path))
                )

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/token":
                    forms.append(parse_qs(body.decode()))
                    self.reply({"access_token": "tls-access", "token_type": "Bearer"})
                    return
                message = json.loads(body)
                deliveries.append(
                    (message.get("id"), self.headers.get("Authorization"))
                )
                if self.headers.get("Authorization") != "Bearer tls-access":
                    self.reply(status=401, headers={"WWW-Authenticate": "Bearer"})
                elif message.get("id") == "cancel":
                    blocked.set()
                    release.wait(timeout=5)
                    self.reply(
                        {
                            "jsonrpc": "2.0",
                            "id": "cancel",
                            "result": {"protocolVersion": "draft", "effects": []},
                        }
                    )
                elif message["method"] == "hooks/observe":
                    self.reply(status=204)
                else:
                    self.reply(
                        {
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "result": {"protocolVersion": "draft", "effects": []},
                        }
                    )

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        class LocalTLS(httpx.AsyncBaseTransport):
            def __init__(self):
                self.inner = httpx.AsyncHTTPTransport(verify=client_context)

            async def handle_async_request(self, request):
                mapped = httpx.Request(
                    request.method,
                    request.url.copy_with(host="localhost", port=server.server_port),
                    headers=request.headers,
                    stream=request.stream,
                    extensions=request.extensions,
                )
                return await self.inner.handle_async_request(mapped)

            async def aclose(self):
                await self.inner.aclose()

        async def run():
            blocked.clear()
            release.clear()
            network, store = Network(), Store()
            await network.client.aclose()
            network.client = httpx.AsyncClient(transport=LocalTLS(), trust_env=False)
            managed = ManagedOAuthProvider(
                network=network,
                policy=Policy("authorization_code_pkce"),
                store=store,
                namespace="tls",
            )
            target = AuthTarget("tls", "backend", RESOURCE, "event", None)
            router = RoutingAuthProvider(
                discover=managed, oauth=managed, namespace="tls"
            )
            transport = AuthenticatedHTTPTransport(
                RESOURCE,
                backend={"id": "backend"},
                auth_provider=router,
                client=network.client,
            )
            try:
                with self.assertRaises(AuthenticationFailure) as failure:
                    await transport.request(intercept_request())
                self.assertEqual(failure.exception.code, "interaction_required")
                self.assertFalse(store.records)
                login = await managed.prepare(target, OperationBudget.after(10))
                ready = await self.complete_login(managed, target, login)
                self.assertEqual(ready.credential.token, "tls-access")
                self.assertEqual(forms[-1]["resource"], [RESOURCE])
                self.assertEqual(forms[-1]["grant_type"], ["authorization_code"])
                self.assertIn("code_verifier", forms[-1])
                await transport.request(intercept_request())
                await transport.notify(
                    {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                )
                self.assertEqual(deliveries[-1][1], "Bearer tls-access")
                cancelled = []

                async def request():
                    message = intercept_request()
                    message["id"] = "cancel"
                    try:
                        await transport.request(message)
                    except anyio.get_cancelled_exc_class():
                        cancelled.append(True)
                        raise

                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(request)
                    self.assertTrue(
                        await anyio.to_thread.run_sync(lambda: blocked.wait(timeout=3))
                    )
                    tasks.cancel_scope.cancel()
                self.assertEqual(cancelled, [True])
                release.set()
                await transport.aclose()
                self.assertFalse(network.client.is_closed)
                # Cancellation does not invalidate an established grant.
                await transport.request(intercept_request())
            finally:
                release.set()
                await network.client.aclose()

        try:
            for backend in ("asyncio", "trio"):
                with self.subTest(backend=backend):
                    anyio.run(run, backend=backend)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_cancel_during_final_store_commit_keeps_rotated_token(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            with anyio.CancelScope() as cancellation:

                async def cancel_commit(key, record):
                    if record.status == "active":
                        cancellation.cancel()
                        await anyio.lowlevel.checkpoint()
                    return True

                s.cas_hook = cancel_commit
                await p.prepare(target, OperationBudget.after(5))
                self.fail("cancellation must be observed after the shielded commit")
            s.cas_hook = None
            record = next(iter(s.records.values()))
            self.assertEqual(record.status, "active")
            self.assertEqual(record.token.refresh_token, "refresh-2")
            ready = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(ready.credential.token, "access-2")
            self.assertEqual(len(n.tokens), 2)

        self.run_async(run)

    def test_challenge_rebinds_changed_client_without_reusing_old_principal(self):
        async def run(p, n, s, policy, target, now):
            first = await p.prepare(target, OperationBudget.after(5))
            with anyio.CancelScope() as cancellation:
                context = AuthContext(
                    {"id": "backend"}, None, RESOURCE, "event", cancellation
                )
                challenge = AuthChallenge(
                    401, {}, RESOURCE, first.credential.identity, True
                )
                policy.configuration = replace(
                    policy.configuration, client_id="replacement"
                )
                credential = await p.challenge(context, challenge)
                self.assertNotEqual(credential.token, first.credential.token)
                self.assertEqual(len(s.records), 2)
                self.assertEqual(len(n.tokens), 2)
                self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])

        self.run_async(run)

    def test_complete_rechecks_policy_resource_client_and_scopes(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            original = policy.configuration
            login = await p.prepare(target, OperationBudget.after(5))
            state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
            callback = "https://host.test/callback?" + urlencode(
                {"state": state, "code": "valid"}
            )
            calls = []

            async def select(target, resource, issuers, required_scopes, budget):
                calls.append((resource, issuers, required_scopes))
                return policy.configuration

            policy.select = select
            for change in ({"client_id": "revoked-client"},):
                policy.configuration = replace(original, **change)
                with self.assertRaises(AuthenticationFailure):
                    await p.complete(target, login, callback, OperationBudget.after(5))
                self.assertFalse(n.tokens)
                self.assertEqual(next(iter(s.records.values())).status, "pending")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[-1], (RESOURCE, (ISSUER,), ()))
            policy.configuration = original
            original_resource = policy.resource

            async def revoked_resource(target, budget):
                return RESOURCE + "/revoked"

            policy.resource = revoked_resource
            with self.assertRaises(AuthenticationFailure):
                await p.complete(target, login, callback, OperationBudget.after(5))
            self.assertFalse(n.tokens)
            policy.resource = original_resource
            self.assertIsInstance(
                await p.complete(target, login, callback, OperationBudget.after(5)),
                Ready,
            )

        self.run_async(run)

    def test_callback_must_preserve_fixed_redirect_query(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                redirect_uri="https://host.test/callback?tenant=one&blank=",
            )
            login = await p.prepare(target, OperationBudget.after(5))
            state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
            auth_query = urlencode({"state": state, "code": "valid"})
            for query in (
                auth_query,
                "tenant=two&blank=&" + auth_query,
                "tenant=one&tenant=two&blank=&" + auth_query,
                "tenant=one&" + auth_query,
            ):
                with self.subTest(query=query):
                    with self.assertRaises(AuthenticationFailure):
                        await p.complete(
                            target,
                            login,
                            "https://host.test/callback?" + query,
                            OperationBudget.after(5),
                        )
                    self.assertFalse(n.tokens)
            ready = await p.complete(
                target,
                login,
                "https://host.test/callback?tenant=one&blank=&" + auth_query,
                OperationBudget.after(5),
            )
            self.assertIsInstance(ready, Ready)
            self.assertEqual(
                n.tokens[0]["redirect_uri"], [policy.configuration.redirect_uri]
            )

        self.run_async(run)

    def test_uncertain_refresh_preserves_material_and_retry_can_recover(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            old_token = next(iter(s.records.values())).token
            now[0] += 61

            async def uncertain(request):
                raise httpx.ReadError(
                    "response lost after possible rotation", request=request
                )

            n.token_hook = uncertain
            for _ in range(2):
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.prepare(target, OperationBudget.after(5))
                self.assertEqual(failure.exception.recovery, "retry")
                self.assertEqual(next(iter(s.records.values())).token, old_token)
            self.assertEqual(len(n.tokens), 3)
            n.token_hook = None
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            self.assertEqual(n.tokens[-1]["refresh_token"], [old_token.refresh_token])

        self.run_async(run)

    async def complete_login(self, provider, target, login):
        state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
        return await provider.complete(
            target,
            login,
            "https://host.test/callback?"
            + urlencode({"state": state, "code": "valid"}),
            OperationBudget.after(5),
        )

    def test_unknown_expiry_narrowed_scopes_initial_and_refresh(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                policy.configuration, scopes=("read", "write")
            )

            async def token(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"unknown-{len(n.tokens)}",
                        "token_type": "Bearer",
                        "refresh_token": f"rotated-{len(n.tokens)}",
                        "scope": "read",
                    },
                )

            n.token_hook = token
            first = await p.prepare(target, OperationBudget.after(5))
            record = next(iter(s.records.values()))
            self.assertIsNone(record.token.expires_at)
            self.assertEqual(record.token.scopes, ("read",))
            now[0] += 100000
            self.assertEqual(
                (await p.prepare(target, OperationBudget.after(5))).credential,
                first.credential,
            )
            self.assertEqual(len(n.tokens), 1)
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                second = await p.challenge(
                    context,
                    AuthChallenge(401, {}, RESOURCE, first.credential.identity, True),
                )
            self.assertEqual(second.token, "unknown-2")
            token = next(iter(s.records.values())).token
            self.assertIsNone(token.expires_at)
            self.assertEqual(token.refresh_token, "rotated-2")
            self.assertEqual(token.scopes, ("read",))
            self.assertEqual(n.tokens[-1]["refresh_token"], ["rotated-1"])
            self.assertNotIn("scope", n.tokens[-1])

        self.run_async(run)

    def test_pkce_refresh_rotation_persists_before_required_scope_failure(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                scopes=("read", "write"),
                required_scopes=("write",),
            )

            async def token(request):
                initial = n.tokens[-1]["grant_type"] == ["authorization_code"]
                return httpx.Response(
                    200,
                    json={
                        "access_token": "initial" if initial else "narrowed",
                        "token_type": "Bearer",
                        "refresh_token": "r1" if initial else "r2",
                        "scope": "read write" if initial else "read",
                        **({"expires_in": 60} if initial else {}),
                    },
                )

            n.token_hook = token
            await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            now[0] += 61
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.code, "access_denied")
            self.assertEqual(failure.exception.required_scopes, ("write",))
            record = next(iter(s.records.values()))
            self.assertEqual(record.token.refresh_token, "r2")
            self.assertEqual(record.token.scopes, ("read",))
            self.assertIsNone(record.token.expires_at)
            self.assertNotIn("scope", n.tokens[-1])

        self.run_async(run)

    def test_pkce_completion_narrowed_required_response_persists_refresh(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                scopes=("read", "write"),
                required_scopes=("write",),
            )

            async def token(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "narrow",
                        "token_type": "Bearer",
                        "refresh_token": "retain-rotation",
                        "scope": "read",
                    },
                )

            n.token_hook = token
            login = await p.prepare(target, OperationBudget.after(5))
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            self.assertEqual(failure.exception.code, "access_denied")
            token = next(iter(s.records.values())).token
            self.assertEqual(token.refresh_token, "retain-rotation")
            self.assertIsNone(token.expires_at)
            self.assertEqual(token.scopes, ("read",))

        self.run_async(run)

    def test_fresh_provider_uses_persistent_binding_offline_and_sends_upfront(self):
        async def run(p, n, s, policy, target, now):
            first = await p.prepare(target, OperationBudget.after(5))
            upload_target = replace(
                target,
                purpose="upload",
                destination=RESOURCE + "/upload",
                typed_binding=OAuthBinding(
                    ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)
                ),
            )
            upload_ready = await p.prepare(upload_target, OperationBudget.after(5))
            self.assertNotEqual(upload_ready.credential.token, first.credential.token)
            self.assertTrue(s.bindings)
            self.assertFalse(set(s.records) & set(s.bindings))
            request_count = len(n.requests)

            async def offline(url, purpose, budget):
                self.fail("cached valid credentials must not rediscover")

            n.authorize = offline
            fresh = ManagedOAuthProvider(
                network=n,
                policy=policy,
                store=s,
                namespace="tenant",
                clock=lambda: now[0],
            )
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                credential = await fresh.credential(context)
            self.assertEqual(credential.token, first.credential.token)
            sent = []

            async def deliver(request):
                sent.append(request.headers.get("authorization"))
                if request.url.path.endswith("/upload"):
                    body = await request.aread()
                    return httpx.Response(
                        201,
                        json={
                            "ref": "urn:uploaded:cached",
                            "size": len(body),
                            "sha256": hashlib.sha256(body).hexdigest(),
                        },
                    )
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(deliver)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE,
                    backend={"id": "backend"},
                    client=client,
                    auth_provider=RoutingAuthProvider(
                        discover=fresh, namespace="tenant"
                    ),
                )
                await transport.notify(
                    {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                )
                receipt = await transport.upload(RESOURCE + "/upload", b"cached-upload")
                self.assertEqual(receipt.ref, "urn:uploaded:cached")
                await transport.aclose()
                self.assertFalse(client.is_closed)
            self.assertEqual(
                sent,
                [
                    "Bearer " + first.credential.token,
                    "Bearer " + upload_ready.credential.token,
                ],
            )
            self.assertEqual(len(n.requests), request_count)

        self.run_async(run)

    def test_dispatch_does_not_create_pending_and_host_prepare_cancel_is_separate(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                self.assertIsNone(await p.credential(context))
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(
                        context, AuthChallenge(401, {}, RESOURCE, None, True)
                    )
                self.assertEqual(failure.exception.code, "interaction_required")
            self.assertFalse(s.records)
            login = await p.prepare(target, OperationBudget.after(5))
            self.assertIsInstance(login, PendingLogin)
            # A known binding needing consent fails; it is never sent anonymously.
            with anyio.CancelScope() as scope:
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.credential(
                        AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                    )
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertEqual(
                next(iter(s.records.values())).pending.state, login.generation
            )
            await p.cancel(target, login, OperationBudget.after(5))
            self.assertFalse(s.records)
            self.assertTrue(s.bindings)
            replacement = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(replacement.generation, login.generation)

        self.run_async(run)

    def test_secret_rotation_is_runtime_only_for_refresh_and_confidential_pkce_completion(
        self,
    ):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            policy.configuration = replace(
                policy.configuration, client_secret="replacement-secret"
            )
            now[0] += 61
            await p.prepare(target, OperationBudget.after(5))
            request = [r for r, purpose in n.requests if purpose == "token"][-1]
            from base64 import b64decode

            self.assertEqual(
                b64decode(request.headers["authorization"].split()[1]),
                b"host-client:replacement-secret",
            )
            for metadata in list(s.bindings.values()) + [
                r.metadata for r in s.records.values()
            ]:
                self.assertIsNone(metadata.configuration.client_secret)
            await p.reset(target, OperationBudget.after(5))
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                client_secret="pkce-old",
                token_endpoint_auth_method="client_secret_basic",
            )
            login = await p.prepare(target, OperationBudget.after(5))
            policy.configuration = replace(
                policy.configuration, client_secret="pkce-current"
            )
            await self.complete_login(p, target, login)
            request = [r for r, purpose in n.requests if purpose == "token"][-1]
            self.assertEqual(
                b64decode(request.headers["authorization"].split()[1]),
                b"host-client:pkce-current",
            )
            for metadata in list(s.bindings.values()) + [
                r.metadata for r in s.records.values()
            ]:
                self.assertIsNone(metadata.configuration.client_secret)
            self.assertNotIn("pkce-current", repr(s.records))

        self.run_async(run)

    def test_cc_403_allowed_stepup_reissues_and_forbidden_scope_is_denied(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            first = await p.prepare(target, OperationBudget.after(5))

            async def token(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "stepup",
                        "token_type": "Bearer",
                        "scope": "read write",
                    },
                )

            n.token_hook = token
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                challenge = AuthChallenge(
                    403,
                    {
                        "www-authenticate": 'Bearer error="insufficient_scope", scope="write"'
                    },
                    RESOURCE,
                    first.credential.identity,
                    True,
                )
                credential = await p.challenge(context, challenge)
                self.assertEqual(credential.token, "stepup")
                self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
                self.assertEqual(
                    set(n.tokens[-1]["scope"][0].split()), {"read", "write"}
                )
                count = len(n.tokens)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(
                        context,
                        AuthChallenge(
                            403,
                            {
                                "www-authenticate": 'Bearer error="insufficient_scope", scope="admin"'
                            },
                            RESOURCE,
                            credential.identity,
                            True,
                        ),
                    )
                self.assertEqual(failure.exception.code, "access_denied")
                self.assertEqual(len(n.tokens), count)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(
                        context,
                        AuthChallenge(403, {}, RESOURCE, credential.identity, True),
                    )
                self.assertEqual(failure.exception.code, "access_denied")

        self.run_async(run)

    def test_pkce_stepup_round_trip_shared_grant_and_operation_scoped_requirement(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write"),
                grant_partition="same-principal",
            )
            upload = replace(
                target,
                purpose="upload",
                destination=RESOURCE + "/upload",
                typed_binding=OAuthBinding(
                    ISSUER,
                    RESOURCE,
                    "host-client",
                    "authorization_code_pkce",
                    ("read",),
                ),
            )
            approved_upload = [False]
            original_resource = policy.resource

            async def resource(selected, budget):
                if selected.purpose == "upload" and not approved_upload[0]:
                    raise AuthenticationFailure(code="access_denied")
                return await original_resource(selected, budget)

            policy.resource = resource
            first = await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(upload, OperationBudget.after(5))
            self.assertEqual(len(n.tokens), 1)
            approved_upload[0] = True
            shared = await p.prepare(upload, OperationBudget.after(5))
            self.assertEqual(shared.credential.token, first.credential.token)
            self.assertEqual(len(s.records), 1)
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(
                        context,
                        AuthChallenge(
                            403,
                            {
                                "www-authenticate": 'Bearer error="insufficient_scope", scope="write"'
                            },
                            RESOURCE,
                            first.credential.identity,
                            True,
                        ),
                    )
                self.assertEqual(failure.exception.code, "interaction_required")
                self.assertEqual(failure.exception.required_scopes, ("write",))
            # Step-up round trip: the host passes the validated scopes back.
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            login = await p.prepare(
                target,
                OperationBudget.after(5),
                required_scopes=failure.exception.required_scopes,
            )
            self.assertIsInstance(login, PendingLogin)
            self.assertEqual(
                set(
                    parse_qs(urlsplit(login.authorization_url).query)["scope"][
                        0
                    ].split()
                ),
                {"read", "write"},
            )
            self.assertEqual(
                next(iter(s.records.values())).token.access_token,
                first.credential.token,
            )
            self.assertEqual(
                (await p.prepare(upload, OperationBudget.after(5))).credential.token,
                first.credential.token,
            )
            await p.cancel(target, login, OperationBudget.after(5))
            self.assertEqual(next(iter(s.records.values())).status, "active")
            self.assertEqual(
                (await p.prepare(upload, OperationBudget.after(5))).credential.token,
                first.credential.token,
            )
            # The step-up requirement was operation-scoped, never persisted.
            self.assertTrue(
                all(m.configuration.required_scopes == () for m in s.bindings.values())
            )
            with anyio.CancelScope() as scope:
                cached = await p.credential(
                    AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                )
            self.assertEqual(cached.token, first.credential.token)
            self.assertFalse(any(record.pending for record in s.records.values()))
            self.assertEqual(len(n.tokens), 1)

        self.run_async(run)

    def test_narrowed_refresh_omitted_scope_inherits_previous_grant(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                policy.configuration, scopes=("read", "write")
            )

            async def token(request):
                initial = n.tokens[-1]["grant_type"] == ["client_credentials"]
                return httpx.Response(
                    200,
                    json={
                        "access_token": "first" if initial else "refreshed",
                        "token_type": "Bearer",
                        "refresh_token": "r1" if initial else "r2",
                        **({"scope": "read", "expires_in": 60} if initial else {}),
                    },
                )

            n.token_hook = token
            await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            await p.prepare(target, OperationBudget.after(5))
            record = next(iter(s.records.values()))
            self.assertEqual(record.token.scopes, ("read",))
            self.assertIsNone(record.token.expires_at)
            self.assertEqual(record.token.refresh_token, "r2")
            self.assertNotIn("scope", n.tokens[-1])
            self.assertEqual(n.tokens[-1]["grant_type"], ["refresh_token"])

        self.run_async(run)

    def test_refresh_broadening_scope_is_ignored_and_stays_usable(self):
        """Canonical lifecycle: refresh-broadening-scope-ignored."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                scopes=("read", "write"),
                allowed_scopes=("read", "write"),
            )

            async def token(request):
                initial = len(n.tokens) == 1
                return httpx.Response(
                    200,
                    json={
                        "access_token": "initial-read" if initial else "refreshed",
                        "token_type": "Bearer",
                        "refresh_token": "r1" if initial else "r2",
                        "scope": "read" if initial else "read write",
                        "expires_in": 1 if initial else 60,
                    },
                )

            n.token_hook = token
            await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            now[0] += 2
            ready = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(ready.credential.token, "refreshed")
            self.assertNotIn("scope", n.tokens[-1])
            record = next(iter(s.records.values()))
            self.assertEqual(
                (record.status, record.token.scopes, record.token.refresh_token),
                ("active", ("read",), "r2"),
            )
            policy.configuration = replace(
                policy.configuration, required_scopes=("write",)
            )
            # A write-requiring operation cannot fabricate write from a refresh.
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.credential(self.unbound())
            self.assertEqual(failure.exception.code, "interaction_required")
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.challenge(
                    AuthContext(
                        {"id": "backend"}, None, RESOURCE, "event", anyio.CancelScope()
                    ),
                    AuthChallenge(401, {}, RESOURCE, ready.credential.identity, True),
                )
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertEqual(len(n.tokens), 2)

        self.run_async(run)

    def test_invalid_token_response_clears_in_flight_and_keeps_only_refresh_rotation(
        self,
    ):
        """Canonical lifecycle: token-validation-failure-clears-in-flight."""
        bad = (
            {"scope": "read  write"},
            {"scope": 7},
            {"token_type": "mac"},
            {"expires_in": 0},
            {"expires_in": 1.5},
            {"access_token": "not valid"},
        )
        for change in bad:
            with self.subTest(change=change):

                async def run(p, n, s, policy, target, now):
                    policy.configuration = Policy(
                        "authorization_code_pkce"
                    ).configuration
                    response = {
                        "access_token": "a",
                        "token_type": "Bearer",
                        "refresh_token": "rotated",
                        **change,
                    }

                    async def invalid(request):
                        return httpx.Response(200, json=response)

                    n.token_hook = invalid
                    login = await p.prepare(target, OperationBudget.after(5))
                    with self.assertRaises(AuthenticationFailure) as failure:
                        await self.complete_login(p, target, login)
                    self.assertEqual(
                        (failure.exception.code, failure.exception.recovery),
                        ("provider_failed", "retry"),
                    )
                    # An invalid initial exchange persists nothing and consumes the login.
                    self.assertFalse(s.records)
                    n.token_hook = None
                    await self.complete_login(
                        p, target, await p.prepare(target, OperationBudget.after(5))
                    )
                    now[0] += 61
                    n.token_hook = invalid
                    with self.assertRaises(AuthenticationFailure) as failure:
                        await p.prepare(target, OperationBudget.after(5))
                    self.assertEqual(failure.exception.code, "provider_failed")
                    record = next(iter(s.records.values()))
                    self.assertEqual(record.status, "active")
                    self.assertIsNone(record.token.access_token)
                    self.assertEqual(record.token.refresh_token, "rotated")
                    n.token_hook = None
                    ready = await p.prepare(target, OperationBudget.after(5))
                    self.assertEqual(n.tokens[-1]["refresh_token"], ["rotated"])
                    self.assertIsInstance(ready, Ready)

                self.run_async(run)

    def test_pending_supersede_requests_scope_union_and_old_callback_fails(self):
        """Canonical lifecycle: pending-login-supersede, pending-login-supersede-scope-union."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write", "admin"),
            )
            budget = OperationBudget.after(5)
            first = await p.prepare(target, budget)
            # Requirements already covered by the pending scopes reuse it.
            policy.configuration = replace(
                policy.configuration, required_scopes=("read",)
            )
            self.assertEqual(await p.prepare(target, budget), first)
            policy.configuration = replace(
                policy.configuration, scopes=("write",), required_scopes=()
            )
            second = await p.prepare(target, budget)
            self.assertNotEqual(second.generation, first.generation)

            def scopes(login):
                return set(
                    parse_qs(urlsplit(login.authorization_url).query)["scope"][
                        0
                    ].split()
                )

            self.assertEqual(scopes(second), {"read", "write"})
            # The alternating caller is now covered: no supersede loop.
            policy.configuration = replace(policy.configuration, scopes=("read",))
            self.assertEqual(await p.prepare(target, budget), second)
            # A narrower caller ceiling still reuses (filtered at use); a new
            # scope supersedes with the union intersected with its ceiling.
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "admin"), scopes=("read",)
            )
            self.assertEqual(await p.prepare(target, budget), second)
            policy.configuration = replace(
                policy.configuration, scopes=("read", "admin")
            )
            third = await p.prepare(target, budget)
            # Pending scopes and ceilings only grow.
            self.assertEqual(scopes(third), {"read", "write", "admin"})
            for old in (first, second):
                with self.assertRaises(AuthenticationFailure) as failure:
                    await self.complete_login(p, target, old)
                self.assertEqual(failure.exception.code, "interaction_required")
            self.assertFalse(n.tokens)
            policy.configuration = replace(
                policy.configuration, redirect_uri="https://host.test/other"
            )
            fourth = await p.prepare(target, budget)
            self.assertNotEqual(fourth.generation, third.generation)
            # A different redirect does not merge the old pending scopes.
            self.assertEqual(scopes(fourth), {"read", "admin"})
            policy.configuration = replace(
                policy.configuration, redirect_uri="https://host.test/callback"
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, third)
            self.assertEqual(failure.exception.code, "interaction_required")
            # A supersede stores the union of both ceilings, and completion
            # keeps every merged scope.
            await p.reset(target, budget)
            base = Policy("authorization_code_pkce").configuration
            policy.configuration = replace(
                base, scopes=("read",), allowed_scopes=("read", "write")
            )
            await p.prepare(target, budget)
            policy.configuration = replace(
                base, scopes=("admin",), allowed_scopes=("admin",)
            )
            merged = await p.prepare(target, budget)
            pending = next(iter(s.records.values())).pending.metadata.configuration
            self.assertEqual(set(pending.scopes), {"read", "admin"})
            self.assertEqual(set(pending.ceiling), {"read", "write", "admin"})

            async def everything(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "merged",
                        "token_type": "Bearer",
                        "scope": "read write admin openid",
                    },
                )

            n.token_hook = everything
            await self.complete_login(p, target, merged)
            self.assertEqual(
                next(iter(s.records.values())).token.scopes, ("admin", "read", "write")
            )

        self.run_async(run)

    def test_pending_reuse_is_independent_of_caller_deadline(self):
        """Canonical lifecycle: pending-login-reuse."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            first = await p.prepare(target, OperationBudget.after(1))
            self.assertEqual(await p.prepare(target, OperationBudget.after(5)), first)
            self.assertEqual(await p.prepare(target, OperationBudget.after(0.5)), first)
            now[0] += 100
            # A wider caller ceiling reuses it; the creating ceiling bounds the grant.
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            self.assertEqual(await p.prepare(target, OperationBudget.after(5)), first)

            async def broad(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "t",
                        "token_type": "Bearer",
                        "scope": "read write",
                    },
                )

            n.token_hook = broad
            self.assertIsInstance(await self.complete_login(p, target, first), Ready)
            self.assertEqual(next(iter(s.records.values())).token.scopes, ("read",))

        self.run_async(run)

    def test_pending_lifetime_is_fixed_and_survives_creating_prepare(self):
        """Canonical lifecycle: pending-login-fixed-lifetime."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            with anyio.CancelScope() as owner:
                login = await p.prepare(
                    target, OperationBudget.after(10, cancel_scope=owner)
                )
                owner.cancel()
            self.assertEqual(login.expires_at, now[0] + 600)
            with self.assertRaises(ValueError):
                replace(policy.configuration, login_lifetime=601)
            now[0] += 599
            self.assertIsInstance(await self.complete_login(p, target, login), Ready)
            await p.reset(target, OperationBudget.after(5))
            policy.configuration = replace(policy.configuration, login_lifetime=60)
            login = await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            self.assertEqual(failure.exception.code, "interaction_required")

        self.run_async(run)

    def test_pending_login_completes_from_another_process_after_creator_cancelled(self):
        """Canonical lifecycle: pending-login-cross-process-completion."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            entered = anyio.Event()
            published = []

            async def commit_then_block(key, record):
                if record is not None and record.pending is not None:
                    s.records[key] = record
                    published.append(
                        PendingLogin(
                            key,
                            record.pending.state,
                            record.pending.authorization_url,
                            record.pending.expires_at,
                        )
                    )
                    entered.set()
                    await anyio.sleep_forever()
                return True

            s.cas_hook = commit_then_block

            async def prepare():
                await p.prepare(target, OperationBudget.after(10))

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(prepare)
                await entered.wait()
                tasks.cancel_scope.cancel()
            s.cas_hook = None
            other = ManagedOAuthProvider(
                network=n,
                store=s,
                policy=policy,
                namespace="tenant",
                clock=lambda: now[0],
                expiry_skew=0,
            )
            # Another process only has the stored record and the (serializable) handle.
            self.assertEqual(
                await other.prepare(target, OperationBudget.after(5)), published[0]
            )
            ready = await self.complete_login(other, target, published[0])
            self.assertIsInstance(ready, Ready)
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, published[0])
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertEqual(len(n.tokens), 1)

        self.run_async(run)

    def test_403_without_scope_needs_explicit_host_requirement(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            first = await p.prepare(target, OperationBudget.after(5))
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                challenge = AuthChallenge(
                    403,
                    {"www-authenticate": 'Bearer error="insufficient_scope"'},
                    RESOURCE,
                    first.credential.identity,
                    True,
                )
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(context, challenge)
                self.assertEqual(failure.exception.code, "access_denied")
                self.assertEqual(len(n.tokens), 1)
                policy.configuration = replace(
                    policy.configuration, required_scopes=("write",)
                )

                async def token(request):
                    return httpx.Response(
                        200,
                        json={
                            "access_token": "host-required",
                            "token_type": "Bearer",
                            "scope": "write",
                        },
                    )

                n.token_hook = token
                credential = await p.challenge(context, challenge)
                self.assertEqual(credential.token, "host-required")
                self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
                self.assertIn("write", n.tokens[-1]["scope"][0].split())

        self.run_async(run)

    def test_scope_stepup_does_not_replay_effectful_notification(self):
        from agenthooksprotocol.runtime import ProtocolError

        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            first = await p.prepare(target, OperationBudget.after(5))

            async def token(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "stepped",
                        "token_type": "Bearer",
                        "scope": "read write",
                    },
                )

            n.token_hook = token
            sent = []

            async def deliver(request):
                sent.append(request.headers.get("authorization"))
                if len(sent) == 1:
                    return httpx.Response(
                        403,
                        headers={
                            "www-authenticate": 'Bearer error="insufficient_scope", scope="write"'
                        },
                    )
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(deliver)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE,
                    backend={"id": "backend"},
                    client=client,
                    auth_provider=RoutingAuthProvider(discover=p, namespace="tenant"),
                )
                message = {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                with self.assertRaises(ProtocolError):
                    await transport.notify(message)
                self.assertEqual(sent, ["Bearer " + first.credential.token])
                self.assertEqual(len(n.tokens), 2)
                await transport.notify(message)
                self.assertEqual(sent[-1], "Bearer stepped")
                self.assertEqual(len(sent), 2)
                await transport.aclose()
                self.assertFalse(client.is_closed)

        self.run_async(run)

    def test_cc_without_refresh_reissues_after_transient_using_current_secret(self):
        async def run(p, n, s, policy, target, now):
            async def initial(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "cc-first",
                        "token_type": "Bearer",
                        "expires_in": 60,
                    },
                )

            n.token_hook = initial
            await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(next(iter(s.records.values())).token.scopes, ("read",))
            now[0] += 61

            async def transient(request):
                return httpx.Response(502, text="not OAuth JSON")

            n.token_hook = transient
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.recovery, "retry")
            self.assertIsNotNone(next(iter(s.records.values())).token)
            policy.configuration = replace(
                policy.configuration, client_secret="current-secret"
            )
            n.token_hook = initial
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            self.assertTrue(
                all(form["grant_type"] == ["client_credentials"] for form in n.tokens)
            )
            from base64 import b64decode

            request = [r for r, purpose in n.requests if purpose == "token"][-1]
            self.assertEqual(
                b64decode(request.headers["authorization"].split()[1]),
                b"host-client:current-secret",
            )
            self.assertFalse(any(record.pending for record in s.records.values()))

        self.run_async(run)

    def test_explicit_preset_skips_protected_resource_metadata(self):
        async def run(p, n, s, policy, target, now):
            target = replace(
                target,
                typed_binding=OAuthBinding(
                    ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)
                ),
            )
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            metadata_requests = [
                request for request, purpose in n.requests if purpose == "metadata"
            ]
            self.assertTrue(metadata_requests)
            self.assertTrue(
                all(request.url.host == "issuer.test" for request in metadata_requests)
            )
            self.assertFalse(
                any(
                    "oauth-protected-resource" in str(request.url)
                    for request in metadata_requests
                )
            )

        self.run_async(run)

    def test_literal_loopback_pkce_redirects_complete_but_remote_http_is_rejected(self):
        async def run(p, n, s, policy, target, now):
            for redirect in (
                "http://127.0.0.1:8123/callback",
                "http://[::1]:8123/callback",
            ):
                policy.configuration = replace(
                    Policy("authorization_code_pkce").configuration,
                    redirect_uri=redirect,
                )
                login = await p.prepare(target, OperationBudget.after(5))
                state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
                ready = await p.complete(
                    target,
                    login,
                    redirect + "?" + urlencode({"state": state, "code": "loopback"}),
                    OperationBudget.after(5),
                )
                self.assertIsInstance(ready, Ready)
                self.assertEqual(n.tokens[-1]["redirect_uri"], [redirect])
                await p.reset(target, OperationBudget.after(5), handle=ready.credential)
            policy.configuration = replace(
                policy.configuration, redirect_uri="http://remote.test/callback"
            )
            count = len(n.tokens)
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(len(n.tokens), count)
            self.assertFalse(s.records)

        self.run_async(run)

    def test_all_canonical_key_vectors_cross_http_and_coordinated_store(self):
        async def run():
            for vector in FIXTURES["keys"]:
                with self.subTest(vector=vector["id"]):
                    value = vector["input"]
                    scopes = tuple(value["allowed_scopes"])
                    config = OAuthClientConfiguration(
                        issuer=value["issuer"],
                        client_id=value["client_id"],
                        flow=value["flow"],
                        scopes=scopes,
                        allowed_scopes=scopes,
                        redirect_uri="https://host.test/callback",
                        client_secret=value.get("client_secret"),
                        grant_partition=value.get("grant_partition"),
                    )
                    network = VectorNetwork(
                        config, metadata_overrides=value.get("metadata")
                    )
                    store = Store()
                    policy = VectorPolicy(config, value["resource"])
                    provider = ManagedOAuthProvider(
                        network=network,
                        policy=policy,
                        store=store,
                        namespace=value["namespace"],
                    )
                    target = AuthTarget(
                        value["namespace"],
                        value["backend_id"],
                        value["destination"],
                        value["purpose"],
                        None,
                        OAuthBinding(
                            value["issuer"],
                            value["resource"],
                            value["client_id"],
                            value["flow"],
                            scopes,
                        ),
                    )
                    try:
                        result = await provider.prepare(
                            target, OperationBudget.after(5)
                        )
                        self.assertIsInstance(result, PendingLogin)
                        self.assertEqual(set(store.bindings), {vector["binding_key"]})
                        self.assertEqual(store.coordinated, [vector["grant_key"]])
                        self.assertEqual(set(store.records), {vector["grant_key"]})
                        self.assertEqual(result.key, vector["grant_key"])
                        self.assertTrue(network.requests)
                        self.assertTrue(
                            all(
                                request.method == "GET"
                                for request, _ in network.requests
                            )
                        )
                        self.assertFalse(
                            any(
                                "oauth-protected-resource" in str(request.url)
                                for request, _ in network.requests
                            )
                        )
                        self.assertTrue(
                            all(
                                record.metadata.configuration.client_secret is None
                                for record in store.records.values()
                            )
                        )
                        self.assertTrue(
                            all(
                                metadata.configuration.client_secret is None
                                for metadata in store.bindings.values()
                            )
                        )
                    finally:
                        await network.client.aclose()

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_all_canonical_token_vectors_cross_http_store_and_dispatch(self):
        async def run():
            for vector in FIXTURES["token_responses"]:
                with self.subTest(vector=vector["id"]):
                    # Local policy keeps requested scopes inside the caller's ceiling.
                    requested = sorted(
                        set(vector["requested"]) & set(vector["allowed"])
                    )
                    config = OAuthClientConfiguration(
                        issuer=ISSUER,
                        client_id="host-client",
                        flow="client_credentials",
                        scopes=tuple(requested),
                        allowed_scopes=tuple(vector["allowed"]),
                        required_scopes=tuple(vector["required"]),
                    )
                    responses = []
                    refreshing = vector.get("exchange") == "refresh"
                    seeded = "previous_granted" in vector
                    if seeded:
                        responses.append(
                            {
                                "access_token": "seed-access",
                                "token_type": "Bearer",
                                "expires_in": 1,
                                "refresh_token": "r1",
                                "scope": " ".join(vector["previous_granted"]),
                            }
                        )
                    responses.append(vector["response"])
                    network = VectorNetwork(config, responses)
                    # The seed grant was acquired under a ceiling covering it.
                    seed = replace(
                        config,
                        required_scopes=(),
                        allowed_scopes=tuple(
                            sorted(
                                set(vector["allowed"])
                                | set(vector.get("previous_granted", []))
                            )
                        ),
                    )
                    store, policy, now = Store(), VectorPolicy(seed, RESOURCE), [1000.0]
                    provider = ManagedOAuthProvider(
                        network=network,
                        policy=policy,
                        store=store,
                        namespace="vectors",
                        clock=lambda: now[0],
                        expiry_skew=0,
                    )
                    typed = OAuthBinding(
                        ISSUER,
                        RESOURCE,
                        "host-client",
                        "client_credentials",
                        tuple(requested),
                    )
                    target = AuthTarget(
                        "vectors", "backend", RESOURCE, "event", None, typed
                    )
                    binding = {
                        "type": "oauth",
                        "issuer": ISSUER,
                        "resource": RESOURCE,
                        "clientId": "host-client",
                        "flow": "client_credentials",
                        "scopes": requested,
                    }
                    delivered = []

                    async def deliver(request):
                        delivered.append(request.headers.get("authorization"))
                        return httpx.Response(204)

                    try:
                        if seeded:
                            await provider.prepare(target, OperationBudget.after(5))
                            now[0] += 2
                        policy.configuration = config
                        async with httpx.AsyncClient(
                            transport=httpx.MockTransport(deliver)
                        ) as client:
                            transport = AuthenticatedHTTPTransport(
                                RESOURCE,
                                backend={"id": "backend", "authentication": binding},
                                client=client,
                                auth_provider=RoutingAuthProvider(
                                    oauth=provider, namespace="vectors"
                                ),
                            )
                            message = {
                                "jsonrpc": "2.0",
                                "method": "hooks/observe",
                                "params": {},
                            }
                            if vector["accepted"] and vector["usable"]:
                                await transport.notify(message)
                                self.assertEqual(
                                    delivered,
                                    ["Bearer " + vector["response"]["access_token"]],
                                )
                            else:
                                with self.assertRaises(
                                    AuthenticationFailure
                                ) as failure:
                                    await transport.notify(message)
                                self.assertEqual(
                                    failure.exception.code,
                                    vector.get("error", "access_denied"),
                                )
                                self.assertEqual(delivered, [])
                            await transport.aclose()
                            self.assertFalse(client.is_closed)
                        record = next(iter(store.records.values()), None)
                        if not vector["accepted"] and not refreshing:
                            # An invalid initial exchange persists nothing.
                            self.assertIsNone(record)
                        else:
                            self.assertEqual(record.status, "active")
                            stored = record.token
                            if vector["accepted"]:
                                self.assertEqual(
                                    stored.access_token,
                                    vector["response"]["access_token"],
                                )
                                self.assertEqual(
                                    set(stored.scopes), set(vector["granted"])
                                )
                                self.assertEqual(
                                    set(stored.scopes) & set(vector["allowed"]),
                                    set(vector.get("effective", vector["granted"])),
                                )
                            else:
                                self.assertIsNone(stored.access_token)
                            if vector.get("expiry") == "unknown":
                                self.assertIsNone(stored.expires_at)
                            elif vector.get("expiry") == "known":
                                self.assertEqual(
                                    stored.expires_at,
                                    now[0] + int(vector["response"]["expires_in"]),
                                )
                            if vector["refresh_preserved"]:
                                self.assertEqual(
                                    stored.refresh_token,
                                    vector["response"]["refresh_token"],
                                )
                            elif (
                                "refresh_token" not in vector["response"]
                                and not refreshing
                            ):
                                self.assertIsNone(stored.refresh_token)
                        self.assertEqual(
                            network.tokens[-1]["grant_type"],
                            ["refresh_token" if refreshing else "client_credentials"],
                        )
                        if vector.get("exchange") == "reacquire":
                            wire = set(vector["previous_granted"]) | set(
                                vector["requested"]
                            ) & set(vector["allowed"])
                            self.assertEqual(set(vector["wire_request"]), wire)
                            self.assertEqual(
                                set(network.tokens[-1]["scope"][0].split()), wire
                            )
                        if refreshing:
                            self.assertEqual(
                                network.tokens[-1]["refresh_token"], ["r1"]
                            )
                            self.assertNotIn("scope", network.tokens[-1])
                        self.assertEqual(len(network.tokens), 2 if seeded else 1)
                        self.assertFalse(network.responses)
                        self.assertTrue(store.coordinated)
                    finally:
                        await network.client.aclose()

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_other_task_cancels_budget_owner_during_http_rotation_commits_but_never_returns_ready(
        self,
    ):
        from agenthooksprotocol.runtime import OperationCancelledError

        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            owner_ready, owner_done = anyio.Event(), anyio.Event()
            token_entered, allow_response = anyio.Event(), anyio.Event()
            owners, budgets, ready, cancelled = [], [], [], []

            async def own_budget():
                with anyio.CancelScope() as owner:
                    owners.append(owner)
                    budgets.append(OperationBudget.after(5, cancel_scope=owner))
                    owner_ready.set()
                    await anyio.sleep_forever()
                owner_done.set()

            async def rotate(request):
                token_entered.set()
                await allow_response.wait()
                return httpx.Response(
                    200,
                    json={
                        "access_token": "committed-after-owner-cancel",
                        "token_type": "Bearer",
                        "refresh_token": "rotated-after-owner-cancel",
                        "scope": "read",
                    },
                )

            n.token_hook = rotate

            async def acquire():
                await owner_ready.wait()
                try:
                    ready.append(await p.prepare(target, budgets[0]))
                except OperationCancelledError:
                    cancelled.append(True)

            async def cancel_owner():
                await token_entered.wait()
                owners[0].cancel()
                await owner_done.wait()
                allow_response.set()

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(own_budget)
                tasks.start_soon(acquire)
                tasks.start_soon(cancel_owner)
            self.assertEqual(ready, [])
            self.assertEqual(cancelled, [True])
            record = next(iter(s.records.values()))
            self.assertEqual(record.status, "active")
            self.assertEqual(record.token.refresh_token, "rotated-after-owner-cancel")
            self.assertEqual(record.token.access_token, "committed-after-owner-cancel")
            self.assertIsNone(record.token.expires_at)
            self.assertFalse(n.client.is_closed)
            fresh = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(fresh.credential.token, "committed-after-owner-cancel")
            self.assertEqual(len(n.tokens), 2)

        self.run_async(run)

    def test_endpoint_and_capability_rotation_renews_outside_grant_lock_with_current_secret(
        self,
    ):
        from base64 import b64decode

        async def run(p, n, s, policy, target, now):
            target = replace(
                target,
                typed_binding=OAuthBinding(
                    ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)
                ),
            )
            state = {"outage": False, "rotated": False}
            metadata_urls, token_requests = [], []

            async def handle(request):
                if request.method == "GET":
                    self.assertFalse(any(lock.locked() for lock in s.locks.values()))
                    metadata_urls.append(str(request.url))
                    self.assertEqual(request.url.host, "issuer.test")
                    if state["outage"]:
                        return httpx.Response(503, text="issuer metadata unavailable")
                    return httpx.Response(
                        200,
                        json={
                            "issuer": ISSUER,
                            "token_endpoint": ISSUER
                            + ("/rotated-token" if state["rotated"] else "/token"),
                            "grant_types_supported": [
                                "client_credentials",
                                "refresh_token",
                            ]
                            + (["authorization_code"] if state["rotated"] else []),
                            "token_endpoint_auth_methods_supported": [
                                "client_secret_basic"
                            ]
                            + (
                                ["client_secret_post", "none"]
                                if state["rotated"]
                                else []
                            ),
                        },
                    )
                self.assertTrue(any(lock.locked() for lock in s.locks.values()))
                token_requests.append(request)
                n.tokens.append(parse_qs(request.content.decode()))
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"endpoint-access-{len(token_requests)}",
                        "token_type": "Bearer",
                        "expires_in": 60,
                        "refresh_token": f"endpoint-refresh-{len(token_requests)}",
                        "scope": "read",
                    },
                )

            await n.client.aclose()
            n.client = httpx.AsyncClient(
                transport=httpx.MockTransport(handle), trust_env=False
            )
            first = await p.prepare(target, OperationBudget.after(5))
            grant_keys = set(s.records)
            self.assertEqual(str(token_requests[0].url), ISSUER + "/token")
            state["outage"] = True
            request_count = len(n.requests)
            cached = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(cached.credential, first.credential)
            self.assertEqual(len(n.requests), request_count)
            self.assertEqual(len(metadata_urls), 1)
            state.update(outage=False, rotated=True)
            policy.configuration = replace(
                policy.configuration, client_secret="latest-endpoint-secret"
            )
            now[0] += 61
            renewed = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(renewed.credential.token, first.credential.token)
            self.assertEqual(set(s.records), grant_keys)
            self.assertEqual(len(metadata_urls), 2)
            self.assertFalse(
                any("oauth-protected-resource" in url for url in metadata_urls)
            )
            self.assertEqual(len(token_requests), 2)
            self.assertEqual(str(token_requests[-1].url), ISSUER + "/rotated-token")
            self.assertEqual(n.tokens[-1]["grant_type"], ["refresh_token"])
            self.assertEqual(n.tokens[-1]["refresh_token"], ["endpoint-refresh-1"])
            self.assertEqual(
                b64decode(token_requests[-1].headers["authorization"].split()[1]),
                b"host-client:latest-endpoint-secret",
            )
            self.assertTrue(
                all(
                    value.token_endpoint == ISSUER + "/rotated-token"
                    for value in s.bindings.values()
                )
            )
            self.assertTrue(
                all(
                    value.configuration.client_secret is None
                    for value in s.bindings.values()
                )
            )
            self.assertFalse(any(lock.locked() for lock in s.locks.values()))
            self.assertFalse(n.client.is_closed)

        self.run_async(run)

    def test_managed_missing_backend_id_fails_before_http_or_store_identity(self):
        async def run(p, n, s, policy, target, now):
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    replace(target, backend_id=""), OperationBudget.after(5)
                )
            self.assertEqual(failure.exception.code, "invalid_configuration")
            delivered = []

            async def deliver(request):
                delivered.append(request)
                return httpx.Response(204)

            binding = {
                "type": "oauth",
                "issuer": ISSUER,
                "resource": RESOURCE,
                "clientId": "host-client",
                "flow": "client_credentials",
                "scopes": ["read"],
            }
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(deliver)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE,
                    backend={"authentication": binding},
                    client=client,
                    auth_provider=RoutingAuthProvider(oauth=p, namespace="tenant"),
                )
                with self.assertRaises(AuthenticationFailure) as failure:
                    await transport.notify(
                        {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                    )
                self.assertEqual(failure.exception.code, "invalid_configuration")
                await transport.aclose()
                self.assertFalse(client.is_closed)
            self.assertEqual(delivered, [])
            self.assertEqual(n.requests, [])
            self.assertEqual(n.authorized, [])
            self.assertFalse(s.bindings)
            self.assertFalse(s.records)
            self.assertEqual(s.coordinated, [])

        self.run_async(run)

    def test_handle_bound_reset_needs_no_network_for_ready_or_pending(self):
        async def run(p, n, s, policy, target, now):
            ready = await p.prepare(target, OperationBudget.after(5))
            count = len(n.requests)
            authorized_count = len(n.authorized)
            original_authorize = n.authorize

            async def deny_network(url, purpose, budget):
                self.fail("handle-bound reset must not rediscover or authorize URLs")

            n.authorize = deny_network
            with self.assertRaises(AuthenticationFailure):
                await p.reset(
                    replace(target, purpose="upload"),
                    OperationBudget.after(5),
                    handle=ready.credential,
                )
            self.assertEqual(len(s.records), 1)
            await p.reset(target, OperationBudget.after(5), handle=ready.credential)
            self.assertFalse(s.records)
            self.assertEqual(len(n.requests), count)
            self.assertEqual(len(n.authorized), authorized_count)
            n.authorize = original_authorize
            policy.configuration = Policy("authorization_code_pkce").configuration
            login = await p.prepare(target, OperationBudget.after(5))
            self.assertIsInstance(login, PendingLogin)
            count = len(n.requests)
            n.authorize = deny_network
            await p.reset(target, OperationBudget.after(5), handle=login)
            self.assertFalse(s.records)
            self.assertEqual(len(n.requests), count)

        self.run_async(run)

    def unbound(self):
        return AuthContext(
            {"id": "backend"}, None, RESOURCE, "event", anyio.CancelScope()
        )

    def test_unbound_lookup_is_anonymous_only_on_store_miss_or_policy_refusal(self):
        """Canonical lifecycle: unbound-lookup-anonymous-fallback."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            self.assertIsNone(await p.credential(self.unbound()))
            self.assertEqual((n.requests, n.authorized, s.records), ([], [], {}))
            policy.configuration = Policy().configuration
            ready = await p.prepare(target, OperationBudget.after(5))
            count = len(n.requests)
            original = policy.select

            async def refuse(*args):
                raise AuthenticationFailure(code="untrusted_destination")

            policy.select = refuse
            self.assertIsNone(await p.credential(self.unbound()))
            policy.select = original
            self.assertEqual(
                (await p.credential(self.unbound())).token, ready.credential.token
            )
            self.assertEqual(len(n.requests), count)
            self.assertFalse(any(record.pending for record in s.records.values()))

        self.run_async(run)

    def test_unbound_lookup_refreshes_expired_token_with_cached_metadata(self):
        """Canonical lifecycle: unbound-lookup-refreshes-expired-token."""

        async def run(p, n, s, policy, target, now):
            first = await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            fresh = ManagedOAuthProvider(
                network=n,
                store=s,
                policy=policy,
                namespace="tenant",
                clock=lambda: now[0],
                expiry_skew=0,
            )
            credential = await fresh.credential(self.unbound())
            self.assertNotEqual(credential.token, first.credential.token)
            self.assertEqual(n.tokens[-1]["grant_type"], ["refresh_token"])
            self.assertEqual(
                [r.method for r, purpose in n.requests if purpose == "metadata"],
                ["GET", "GET"],
            )
            self.assertEqual(next(iter(s.records.values())).status, "active")

        self.run_async(run)

    async def pkce_grant(self, p, n, policy, target):
        policy.configuration = Policy("authorization_code_pkce").configuration
        return await self.complete_login(
            p, target, await p.prepare(target, OperationBudget.after(5))
        )

    def test_refresh_invalid_grant_drops_both_tokens(self):
        """Canonical lifecycle: refresh-invalid-grant-drops-tokens."""

        async def run_bound(p, n, s, policy, target, now):
            await self.pkce_grant(p, n, policy, target)
            now[0] += 61

            async def rejected(request):
                return httpx.Response(400, json={"error": "invalid_grant"})

            n.token_hook = rejected
            binding = {
                "type": "oauth",
                "flow": "authorization_code_pkce",
                "issuer": ISSUER,
                "resource": RESOURCE,
                "clientId": "host-client",
                "scopes": ["read"],
            }
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.credential(
                    AuthContext(
                        {"id": "backend"},
                        binding,
                        RESOURCE,
                        "event",
                        anyio.CancelScope(),
                    )
                )
            self.assertEqual(
                (failure.exception.code, failure.exception.recovery),
                ("refresh_rejected", "login"),
            )
            self.assertFalse(s.records)

        self.run_async(run_bound)

    def test_refresh_invalid_grant_for_replaced_record_keeps_newer_record(self):
        """Canonical lifecycle: refresh-invalid-grant-stale-does-not-wipe."""

        async def run(p, n, s, policy, target, now):
            await self.pkce_grant(p, n, policy, target)
            now[0] += 61
            newer = []

            async def rejected(request):
                # Another writer (e.g. a misbehaving store lock) rotates first.
                key = next(iter(s.records))
                newer.append(
                    replace(
                        s.records[key],
                        generation="newer",
                        status="active",
                        token=replace(
                            s.records[key].token,
                            access_token="newer",
                            refresh_token="newer-refresh",
                            expires_at=None,
                        ),
                    )
                )
                s.records[key] = newer[0]
                return httpx.Response(400, json={"error": "invalid_grant"})

            n.token_hook = rejected
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.code, "provider_failed")
            self.assertEqual(next(iter(s.records.values())), newer[0])
            n.token_hook = None
            self.assertEqual(
                (await p.prepare(target, OperationBudget.after(5))).credential.token,
                "newer",
            )

        self.run_async(run)

    def test_pending_login_ends_once_by_completion_cancel_denial_or_expiry(self):
        """Canonical lifecycle: pending-login-end-states."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration

            async def ended(login):
                with self.assertRaises(AuthenticationFailure) as failure:
                    await self.complete_login(p, target, login)
                self.assertEqual(failure.exception.code, "interaction_required")

            login = await p.prepare(target, OperationBudget.after(5))
            await p.cancel(target, login, OperationBudget.after(5))
            await ended(login)
            login = await p.prepare(target, OperationBudget.after(5))
            now[0] = login.expires_at
            await ended(login)
            login = await p.prepare(target, OperationBudget.after(5))
            state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.complete(
                    target,
                    login,
                    "https://host.test/callback?"
                    + urlencode({"state": state, "error": "access_denied"}),
                    OperationBudget.after(5),
                )
            self.assertEqual(failure.exception.code, "access_denied")
            await ended(login)
            login = await p.prepare(target, OperationBudget.after(5))
            self.assertIsInstance(await self.complete_login(p, target, login), Ready)
            await ended(login)
            self.assertEqual(len(n.tokens), 1)

        self.run_async(run)

    def test_widening_allowed_ceiling_keeps_existing_grant(self):
        """Canonical lifecycle: scope-ceiling-widening-keeps-grant."""

        async def run(p, n, s, policy, target, now):
            first = await self.pkce_grant(p, n, policy, target)
            keys = set(s.records)
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write", "offline_access")
            )
            again = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(again.credential.token, first.credential.token)
            self.assertEqual(set(s.records), keys)
            # Narrowing re-intersects at use: the read grant is no longer effective.
            policy.configuration = replace(
                policy.configuration,
                scopes=("write",),
                allowed_scopes=("write",),
                required_scopes=("write",),
            )
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), PendingLogin
            )
            self.assertEqual(set(s.records), keys)

        self.run_async(run)

    def test_extra_granted_scopes_are_ignored_without_token_storm(self):
        """Canonical lifecycle: extra-granted-scope-ignored."""

        async def run(p, n, s, policy, target, now):
            async def every_scope(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "all",
                        "token_type": "Bearer",
                        "expires_in": 60,
                        "scope": "read openid offline_access admin",
                    },
                )

            n.token_hook = every_scope
            for _ in range(3):
                self.assertEqual(
                    (
                        await p.prepare(target, OperationBudget.after(5))
                    ).credential.token,
                    "all",
                )
            self.assertEqual(len(n.tokens), 1)
            self.assertEqual(next(iter(s.records.values())).token.scopes, ("read",))
            writes = len(s.transitions)
            bindings = dict(s.bindings)
            await p.credential(self.unbound())
            self.assertEqual((len(s.transitions), s.bindings), (writes, bindings))

        self.run_async(run)

    def test_challenged_replay_once_for_request_methods_only(self):
        """Canonical lifecycle: challenged-replay-once."""
        from agenthooksprotocol.runtime import ProtocolError

        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            for method, message in (
                ("hooks/intercept", intercept_request()),
                (
                    "hooks/configuration",
                    {
                        "jsonrpc": "2.0",
                        "id": "cfg",
                        "method": "hooks/configuration",
                        "params": {},
                    },
                ),
                (
                    "hooks/capabilities",
                    {
                        "jsonrpc": "2.0",
                        "id": "cap",
                        "method": "hooks/capabilities",
                        "params": {},
                    },
                ),
            ):
                for reject_twice in (False, True):
                    with self.subTest(method=method, reject_twice=reject_twice):
                        seen = []

                        async def deliver(request):
                            seen.append(
                                (request.headers.get("authorization"), request.content)
                            )
                            if len(seen) == 1 or reject_twice:
                                return httpx.Response(
                                    401, headers={"www-authenticate": "Bearer"}
                                )
                            return httpx.Response(
                                200,
                                json={
                                    "jsonrpc": "2.0",
                                    "id": message["id"],
                                    "result": {
                                        "protocolVersion": "draft",
                                        "effects": [],
                                    },
                                },
                            )

                        async with httpx.AsyncClient(
                            transport=httpx.MockTransport(deliver)
                        ) as client:
                            transport = AuthenticatedHTTPTransport(
                                RESOURCE,
                                backend={"id": "backend"},
                                client=client,
                                auth_provider=RoutingAuthProvider(
                                    discover=p, namespace="tenant"
                                ),
                            )
                            transport._validator.validate = lambda kind, value: value
                            if reject_twice:
                                with self.assertRaises(ProtocolError):
                                    await transport.request(message)
                            else:
                                await transport.request(message)
                        self.assertEqual(len(seen), 2)
                        self.assertEqual(seen[0][1], seen[1][1])
                        self.assertNotEqual(seen[0][0], seen[1][0])
            sent = []

            async def reject(request):
                sent.append(request)
                return httpx.Response(401, headers={"www-authenticate": "Bearer"})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(reject)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE,
                    backend={"id": "backend"},
                    client=client,
                    auth_provider=RoutingAuthProvider(discover=p, namespace="tenant"),
                )
                with self.assertRaises(ProtocolError):
                    await transport.notify(
                        {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                    )
            self.assertEqual(len(sent), 1)
            # Known binding: the stored token is sent up front, never replayed.
            self.assertTrue(sent[0].headers["authorization"].startswith("Bearer "))

        self.run_async(run)

    def test_narrowing_ceiling_hides_scopes_only_at_use(self):
        """Canonical lifecycle: scope-ceiling-narrowing-keeps-grant."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                scopes=("read", "write"),
            )

            async def token(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"t{len(n.tokens)}",
                        "token_type": "Bearer",
                        "refresh_token": f"r{len(n.tokens)}",
                        "expires_in": 60,
                    },
                )

            n.token_hook = token
            await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            policy.configuration = replace(
                policy.configuration, scopes=("read",), allowed_scopes=("read",)
            )
            now[0] += 61
            self.assertEqual(
                (await p.prepare(target, OperationBudget.after(5))).credential.token,
                "t2",
            )
            self.assertEqual(
                next(iter(s.records.values())).token.scopes, ("read", "write")
            )
            policy.configuration = replace(
                policy.configuration,
                allowed_scopes=("read", "write"),
                required_scopes=("write",),
            )
            self.assertEqual(
                (await p.prepare(target, OperationBudget.after(5))).credential.token,
                "t2",
            )
            self.assertEqual(len(n.tokens), 2)

        self.run_async(run)

    def test_unreplayed_challenge_prepares_the_next_attempt(self):
        """Canonical lifecycle: unreplayed-challenge-prepares-next-attempt."""
        from agenthooksprotocol.runtime import ProtocolError

        async def run(p, n, s, policy, target, now):
            sent = []

            async def deliver(request):
                sent.append(request.headers.get("authorization"))
                if len(sent) == 1:
                    return httpx.Response(401, headers={"www-authenticate": "Bearer"})
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(deliver)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE,
                    backend={"id": "backend"},
                    client=client,
                    auth_provider=RoutingAuthProvider(discover=p, namespace="tenant"),
                )
                message = {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                with self.assertRaises(ProtocolError):
                    await transport.notify(message)
                self.assertEqual(sent, [None])
                self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
                await transport.notify(message)
                self.assertEqual(sent[-1], "Bearer access-1")
            policy.configuration = Policy("authorization_code_pkce").configuration
            await p.reset(target, OperationBudget.after(5))
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.challenge(
                    self.unbound(),
                    AuthChallenge(
                        401, {"www-authenticate": "Bearer"}, RESOURCE, None, False
                    ),
                )
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertFalse(s.records)

        self.run_async(run)

    def test_up_front_refresh_failure_has_no_anonymous_fallback(self):
        """Canonical lifecycle: up-front-refresh-failure-no-anonymous-fallback."""

        async def run(p, n, s, policy, target, now):
            await self.pkce_grant(p, n, policy, target)

            async def expiring(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "short",
                        "token_type": "Bearer",
                        "refresh_token": "r",
                        "expires_in": 60,
                    },
                )

            n.token_hook = expiring
            await p.reset(target, OperationBudget.after(5))
            await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            now[0] += 61
            for response, code in (
                (httpx.Response(503), "provider_failed"),
                (
                    httpx.Response(400, json={"error": "invalid_grant"}),
                    "refresh_rejected",
                ),
            ):

                async def fail(request, response=response):
                    return response

                n.token_hook = fail
                sent = []

                async def deliver(request):
                    sent.append(request)
                    return httpx.Response(204)

                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(deliver)
                ) as client:
                    transport = AuthenticatedHTTPTransport(
                        RESOURCE,
                        backend={"id": "backend"},
                        client=client,
                        auth_provider=RoutingAuthProvider(
                            discover=p, namespace="tenant"
                        ),
                    )
                    with self.assertRaises(AuthenticationFailure) as failure:
                        await transport.notify(
                            {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                        )
                self.assertEqual(failure.exception.code, code)
                self.assertEqual(sent, [])

        self.run_async(run)

    def test_prepare_required_scopes_outside_ceiling_are_denied(self):
        """Canonical lifecycle: prepare-required-outside-ceiling-denied."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            await p.prepare(target, OperationBudget.after(5))
            records = dict(s.records)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    target, OperationBudget.after(5), required_scopes=("admin",)
                )
            self.assertEqual(failure.exception.code, "access_denied")
            self.assertEqual(s.records, records)
            self.assertFalse(n.tokens)

        self.run_async(run)

    def test_up_front_lookup_reacquires_client_credentials_with_persisted_metadata(
        self,
    ):
        """Canonical lifecycle: up-front-client-credentials-reacquire."""

        async def run(p, n, s, policy, target, now):
            async def no_refresh(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"cc-{len(n.tokens)}",
                        "token_type": "Bearer",
                        "expires_in": 60,
                    },
                )

            n.token_hook = no_refresh
            await p.prepare(target, OperationBudget.after(5))
            metadata_requests = [
                r for r, purpose in n.requests if purpose == "metadata"
            ]
            now[0] += 61
            self.assertEqual((await p.credential(self.unbound())).token, "cc-2")
            self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
            self.assertEqual(
                [r for r, purpose in n.requests if purpose == "metadata"],
                metadata_requests,
            )

        self.run_async(run)

    def test_up_front_lookup_fetches_only_issuer_metadata_when_missing(self):
        """Canonical lifecycle: up-front-lookup-issuer-metadata-only."""

        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            for key, value in list(s.bindings.items()):
                s.bindings[key] = replace(value, token_endpoint="")
            before = len(n.requests)
            self.assertIsNotNone(await p.credential(self.unbound()))
            urls = [
                str(r.url)
                for r, purpose in n.requests[before:]
                if purpose == "metadata"
            ]
            self.assertEqual(urls, [ISSUER + "/.well-known/oauth-authorization-server"])
            self.assertTrue(all(value.token_endpoint for value in s.bindings.values()))
            for key, value in list(s.bindings.items()):
                s.bindings[key] = replace(value, token_endpoint="")
            now[0] += 61
            original = n.handle

            async def outage(request):
                if request.method == "GET":
                    return httpx.Response(503)
                return await original(request)

            await n.client.aclose()
            n.client = httpx.AsyncClient(
                transport=httpx.MockTransport(outage), trust_env=False
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.credential(self.unbound())
            self.assertEqual(failure.exception.code, "discovery_failed")
            self.assertFalse(
                any(
                    "oauth-protected-resource" in str(r.url)
                    for r, _ in n.requests[before:]
                )
            )

        self.run_async(run)

    def test_known_binding_without_token_requires_login_until_prepare(self):
        """Canonical lifecycle: known-binding-without-token-requires-login."""

        async def run(p, n, s, policy, target, now):
            await self.pkce_grant(p, n, policy, target)
            await p.reset(target, OperationBudget.after(5))
            self.assertTrue(s.bindings)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.credential(self.unbound())
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertFalse(s.records)
            ready = await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            self.assertEqual(
                (await p.credential(self.unbound())).token, ready.credential.token
            )

        self.run_async(run)

    def test_challenge_renews_rejected_unexpired_token(self):
        """Canonical lifecycle: challenge-renews-rejected-unexpired-token."""
        from agenthooksprotocol.runtime import ProtocolError

        async def run(p, n, s, policy, target, now):
            async def unknown_expiry(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"cc-{len(n.tokens)}",
                        "token_type": "Bearer",
                    },
                )

            n.token_hook = unknown_expiry
            await p.prepare(target, OperationBudget.after(5))
            sent = []

            async def deliver(request):
                sent.append(request.headers.get("authorization"))
                if len(sent) == 1:
                    return httpx.Response(401, headers={"www-authenticate": "Bearer"})
                return httpx.Response(204)

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(deliver)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE,
                    backend={"id": "backend"},
                    client=client,
                    auth_provider=RoutingAuthProvider(discover=p, namespace="tenant"),
                )
                message = {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                with self.assertRaises(ProtocolError):
                    await transport.notify(message)
                await transport.notify(message)
            self.assertEqual(sent, ["Bearer cc-1", "Bearer cc-2"])

        self.run_async(run)

    def test_step_up_reacquisition_keeps_previous_grant(self):
        """Canonical lifecycle: step-up-keeps-previous-grant."""

        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            first = await p.prepare(target, OperationBudget.after(5))

            async def granted(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "stepped",
                        "token_type": "Bearer",
                        "scope": "read write openid",
                    },
                )

            n.token_hook = granted
            policy.configuration = replace(policy.configuration, scopes=("write",))
            challenge = AuthChallenge(
                403,
                {
                    "www-authenticate": 'Bearer error="insufficient_scope", scope="write"'
                },
                RESOURCE,
                first.credential.identity,
                True,
            )
            self.assertEqual(
                (await p.challenge(self.unbound(), challenge)).token, "stepped"
            )
            self.assertEqual(set(n.tokens[-1]["scope"][0].split()), {"read", "write"})
            self.assertEqual(
                next(iter(s.records.values())).token.scopes, ("read", "write")
            )

        self.run_async(run)

    def test_stale_issuer_metadata_is_refetched_once(self):
        """Canonical lifecycle: stale-metadata-refetch-once."""

        async def run(p, n, s, policy, target, now):
            state = {"endpoint": "/token", "issuer": ISSUER, "token": None}
            gets = []

            async def handle(request):
                if request.method == "GET":
                    gets.append(str(request.url))
                    if request.url.host == "resource.test":
                        return httpx.Response(200, json=metadata(request))
                    return httpx.Response(
                        200,
                        json={
                            **metadata(request),
                            "issuer": state["issuer"],
                            "token_endpoint": ISSUER + state["endpoint"],
                        },
                    )
                n.tokens.append(parse_qs(request.content.decode()))
                if state["token"] is not None:
                    return state["token"]
                if request.url.path != state["endpoint"]:
                    return httpx.Response(404, text="moved")
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"t{len(n.tokens)}",
                        "token_type": "Bearer",
                        "refresh_token": f"r{len(n.tokens)}",
                        "expires_in": 60,
                    },
                )

            await n.client.aclose()
            n.client = httpx.AsyncClient(
                transport=httpx.MockTransport(handle), trust_env=False
            )
            await p.prepare(target, OperationBudget.after(5))
            gets.clear()
            state["endpoint"] = "/moved-token"
            now[0] += 61
            credential = await p.credential(self.unbound())
            self.assertEqual(credential.token, "t3")
            self.assertEqual(gets, [ISSUER + "/.well-known/oauth-authorization-server"])
            self.assertTrue(
                all(
                    m.token_endpoint == ISSUER + "/moved-token"
                    for m in s.bindings.values()
                )
            )
            # An OAuth error response never triggers a refetch.
            gets.clear()
            now[0] += 61
            state["token"] = httpx.Response(400, json={"error": "invalid_client"})
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.credential(self.unbound())
            self.assertEqual(failure.exception.code, "credential_unavailable")
            self.assertEqual(gets, [])
            # A changed issuer (or failed refetch) reports discovery_failed once.
            state.update(token=httpx.Response(404), issuer="https://other.test")
            count = len(n.tokens)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.credential(self.unbound())
            self.assertEqual(
                (failure.exception.code, failure.exception.recovery),
                ("discovery_failed", "retry"),
            )
            self.assertEqual(len(gets), 1)
            self.assertEqual(len(n.tokens), count + 1)
            self.assertFalse(any("oauth-protected-resource" in url for url in gets))
            self.assertEqual(next(iter(s.records.values())).status, "active")

        self.run_async(run)

    def test_ambiguous_renewal_failure_neither_refetches_nor_retries(self):
        """Canonical lifecycle: ambiguous-renewal-failure-no-refetch."""

        def raising(error_type):
            def respond(request):
                raise error_type("after send", request=request)

            return respond

        failures = (
            ("read-reset", raising(httpx.ReadError), AuthenticationFailure),
            ("read-timeout", raising(httpx.ReadTimeout), AuthenticationFailure),
            (
                "5xx",
                lambda request: httpx.Response(503, text="busy"),
                AuthenticationFailure,
            ),
            (
                "non-oauth",
                lambda request: httpx.Response(200, text="<html>"),
                AuthenticationFailure,
            ),
            (
                "redirect",
                lambda request: httpx.Response(
                    307, headers={"location": ISSUER + "/elsewhere"}
                ),
                AuthenticationFailure,
            ),
        )
        for name, respond, expected in failures:
            with self.subTest(failure=name):

                async def run(p, n, s, policy, target, now):
                    await p.prepare(target, OperationBudget.after(5))
                    old = next(iter(s.records.values())).token
                    now[0] += 61
                    before, tokens = len(n.requests), len(n.tokens)

                    async def fail(request):
                        return respond(request)

                    n.token_hook = fail
                    with self.assertRaises(expected) as failure:
                        await p.credential(self.unbound())
                    if expected is AuthenticationFailure:
                        self.assertEqual(
                            (failure.exception.code, failure.exception.recovery),
                            ("provider_failed", "retry"),
                        )
                    self.assertEqual(len(n.tokens), tokens + 1)
                    self.assertFalse(
                        [
                            r
                            for r, purpose in n.requests[before:]
                            if purpose == "metadata"
                        ]
                    )
                    record = next(iter(s.records.values()))
                    self.assertEqual(
                        (record.status, record.token.refresh_token),
                        ("active", old.refresh_token),
                    )

                self.run_async(run)

    def test_connect_failure_refetches_issuer_metadata_once(self):
        """A connect failure provably sent nothing, so one refetch and retry is safe."""

        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            calls = []

            async def connect_once(request):
                calls.append(request)
                if len(calls) == 1:
                    raise httpx.ConnectError("refused", request=request)
                return httpx.Response(
                    200,
                    json={
                        "access_token": "retried",
                        "token_type": "Bearer",
                        "expires_in": 60,
                    },
                )

            n.token_hook = connect_once
            before = len(n.requests)
            self.assertEqual((await p.credential(self.unbound())).token, "retried")
            self.assertEqual(
                [
                    str(r.url)
                    for r, purpose in n.requests[before:]
                    if purpose == "metadata"
                ],
                [ISSUER + "/.well-known/oauth-authorization-server"],
            )

        self.run_async(run)

    def issuer_move(self, n, policy, new_issuer):
        async def handle(request):
            if request.method == "GET":
                if request.url.host == "resource.test":
                    return httpx.Response(
                        200,
                        json={
                            "resource": RESOURCE,
                            "authorization_servers": [new_issuer],
                        },
                    )
                document = metadata(request)
                if request.url.host == urlsplit(new_issuer).hostname:
                    document = {
                        **document,
                        "issuer": new_issuer,
                        "token_endpoint": new_issuer + "/token",
                        "authorization_endpoint": new_issuer + "/authorize",
                    }
                return httpx.Response(200, json=document)
            n.tokens.append(parse_qs(request.content.decode()))
            return httpx.Response(
                200,
                json={
                    "access_token": f"moved-{len(n.tokens)}",
                    "token_type": "Bearer",
                    "expires_in": 60,
                },
            )

        policy.configuration = replace(policy.configuration, issuer=new_issuer)

        async def select(target, resource, issuers, required_scopes, budget):
            return policy.configuration

        policy.select = select
        return httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False)

    def test_issuer_change_is_repaired_by_prepare_and_challenge(self):
        new_issuer = "https://new-issuer.test"

        async def run(p, n, s, policy, target, now):
            first = await p.prepare(target, OperationBudget.after(5))
            await n.client.aclose()
            n.client = self.issuer_move(n, policy, new_issuer)
            # A 401 challenge rediscovers and acquires from the new issuer.
            challenge = AuthChallenge(
                401,
                {"www-authenticate": "Bearer"},
                RESOURCE,
                first.credential.identity,
                True,
            )
            credential = await p.challenge(self.unbound(), challenge)
            self.assertTrue(credential.token.startswith("moved-"))
            self.assertEqual(
                [m.configuration.issuer for m in s.bindings.values()], [new_issuer]
            )
            self.assertEqual(
                (await p.credential(self.unbound())).token, credential.token
            )

        self.run_async(run)

        async def run_pkce(p, n, s, policy, target, now):
            await self.pkce_grant(p, n, policy, target)
            await n.client.aclose()
            n.client = self.issuer_move(n, policy, new_issuer)
            await p.reset(target, OperationBudget.after(5))
            login = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(
                urlsplit(login.authorization_url).hostname, "new-issuer.test"
            )
            self.assertEqual(
                [m.configuration.issuer for m in s.bindings.values()], [new_issuer]
            )
            self.assertTrue(
                (
                    await self.complete_login(p, target, login)
                ).credential.token.startswith("moved-")
            )

        self.run_async(run_pkce)

    def test_prepare_rebuilds_metadata_before_creating_a_login(self):
        async def run(p, n, s, policy, target, now):
            await self.pkce_grant(p, n, policy, target)
            await p.reset(target, OperationBudget.after(5))
            original = n.handle

            async def moved(request):
                if request.method == "GET" and request.url.host == "issuer.test":
                    return httpx.Response(
                        200,
                        json={
                            **metadata(request),
                            "authorization_endpoint": ISSUER + "/authorize-v2",
                        },
                    )
                return await original(request)

            await n.client.aclose()
            n.client = httpx.AsyncClient(
                transport=httpx.MockTransport(moved), trust_env=False
            )
            login = await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(urlsplit(login.authorization_url).path, "/authorize-v2")
            self.assertTrue(
                all(
                    m.authorization_endpoint == ISSUER + "/authorize-v2"
                    for m in s.bindings.values()
                )
            )

        self.run_async(run)

    def test_up_front_lookup_propagates_validation_and_rotated_principal_fails(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            good = policy.configuration
            policy.configuration = replace(good, client_secret=None)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.credential(self.unbound())
            self.assertEqual(failure.exception.code, "credential_unavailable")
            # A changed principal on a known binding cannot rediscover here:
            # it fails discovery_failed and is never sent anonymously.
            for change in (
                {"client_id": "rotated-client"},
                {"grant_partition": "other-partition"},
            ):
                policy.configuration = replace(good, **change)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.credential(self.unbound())
                self.assertEqual(failure.exception.code, "discovery_failed")
            # Host prepare repairs it under the new principal.
            policy.configuration = replace(good, client_id="rotated-client")
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            self.assertIsNotNone(await p.credential(self.unbound()))

        self.run_async(run)

    def test_huge_expires_in_is_clamped_and_keeps_rotated_refresh(self):
        for lifetime in (b"1" + b"0" * 400, b"9" * 5000, b'"' + b"9" * 5000 + b'"'):
            with self.subTest(digits=len(lifetime)):

                async def run(p, n, s, policy, target, now, lifetime=lifetime):
                    await self.pkce_grant(p, n, policy, target)
                    now[0] += 61

                    async def huge(request):
                        body = (
                            b'{"access_token":"new","token_type":"Bearer",'
                            b'"refresh_token":"ROTATED","expires_in":' + lifetime + b"}"
                        )
                        return httpx.Response(
                            200,
                            content=body,
                            headers={"content-type": "application/json"},
                        )

                    n.token_hook = huge
                    ready = await p.prepare(target, OperationBudget.after(5))
                    self.assertEqual(ready.credential.token, "new")
                    token = next(iter(s.records.values())).token
                    self.assertEqual(token.refresh_token, "ROTATED")
                    self.assertEqual(token.expires_at, now[0] + 2**31)

                self.run_async(run)

    def test_slow_store_commit_after_refresh_keeps_new_refresh_token(self):
        async def run(p, n, s, policy, target, now):
            await self.pkce_grant(p, n, policy, target)
            now[0] += 61

            async def slow(key, record):
                if record is not None and record.status == "active":
                    await anyio.sleep(1.2)
                return True

            s.cas_hook = slow
            patient = ManagedOAuthProvider(
                network=n,
                policy=policy,
                store=s,
                namespace="tenant",
                clock=lambda: now[0],
                expiry_skew=0,
            )
            self.assertIsNotNone(await patient.credential(self.unbound()))
            record = next(iter(s.records.values()))
            self.assertEqual(
                (record.status, record.token.refresh_token), ("active", "refresh-2")
            )
            with self.assertRaises(AuthenticationFailure):
                ManagedOAuthProvider(
                    network=n,
                    policy=policy,
                    store=s,
                    namespace="tenant",
                    commit_timeout=0,
                )

        self.run_async(run)

    def test_endpointless_binding_with_gone_issuer_falls_back_to_discovery(self):
        new_issuer = "https://new-issuer.test"

        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            for key, value in list(s.bindings.items()):
                s.bindings[key] = replace(value, token_endpoint="")
            await n.client.aclose()
            n.client = self.issuer_move(n, policy, new_issuer)
            original = policy.select

            async def select(target, resource, issuers, required_scopes, budget):
                # The host still selects the old issuer for the cached binding.
                config = await original(
                    target, resource, issuers, required_scopes, budget
                )
                return replace(config, issuer=issuers[0])

            policy.select = select
            gone = n.client

            async def without_old_issuer(request):
                if request.method == "GET" and request.url.host == "issuer.test":
                    return httpx.Response(404)
                return await gone._transport.handle_async_request(request)

            n.client = httpx.AsyncClient(
                transport=httpx.MockTransport(without_old_issuer), trust_env=False
            )
            now[0] += 61
            self.assertIsInstance(
                await p.prepare(target, OperationBudget.after(5)), Ready
            )
            self.assertEqual(
                [m.configuration.issuer for m in s.bindings.values()], [new_issuer]
            )
            await gone.aclose()

        self.run_async(run)

    def test_refresh_response_shape_failures_keep_rotated_refresh(self):
        shapes = (
            {"token_type": "Bearer"},
            {"access_token": "a", "token_type": 7},
            {"access_token": "a", "token_type": "Bearer", "status": 201},
        )
        for shape in shapes:
            with self.subTest(shape=shape):

                async def run(p, n, s, policy, target, now, shape=shape):
                    await self.pkce_grant(p, n, policy, target)
                    now[0] += 61
                    body = {
                        key: value for key, value in shape.items() if key != "status"
                    }

                    async def invalid(request):
                        return httpx.Response(
                            shape.get("status", 200),
                            json={**body, "refresh_token": "ROTATED"},
                        )

                    n.token_hook = invalid
                    with self.assertRaises(AuthenticationFailure) as failure:
                        await p.prepare(target, OperationBudget.after(5))
                    self.assertEqual(failure.exception.code, "provider_failed")
                    record = next(iter(s.records.values()))
                    self.assertEqual(
                        (
                            record.status,
                            record.token.access_token,
                            record.token.refresh_token,
                        ),
                        ("active", None, "ROTATED"),
                    )

                self.run_async(run)

    def test_rejected_token_is_marked_before_a_failing_renewal(self):
        for flow in ("client_credentials", "authorization_code_pkce"):
            with self.subTest(flow=flow):

                async def run(p, n, s, policy, target, now, flow=flow):
                    if flow == "client_credentials":
                        first = await p.prepare(target, OperationBudget.after(5))
                    else:
                        first = await self.pkce_grant(p, n, policy, target)

                    async def unavailable(request):
                        return httpx.Response(503)

                    n.token_hook = unavailable
                    challenge = AuthChallenge(
                        401,
                        {"www-authenticate": "Bearer"},
                        RESOURCE,
                        first.credential.identity,
                        True,
                    )
                    with self.assertRaises(AuthenticationFailure):
                        await p.challenge(self.unbound(), challenge)
                    self.assertIsNone(next(iter(s.records.values())).token.access_token)
                    with self.assertRaises(AuthenticationFailure):
                        await p.credential(self.unbound())

                self.run_async(run)

        async def discovery_outage(p, n, s, policy, target, now):
            # Discovery fails before any exchange: the mark must already hold.
            first = await p.prepare(target, OperationBudget.after(5))

            async def outage(request):
                if request.method == "GET":
                    return httpx.Response(503)
                return httpx.Response(
                    200, json={"access_token": "x", "token_type": "Bearer"}
                )

            await n.client.aclose()
            n.client = httpx.AsyncClient(
                transport=httpx.MockTransport(outage), trust_env=False
            )
            challenge = AuthChallenge(
                401,
                {"www-authenticate": "Bearer"},
                RESOURCE,
                first.credential.identity,
                True,
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.challenge(self.unbound(), challenge)
            self.assertEqual(failure.exception.code, "discovery_failed")
            self.assertEqual(n.tokens, [n.tokens[0]])
            self.assertIsNone(next(iter(s.records.values())).token.access_token)

        self.run_async(discovery_outage)

    def test_plain_403_on_replay_is_operational_and_keeps_rpc_error(self):
        from agenthooksprotocol.runtime import ProtocolError

        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            message = intercept_request()
            sent = []

            async def deliver(request):
                sent.append(request)
                if len(sent) == 1:
                    return httpx.Response(401, headers={"www-authenticate": "Bearer"})
                return httpx.Response(
                    403,
                    json={
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {"code": -32001, "message": "forbidden"},
                    },
                )

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(deliver)
            ) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE,
                    backend={"id": "backend"},
                    client=client,
                    auth_provider=RoutingAuthProvider(discover=p, namespace="tenant"),
                )
                tokens = len(n.tokens)
                with self.assertRaises(ProtocolError) as failure:
                    await transport.request(message)
            self.assertNotIsInstance(failure.exception, AuthenticationFailure)
            self.assertEqual(getattr(failure.exception, "code", None), -32001)
            self.assertEqual(len(sent), 2)
            # Only the first 401 reached challenge handling.
            self.assertEqual(len(n.tokens), tokens + 1)

        self.run_async(run)

    def test_form_encoded_refresh_body_keeps_rotated_refresh(self):
        for kind in ("application/x-www-form-urlencoded", "text/plain; charset=utf-8"):
            with self.subTest(kind=kind):

                async def run(p, n, s, policy, target, now, kind=kind):
                    await self.pkce_grant(p, n, policy, target)
                    now[0] += 61

                    async def form(request):
                        return httpx.Response(
                            200,
                            content=b"access_token=new&token_type=Bearer&refresh_token=ROTATED",
                            headers={"content-type": kind},
                        )

                    n.token_hook = form
                    with self.assertRaises(AuthenticationFailure) as failure:
                        await p.prepare(target, OperationBudget.after(5))
                    self.assertEqual(failure.exception.code, "provider_failed")
                    record = next(iter(s.records.values()))
                    self.assertEqual(
                        (
                            record.status,
                            record.token.access_token,
                            record.token.refresh_token,
                        ),
                        ("active", None, "ROTATED"),
                    )

                self.run_async(run)

    def test_sent_token_request_completes_and_commits_despite_caller_cancel(self):
        """A response body delayed past the caller's cancellation is still
        received over real HTTP and its rotated refresh token persisted."""
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        received, release = threading.Event(), threading.Event()
        posts = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                body = json.dumps(
                    {
                        "access_token": f"late-{len(posts)}",
                        "token_type": "Bearer",
                        "expires_in": 60,
                        "refresh_token": f"ROTATED-{len(posts)}",
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body[:5])
                self.wfile.flush()
                if posts.append(True) or len(posts) > 1:
                    # Delay the refresh body until after the caller cancels.
                    received.set()
                    release.wait(timeout=5)
                self.wfile.write(body[5:])

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        class Local(httpx.AsyncBaseTransport):
            def __init__(self):
                self.inner = httpx.AsyncHTTPTransport()

            async def handle_async_request(self, request):
                if request.method == "GET":
                    return httpx.Response(200, json=metadata(request))
                mapped = httpx.Request(
                    request.method,
                    f"http://127.0.0.1:{server.server_port}/token",
                    headers=request.headers,
                    stream=request.stream,
                    extensions=request.extensions,
                )
                return await self.inner.handle_async_request(mapped)

            async def aclose(self):
                await self.inner.aclose()

        async def run():
            release.clear()
            received.clear()
            posts.clear()
            n, s = Network(), Store()
            await n.client.aclose()
            n.client = httpx.AsyncClient(transport=Local(), trust_env=False)
            policy, now = Policy(), [1000.0]
            p = ManagedOAuthProvider(
                network=n,
                policy=policy,
                store=s,
                namespace="tenant",
                clock=lambda: now[0],
                expiry_skew=0,
                commit_timeout=5,
            )
            target = AuthTarget("tenant", "backend", RESOURCE, "event", None)
            try:
                await p.prepare(target, OperationBudget.after(5))
                now[0] += 120
                cancelled = []

                async def refresh():
                    try:
                        await p.prepare(target, OperationBudget.after(5))
                    except anyio.get_cancelled_exc_class():
                        cancelled.append(True)
                        raise

                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(refresh)
                    await anyio.to_thread.run_sync(lambda: received.wait(timeout=5))
                    tasks.cancel_scope.cancel()
                    release.set()
                self.assertEqual(cancelled, [True])
                self.assertEqual(len(posts), 2)
                record = next(iter(s.records.values()))
                self.assertEqual(
                    (
                        record.status,
                        record.token.access_token,
                        record.token.refresh_token,
                    ),
                    ("active", "late-1", "ROTATED-1"),
                )
            finally:
                release.set()
                await n.client.aclose()

        try:
            for backend in ("asyncio", "trio"):
                with self.subTest(backend=backend):
                    anyio.run(run, backend=backend)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_stalled_connect_is_cancelled_promptly_before_the_request_is_sent(self):
        import socket
        import time

        # Accepts TCP but never answers the TLS handshake: nothing is sent.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]

        class Stalled(httpx.AsyncBaseTransport):
            def __init__(self):
                self.inner = httpx.AsyncHTTPTransport()

            async def handle_async_request(self, request):
                if request.method == "GET":
                    return httpx.Response(200, json=metadata(request))
                mapped = httpx.Request(
                    request.method,
                    f"https://127.0.0.1:{port}/token",
                    headers=request.headers,
                    stream=request.stream,
                    extensions=request.extensions,
                )
                return await self.inner.handle_async_request(mapped)

            async def aclose(self):
                await self.inner.aclose()

        async def run():
            n, s = Network(), Store()
            first = n.client
            policy, now = Policy(), [1000.0]
            p = ManagedOAuthProvider(
                network=n,
                policy=policy,
                store=s,
                namespace="tenant",
                clock=lambda: now[0],
                expiry_skew=0,
            )
            target = AuthTarget("tenant", "backend", RESOURCE, "event", None)
            try:
                await p.prepare(target, OperationBudget.after(5))
                old = next(iter(s.records.values())).token
                n.client = httpx.AsyncClient(transport=Stalled(), trust_env=False)
                now[0] += 61
                started = time.monotonic()
                with anyio.move_on_after(0.3):
                    await p.prepare(target, OperationBudget.after(5))
                self.assertLess(time.monotonic() - started, 2)
                record = next(iter(s.records.values()))
                self.assertEqual((record.status, record.token), ("active", old))
            finally:
                await first.aclose()
                await n.client.aclose()

        try:
            for backend in ("asyncio", "trio"):
                with self.subTest(backend=backend):
                    anyio.run(run, backend=backend)
        finally:
            listener.close()


LIFECYCLE_TESTS = {
    "cached-token-metadata-outage": "test_endpoint_and_capability_rotation_renews_outside_grant_lock_with_current_secret",
    "unbound-preemptive-unsafe-delivery": "test_fresh_provider_uses_persistent_binding_offline_and_sends_upfront",
    "unbound-lookup-anonymous-fallback": "test_unbound_lookup_is_anonymous_only_on_store_miss_or_policy_refusal",
    "unbound-lookup-refreshes-expired-token": "test_unbound_lookup_refreshes_expired_token_with_cached_metadata",
    "refresh-unknown-expiry-rotation": "test_unknown_expiry_narrowed_scopes_initial_and_refresh",
    "transient-refresh-failure": "test_uncertain_refresh_preserves_material_and_retry_can_recover",
    "refresh-invalid-grant-drops-tokens": "test_refresh_invalid_grant_drops_both_tokens",
    "refresh-invalid-grant-stale-does-not-wipe": "test_refresh_invalid_grant_for_replaced_record_keeps_newer_record",
    "token-validation-failure-clears-in-flight": "test_invalid_token_response_clears_in_flight_and_keeps_only_refresh_rotation",
    "client-credentials-transient-reissue": "test_cc_without_refresh_reissues_after_transient_using_current_secret",
    "delivery-never-creates-pending-login": "test_dispatch_does_not_create_pending_and_host_prepare_cancel_is_separate",
    "pending-login-fixed-lifetime": "test_pending_lifetime_is_fixed_and_survives_creating_prepare",
    "pending-login-cross-process-completion": "test_pending_login_completes_from_another_process_after_creator_cancelled",
    "pending-login-reuse": "test_pending_reuse_is_independent_of_caller_deadline",
    "pending-login-supersede": "test_pending_supersede_requests_scope_union_and_old_callback_fails",
    "pending-login-supersede-scope-union": "test_pending_supersede_requests_scope_union_and_old_callback_fails",
    "pending-login-end-states": "test_pending_login_ends_once_by_completion_cancel_denial_or_expiry",
    "metadata-and-secret-rotation": "test_secret_rotation_is_runtime_only_for_refresh_and_confidential_pkce_completion",
    "scope-ceiling-widening-keeps-grant": "test_widening_allowed_ceiling_keeps_existing_grant",
    "insufficient-scope-step-up": "test_cc_403_allowed_stepup_reissues_and_forbidden_scope_is_denied",
    "step-up-requirement-operation-scoped": "test_pkce_stepup_round_trip_shared_grant_and_operation_scoped_requirement",
    "step-up-required-scopes-round-trip": "test_pkce_stepup_round_trip_shared_grant_and_operation_scoped_requirement",
    "challenged-replay-once": "test_challenged_replay_once_for_request_methods_only",
    "configured-preset-no-protected-resource-metadata": "test_explicit_preset_skips_protected_resource_metadata",
    "explicit-shared-grant": "test_pkce_stepup_round_trip_shared_grant_and_operation_scoped_requirement",
    "invalid-callback-does-not-consume": "test_pkce_complete_wrong_state_verifier_and_replay",
    "loopback-redirect": "test_literal_loopback_pkce_redirects_complete_but_remote_http_is_rejected",
    "narrowed-refresh-scope-inheritance": "test_narrowed_refresh_omitted_scope_inherits_previous_grant",
    "scope-challenge-without-required-scope": "test_403_without_scope_needs_explicit_host_requirement",
    "refresh-broadening-scope-ignored": "test_refresh_broadening_scope_is_ignored_and_stays_usable",
    "extra-granted-scope-ignored": "test_extra_granted_scopes_are_ignored_without_token_storm",
    "scope-ceiling-narrowing-keeps-grant": "test_narrowing_ceiling_hides_scopes_only_at_use",
    "unreplayed-challenge-prepares-next-attempt": "test_unreplayed_challenge_prepares_the_next_attempt",
    "up-front-refresh-failure-no-anonymous-fallback": "test_up_front_refresh_failure_has_no_anonymous_fallback",
    "prepare-required-outside-ceiling-denied": "test_prepare_required_scopes_outside_ceiling_are_denied",
    "up-front-client-credentials-reacquire": "test_up_front_lookup_reacquires_client_credentials_with_persisted_metadata",
    "up-front-lookup-issuer-metadata-only": "test_up_front_lookup_fetches_only_issuer_metadata_when_missing",
    "known-binding-without-token-requires-login": "test_known_binding_without_token_requires_login_until_prepare",
    "challenge-renews-rejected-unexpired-token": "test_challenge_renews_rejected_unexpired_token",
    "step-up-keeps-previous-grant": "test_step_up_reacquisition_keeps_previous_grant",
    "stale-metadata-refetch-once": "test_stale_issuer_metadata_is_refetched_once",
    "ambiguous-renewal-failure-no-refetch": "test_ambiguous_renewal_failure_neither_refetches_nor_retries",
}

# Client registration ids map to test_oauth_registration.RegistrationLifecycleTests.
REGISTRATION_TESTS = {
    "registration-order-preregistered-cimd-dcr": "test_registration_order_preregistered_cimd_dcr",
    "dcr-preregistered-wins": "test_preregistered_client_wins_and_obsoletes_recorded_selection",
    "cimd-used-when-supported": "test_cimd_client_completes_as_public_client",
    "cimd-not-supported-falls-back-to-dcr": "test_cimd_unadvertised_or_non_true_support_uses_dcr",
    "cimd-redirect-mismatch-invalid-configuration": "test_cimd_redirect_mismatch_creates_no_login",
    "cimd-never-fetched-by-sdk": "test_cimd_document_url_is_never_requested",
    "cimd-client-credentials-not-used": "test_client_credentials_never_uses_cimd",
    "cimd-invalid-client-no-dcr-fallback": "test_cimd_invalid_client_is_configuration_without_dcr",
    "dcr-policy-disallows-registration": "test_dcr_requires_host_permission",
    "dcr-registration-endpoint-destination-policy": "test_registration_endpoint_destination_policy",
    "dcr-pkce-registers-only-in-prepare": "test_pkce_registers_only_in_prepare_cc_registers_anywhere",
    "dcr-registers-once-across-processes": "test_concurrent_processes_register_once",
    "dcr-registration-reused-across-grants": "test_registration_reused_across_bindings_and_partitions",
    "dcr-expired-secret-reregisters": "test_expired_or_unresolvable_secret_reregisters_before_token_request",
    "dcr-invalid-client-reregisters-once": "test_invalid_client_reregisters_once",
    "dcr-new-client-id-new-grant": "test_replacement_client_uses_new_grant_key",
    "dcr-secret-not-in-token-record": "test_client_secret_only_in_host_secret_store",
    "dcr-no-secret-hook-no-confidential-registration": "test_without_secret_hook_cc_dcr_unavailable_pkce_unaffected",
    "dcr-metadata-change-keeps-selection": "test_metadata_change_keeps_recorded_selection",
    "dcr-management-fields-not-persisted": "test_registration_management_fields_ignored",
    "dcr-initial-access-token-scoped": "test_initial_access_token_sent_only_to_its_issuer",
    "lookup-never-registers-pkce": "test_lookup_never_registers_pkce",
    "dcr-failed-marker-bounds-registration": "test_failed_marker_bounds_registration_until_backoff",
    "dcr-response-validation-invalid-configuration": "test_registration_response_validation_persists_nothing",
    "prepare-force-reregistration": "test_prepare_force_reregistration",
    "dcr-policy-change-reregisters": "test_policy_change_reregisters_with_new_digest",
    "dcr-replaced-secret-deleted": "test_replaced_or_deleted_registration_secret_is_deleted",
    "cc-registration-auto-repairs-after-backoff": "test_cc_auto_repairs_after_backoff",
    "cc-proactive-reregistration-before-expiry": "test_cc_proactive_reregistration_within_margin",
    "marker-blocks-only-registration": "test_marker_blocks_only_registration_requests",
    "stale-callback-does-not-delete-new-registration": "test_stale_callback_invalid_client_keeps_newer_registration",
    "registration-transient-failure-backs-off": "test_transient_registration_failures_back_off",
    "registration-retry-after-honoured": "test_retry_after_sets_next_attempt",
    "marker-update-atomic-across-processes": "test_marker_updates_are_atomic_under_lock",
    "proactive-reregistration-once-across-processes": "test_proactive_renewal_once_across_processes",
    "proactive-renewal-failure-keeps-current-registration": "test_proactive_renewal_failure_keeps_current_registration",
}


class LifecycleCoverageTests(unittest.TestCase):
    def test_every_lifecycle_id_maps_to_an_existing_native_test(self):
        from test_oauth_registration import RegistrationLifecycleTests

        ids = [entry["id"] for entry in FIXTURES["lifecycle"]]
        self.assertFalse(set(LIFECYCLE_TESTS) & set(REGISTRATION_TESTS))
        self.assertEqual(set(ids), set(LIFECYCLE_TESTS) | set(REGISTRATION_TESTS))
        for tests, names in (
            (ManagedOAuthRuntimeTests, LIFECYCLE_TESTS.values()),
            (RegistrationLifecycleTests, REGISTRATION_TESTS.values()),
        ):
            for name in names:
                self.assertTrue(callable(getattr(tests, name, None)), name)
