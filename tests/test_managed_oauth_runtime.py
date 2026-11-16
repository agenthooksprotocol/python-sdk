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
FIXTURES = json.loads((Path(__file__).parent / "fixtures/sdk-auth-lifecycle.json").read_text())


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
            return httpx.Response(200, json={
                "issuer": issuer, "token_endpoint": issuer + "/token",
                "authorization_endpoint": issuer + "/authorize",
                "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
                **self.metadata_overrides,
            })
        self.tokens.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json=self.responses.pop(0))


@unittest.skipUnless(
    importlib.util.find_spec("authlib"),
    "requires optional oauth extra",
)
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
                    self.assertEqual(parse_qs(request.content.decode())["resource"], [RESOURCE])
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
            self.assertTrue(all(b.deadline <= budget.deadline for b in n.budgets + policy.budgets))
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
            self.assertIsInstance(await p.prepare(target, OperationBudget.after(5)), Ready)
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
            self.assertIsInstance(await p.prepare(target, OperationBudget.after(5)), Ready)
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
            target = replace(target, typed_binding=OAuthBinding(
                ISSUER, RESOURCE, config.client_id, config.flow, config.scopes,
            ))
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
            with self.assertRaises(TimeoutError):
                await p.prepare(target, OperationBudget.after(0.05))
            self.assertEqual(next(iter(s.records.values())).status, "refreshing")
            self.assertFalse(n.client.is_closed)

        self.run_async(run)

    def test_expired_pending_login_cannot_exchange(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            login = await p.prepare(target, OperationBudget.after(5))
            state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
            now[0] = login.expires_at + 1
            with self.assertRaises(TimeoutError):
                await p.complete(
                    target,
                    login,
                    "https://host.test/callback?"
                    + urlencode({"state": state, "code": "old"}),
                    OperationBudget.after(5),
                )
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
                entered.set()
                await anyio.sleep_forever()

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
            self.assertIsInstance(await p.prepare(target, OperationBudget.after(5)), Ready)
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
                host = "resource.test" if "oauth-protected-resource" in self.path else "issuer.test"
                self.reply(metadata(httpx.Request("GET", "https://" + host + self.path)))

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/token":
                    forms.append(parse_qs(body.decode()))
                    self.reply({"access_token": "tls-access", "token_type": "Bearer"})
                    return
                message = json.loads(body)
                deliveries.append((message.get("id"), self.headers.get("Authorization")))
                if self.headers.get("Authorization") != "Bearer tls-access":
                    self.reply(status=401, headers={"WWW-Authenticate": "Bearer"})
                elif message.get("id") == "cancel":
                    blocked.set()
                    release.wait(timeout=5)
                    self.reply({"jsonrpc": "2.0", "id": "cancel", "result": {"protocolVersion": "draft", "effects": []}})
                elif message["method"] == "hooks/observe":
                    self.reply(status=204)
                else:
                    self.reply({"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "draft", "effects": []}})

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
                    headers=request.headers, stream=request.stream,
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
            managed = ManagedOAuthProvider(network=network, policy=Policy("authorization_code_pkce"), store=store, namespace="tls")
            target = AuthTarget("tls", "backend", RESOURCE, "event", None)
            router = RoutingAuthProvider(discover=managed, oauth=managed, namespace="tls")
            transport = AuthenticatedHTTPTransport(RESOURCE, backend={"id": "backend"}, auth_provider=router, client=network.client)
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
                await transport.notify({"jsonrpc": "2.0", "method": "hooks/observe", "params": {}})
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
                    self.assertTrue(await anyio.to_thread.run_sync(lambda: blocked.wait(timeout=3)))
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
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", cancellation)
                challenge = AuthChallenge(401, {}, RESOURCE, first.credential.identity, True)
                policy.configuration = replace(policy.configuration, client_id="replacement")
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
            for change in ({"client_id": "revoked-client"}, {"scopes": ()}):
                policy.configuration = replace(original, **change)
                with self.assertRaises(AuthenticationFailure):
                    await p.complete(target, login, callback, OperationBudget.after(5))
                self.assertFalse(n.tokens)
                self.assertEqual(next(iter(s.records.values())).status, "pending")
            self.assertEqual(len(calls), 2)
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
                raise httpx.ReadError("response lost after possible rotation", request=request)
            n.token_hook = uncertain
            for _ in range(2):
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.prepare(target, OperationBudget.after(5))
                self.assertEqual(failure.exception.recovery, "retry")
                self.assertEqual(next(iter(s.records.values())).token, old_token)
            self.assertEqual(len(n.tokens), 3)
            n.token_hook = None
            self.assertIsInstance(await p.prepare(target, OperationBudget.after(5)), Ready)
            self.assertEqual(n.tokens[-1]["refresh_token"], [old_token.refresh_token])
        self.run_async(run)

    async def complete_login(self, provider, target, login):
        state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
        return await provider.complete(
            target, login,
            "https://host.test/callback?" + urlencode({"state": state, "code": "valid"}),
            OperationBudget.after(5),
        )

    def test_unknown_expiry_narrowed_scopes_initial_and_refresh(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(policy.configuration, scopes=("read", "write"))
            async def token(request):
                return httpx.Response(200, json={
                    "access_token": f"unknown-{len(n.tokens)}", "token_type": "Bearer",
                    "refresh_token": f"rotated-{len(n.tokens)}", "scope": "read",
                })
            n.token_hook = token
            first = await p.prepare(target, OperationBudget.after(5))
            record = next(iter(s.records.values()))
            self.assertIsNone(record.token.expires_at)
            self.assertEqual(record.token.scopes, ("read",))
            now[0] += 100000
            self.assertEqual((await p.prepare(target, OperationBudget.after(5))).credential, first.credential)
            self.assertEqual(len(n.tokens), 1)
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                second = await p.challenge(context, AuthChallenge(401, {}, RESOURCE, first.credential.identity, True))
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
                scopes=("read", "write"), required_scopes=("write",),
            )
            async def token(request):
                initial = n.tokens[-1]["grant_type"] == ["authorization_code"]
                return httpx.Response(200, json={
                    "access_token": "initial" if initial else "narrowed",
                    "token_type": "Bearer", "refresh_token": "r1" if initial else "r2",
                    "scope": "read write" if initial else "read",
                    **({"expires_in": 60} if initial else {}),
                })
            n.token_hook = token
            await self.complete_login(p, target, await p.prepare(target, OperationBudget.after(5)))
            now[0] += 61
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.code, "interaction_required")
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
                scopes=("read", "write"), required_scopes=("write",),
            )
            async def token(request):
                return httpx.Response(200, json={
                    "access_token": "narrow", "token_type": "Bearer",
                    "refresh_token": "retain-rotation", "scope": "read",
                })
            n.token_hook = token
            login = await p.prepare(target, OperationBudget.after(5))
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            self.assertEqual(failure.exception.code, "interaction_required")
            token = next(iter(s.records.values())).token
            self.assertEqual(token.refresh_token, "retain-rotation")
            self.assertIsNone(token.expires_at)
            self.assertEqual(token.scopes, ("read",))
        self.run_async(run)

    def test_fresh_provider_uses_persistent_binding_offline_and_sends_upfront(self):
        async def run(p, n, s, policy, target, now):
            first = await p.prepare(target, OperationBudget.after(5))
            upload_target = replace(
                target, purpose="upload", destination=RESOURCE + "/upload",
                typed_binding=OAuthBinding(ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)),
            )
            upload_ready = await p.prepare(upload_target, OperationBudget.after(5))
            self.assertNotEqual(upload_ready.credential.token, first.credential.token)
            self.assertTrue(s.bindings)
            self.assertFalse(set(s.records) & set(s.bindings))
            request_count = len(n.requests)
            async def offline(url, purpose, budget):
                self.fail("cached valid credentials must not rediscover")
            n.authorize = offline
            fresh = ManagedOAuthProvider(network=n, policy=policy, store=s, namespace="tenant", clock=lambda: now[0])
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                credential = await fresh.credential(context)
            self.assertEqual(credential.token, first.credential.token)
            sent = []
            async def deliver(request):
                sent.append(request.headers.get("authorization"))
                if request.url.path.endswith("/upload"):
                    body = await request.aread()
                    return httpx.Response(201, json={"ref": "urn:uploaded:cached", "size": len(body), "sha256": hashlib.sha256(body).hexdigest()})
                return httpx.Response(204)
            async with httpx.AsyncClient(transport=httpx.MockTransport(deliver)) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE, backend={"id": "backend"}, client=client,
                    auth_provider=RoutingAuthProvider(discover=fresh, namespace="tenant"),
                )
                await transport.notify({"jsonrpc": "2.0", "method": "hooks/observe", "params": {}})
                receipt = await transport.upload(RESOURCE + "/upload", b"cached-upload")
                self.assertEqual(receipt.ref, "urn:uploaded:cached")
                await transport.aclose()
                self.assertFalse(client.is_closed)
            self.assertEqual(sent, ["Bearer " + first.credential.token, "Bearer " + upload_ready.credential.token])
            self.assertEqual(len(n.requests), request_count)
        self.run_async(run)

    def test_dispatch_does_not_create_pending_and_host_prepare_cancel_is_separate(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                self.assertIsNone(await p.credential(context))
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(context, AuthChallenge(401, {}, RESOURCE, None, True))
                self.assertEqual(failure.exception.code, "interaction_required")
            self.assertFalse(s.records)
            login = await p.prepare(target, OperationBudget.after(5))
            self.assertIsInstance(login, PendingLogin)
            with anyio.CancelScope() as scope:
                with self.assertRaises(AuthenticationFailure):
                    await p.credential(AuthContext({"id": "backend"}, None, RESOURCE, "event", scope))
            self.assertEqual(next(iter(s.records.values())).generation, login.generation)
            await p.cancel(target, login, OperationBudget.after(5))
            self.assertFalse(s.records)
            self.assertTrue(s.bindings)
            replacement = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(replacement.generation, login.generation)
        self.run_async(run)

    def test_secret_rotation_is_runtime_only_for_refresh_and_confidential_pkce_completion(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            policy.configuration = replace(policy.configuration, client_secret="replacement-secret")
            now[0] += 61
            await p.prepare(target, OperationBudget.after(5))
            request = [r for r, purpose in n.requests if purpose == "token"][-1]
            from base64 import b64decode
            self.assertEqual(b64decode(request.headers["authorization"].split()[1]), b"host-client:replacement-secret")
            for metadata in list(s.bindings.values()) + [r.metadata for r in s.records.values()]:
                self.assertIsNone(metadata.configuration.client_secret)
            await p.reset(target, OperationBudget.after(5))
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                client_secret="pkce-old", token_endpoint_auth_method="client_secret_basic",
            )
            login = await p.prepare(target, OperationBudget.after(5))
            policy.configuration = replace(policy.configuration, client_secret="pkce-current")
            await self.complete_login(p, target, login)
            request = [r for r, purpose in n.requests if purpose == "token"][-1]
            self.assertEqual(b64decode(request.headers["authorization"].split()[1]), b"host-client:pkce-current")
            for metadata in list(s.bindings.values()) + [r.metadata for r in s.records.values()]:
                self.assertIsNone(metadata.configuration.client_secret)
            self.assertNotIn("pkce-current", repr(s.records))
        self.run_async(run)

    def test_cc_403_allowed_stepup_reissues_and_forbidden_scope_is_denied(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(policy.configuration, allowed_scopes=("read", "write"))
            first = await p.prepare(target, OperationBudget.after(5))
            async def token(request):
                return httpx.Response(200, json={"access_token": "stepup", "token_type": "Bearer", "scope": "read write"})
            n.token_hook = token
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                challenge = AuthChallenge(403, {"www-authenticate": 'Bearer error="insufficient_scope", scope="write"'}, RESOURCE, first.credential.identity, True)
                credential = await p.challenge(context, challenge)
                self.assertEqual(credential.token, "stepup")
                self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
                self.assertEqual(set(n.tokens[-1]["scope"][0].split()), {"read", "write"})
                count = len(n.tokens)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(context, AuthChallenge(403, {"www-authenticate": 'Bearer error="insufficient_scope", scope="admin"'}, RESOURCE, credential.identity, True))
                self.assertEqual(failure.exception.code, "access_denied")
                self.assertEqual(len(n.tokens), count)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(context, AuthChallenge(403, {}, RESOURCE, credential.identity, True))
                self.assertEqual(failure.exception.code, "access_denied")
        self.run_async(run)

    def test_pkce_stepup_cancel_keeps_shared_narrow_grant_and_binding_requirements(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write"), grant_partition="same-principal",
            )
            upload = replace(
                target, purpose="upload", destination=RESOURCE + "/upload",
                typed_binding=OAuthBinding(ISSUER, RESOURCE, "host-client", "authorization_code_pkce", ("read",)),
            )
            approved_upload = [False]
            original_resource = policy.resource
            async def resource(selected, budget):
                if selected.purpose == "upload" and not approved_upload[0]:
                    raise AuthenticationFailure(code="access_denied")
                return await original_resource(selected, budget)
            policy.resource = resource
            first = await self.complete_login(p, target, await p.prepare(target, OperationBudget.after(5)))
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
                    await p.challenge(context, AuthChallenge(403, {"www-authenticate": 'Bearer error="insufficient_scope", scope="write"'}, RESOURCE, first.credential.identity, True))
                self.assertEqual(failure.exception.code, "interaction_required")
            login = await p.prepare(target, OperationBudget.after(5))
            self.assertIsInstance(login, PendingLogin)
            self.assertEqual(next(iter(s.records.values())).token.access_token, first.credential.token)
            self.assertEqual((await p.prepare(upload, OperationBudget.after(5))).credential.token, first.credential.token)
            await p.cancel(target, login, OperationBudget.after(5))
            self.assertEqual(next(iter(s.records.values())).status, "active")
            self.assertEqual((await p.prepare(upload, OperationBudget.after(5))).credential.token, first.credential.token)
            with anyio.CancelScope() as scope:
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.credential(AuthContext({"id": "backend"}, None, RESOURCE, "event", scope))
                self.assertEqual(failure.exception.code, "interaction_required")
            self.assertFalse(any(record.pending for record in s.records.values()))
            self.assertEqual(len(n.tokens), 1)
        self.run_async(run)

    def test_narrowed_refresh_omitted_scope_inherits_previous_grant(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(policy.configuration, scopes=("read", "write"))
            async def token(request):
                initial = n.tokens[-1]["grant_type"] == ["client_credentials"]
                return httpx.Response(200, json={
                    "access_token": "first" if initial else "refreshed",
                    "token_type": "Bearer", "refresh_token": "r1" if initial else "r2",
                    **({"scope": "read", "expires_in": 60} if initial else {}),
                })
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

    def test_pending_requested_and_required_scope_context_replaces_old_handle(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(
                Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write"),
            )
            budget = OperationBudget.after(5)
            first = await p.prepare(target, budget)
            self.assertEqual(await p.prepare(target, budget), first)
            policy.configuration = replace(policy.configuration, required_scopes=("read",))
            second = await p.prepare(target, budget)
            self.assertNotEqual(second.generation, first.generation)
            with self.assertRaises(AuthenticationFailure):
                await self.complete_login(p, target, first)
            self.assertFalse(n.tokens)
            policy.configuration = replace(policy.configuration, scopes=("read", "write"))
            third = await p.prepare(target, budget)
            self.assertNotEqual(third.generation, second.generation)
            self.assertEqual(set(parse_qs(urlsplit(third.authorization_url).query)["scope"][0].split()), {"read", "write"})
            with self.assertRaises(AuthenticationFailure):
                await self.complete_login(p, target, second)
            self.assertFalse(n.tokens)
            self.assertIsInstance(await self.complete_login(p, target, third), Ready)
        self.run_async(run)

    def test_pending_longer_budget_replaces_and_old_callback_cannot_complete(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            budget = OperationBudget.after(1)
            first = await p.prepare(target, budget)
            self.assertEqual(await p.prepare(target, budget), first)
            longer = OperationBudget.after(5)
            second = await p.prepare(target, longer)
            self.assertNotEqual(second.generation, first.generation)
            self.assertEqual(await p.prepare(target, longer), second)
            with self.assertRaises(AuthenticationFailure):
                await self.complete_login(p, target, first)
            self.assertFalse(n.tokens)
            self.assertIsInstance(await self.complete_login(p, target, second), Ready)
        self.run_async(run)

    def test_cancelled_original_host_scope_cannot_transfer_pending_ownership(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            with anyio.CancelScope() as owner:
                budget = OperationBudget.after(10, cancel_scope=owner)
                first = await p.prepare(target, budget)
                self.assertEqual(await p.prepare(target, budget), first)
                owner.cancel()
            second = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(second.generation, first.generation)
            with self.assertRaises(AuthenticationFailure):
                await self.complete_login(p, target, first)
            self.assertFalse(n.tokens)
            self.assertIsInstance(await self.complete_login(p, target, second), Ready)
        self.run_async(run)

    def test_cancelled_prepare_after_pending_store_commit_invalidates_handle(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = Policy("authorization_code_pkce").configuration
            entered = anyio.Event()
            unpublished = []
            async def commit_then_block(key, record):
                if record is not None and record.status == "pending":
                    s.records[key] = record
                    unpublished.append(record.generation)
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
            self.assertFalse(any(record.generation in unpublished for record in s.records.values()))
            s.cas_hook = None
            replacement = await p.prepare(target, OperationBudget.after(5))
            self.assertNotIn(replacement.generation, unpublished)
            self.assertIsInstance(await self.complete_login(p, target, replacement), Ready)
        self.run_async(run)

    def test_403_without_scope_needs_explicit_host_requirement(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(policy.configuration, allowed_scopes=("read", "write"))
            first = await p.prepare(target, OperationBudget.after(5))
            with anyio.CancelScope() as scope:
                context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                challenge = AuthChallenge(403, {"www-authenticate": 'Bearer error="insufficient_scope"'}, RESOURCE, first.credential.identity, True)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(context, challenge)
                self.assertEqual(failure.exception.code, "access_denied")
                self.assertEqual(len(n.tokens), 1)
                policy.configuration = replace(policy.configuration, required_scopes=("write",))
                async def token(request):
                    return httpx.Response(200, json={"access_token": "host-required", "token_type": "Bearer", "scope": "write"})
                n.token_hook = token
                credential = await p.challenge(context, challenge)
                self.assertEqual(credential.token, "host-required")
                self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
                self.assertIn("write", n.tokens[-1]["scope"][0].split())
        self.run_async(run)

    def test_scope_stepup_does_not_replay_effectful_notification(self):
        from agenthooksprotocol.runtime import ProtocolError
        async def run(p, n, s, policy, target, now):
            policy.configuration = replace(policy.configuration, allowed_scopes=("read", "write"))
            first = await p.prepare(target, OperationBudget.after(5))
            async def token(request):
                return httpx.Response(200, json={"access_token": "stepped", "token_type": "Bearer", "scope": "read write"})
            n.token_hook = token
            sent = []
            async def deliver(request):
                sent.append(request.headers.get("authorization"))
                if len(sent) == 1:
                    return httpx.Response(403, headers={"www-authenticate": 'Bearer error="insufficient_scope", scope="write"'})
                return httpx.Response(204)
            async with httpx.AsyncClient(transport=httpx.MockTransport(deliver)) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE, backend={"id": "backend"}, client=client,
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
                return httpx.Response(200, json={"access_token": "cc-first", "token_type": "Bearer", "expires_in": 60})
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
            policy.configuration = replace(policy.configuration, client_secret="current-secret")
            n.token_hook = initial
            self.assertIsInstance(await p.prepare(target, OperationBudget.after(5)), Ready)
            self.assertTrue(all(form["grant_type"] == ["client_credentials"] for form in n.tokens))
            from base64 import b64decode
            request = [r for r, purpose in n.requests if purpose == "token"][-1]
            self.assertEqual(b64decode(request.headers["authorization"].split()[1]), b"host-client:current-secret")
            self.assertFalse(any(record.pending for record in s.records.values()))
        self.run_async(run)

    def test_explicit_preset_skips_protected_resource_metadata(self):
        async def run(p, n, s, policy, target, now):
            target = replace(target, typed_binding=OAuthBinding(ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)))
            self.assertIsInstance(await p.prepare(target, OperationBudget.after(5)), Ready)
            metadata_requests = [request for request, purpose in n.requests if purpose == "metadata"]
            self.assertTrue(metadata_requests)
            self.assertTrue(all(request.url.host == "issuer.test" for request in metadata_requests))
            self.assertFalse(any("oauth-protected-resource" in str(request.url) for request in metadata_requests))
        self.run_async(run)

    def test_literal_loopback_pkce_redirects_complete_but_remote_http_is_rejected(self):
        async def run(p, n, s, policy, target, now):
            for redirect in ("http://127.0.0.1:8123/callback", "http://[::1]:8123/callback"):
                policy.configuration = replace(Policy("authorization_code_pkce").configuration, redirect_uri=redirect)
                login = await p.prepare(target, OperationBudget.after(5))
                state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
                ready = await p.complete(target, login, redirect + "?" + urlencode({"state": state, "code": "loopback"}), OperationBudget.after(5))
                self.assertIsInstance(ready, Ready)
                self.assertEqual(n.tokens[-1]["redirect_uri"], [redirect])
                await p.reset(target, OperationBudget.after(5), handle=ready.credential)
            policy.configuration = replace(policy.configuration, redirect_uri="http://remote.test/callback")
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
                        issuer=value["issuer"], client_id=value["client_id"], flow=value["flow"],
                        scopes=scopes, allowed_scopes=scopes,
                        redirect_uri="https://host.test/callback",
                        client_secret=value.get("client_secret"),
                        grant_partition=value.get("grant_partition"),
                    )
                    network = VectorNetwork(config, metadata_overrides=value.get("metadata"))
                    store = Store()
                    policy = VectorPolicy(config, value["resource"])
                    provider = ManagedOAuthProvider(network=network, policy=policy, store=store, namespace=value["namespace"])
                    target = AuthTarget(
                        value["namespace"], value["backend_id"], value["destination"], value["purpose"], None,
                        OAuthBinding(value["issuer"], value["resource"], value["client_id"], value["flow"], scopes),
                    )
                    try:
                        result = await provider.prepare(target, OperationBudget.after(5))
                        self.assertIsInstance(result, PendingLogin)
                        self.assertEqual(set(store.bindings), {vector["binding_key"]})
                        self.assertEqual(store.coordinated, [vector["grant_key"]])
                        self.assertEqual(set(store.records), {vector["grant_key"]})
                        self.assertEqual(result.key, vector["grant_key"])
                        self.assertTrue(network.requests)
                        self.assertTrue(all(request.method == "GET" for request, _ in network.requests))
                        self.assertFalse(any("oauth-protected-resource" in str(request.url) for request, _ in network.requests))
                        self.assertTrue(all(record.metadata.configuration.client_secret is None for record in store.records.values()))
                        self.assertTrue(all(metadata.configuration.client_secret is None for metadata in store.bindings.values()))
                    finally:
                        await network.client.aclose()
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_all_canonical_token_vectors_cross_http_store_and_dispatch(self):
        async def run():
            for vector in FIXTURES["token_responses"]:
                with self.subTest(vector=vector["id"]):
                    config = OAuthClientConfiguration(
                        issuer=ISSUER, client_id="host-client", flow="client_credentials",
                        scopes=tuple(vector["requested"]), allowed_scopes=tuple(vector["allowed"]),
                        required_scopes=tuple(vector["required"]),
                    )
                    responses = []
                    refreshing = vector.get("exchange") == "refresh"
                    if refreshing:
                        responses.append({
                            "access_token": "seed-access", "token_type": "Bearer",
                            "expires_in": 1, "refresh_token": "r1",
                            "scope": " ".join(vector["previous_granted"]),
                        })
                    responses.append(vector["response"])
                    network = VectorNetwork(config, responses)
                    store, policy, now = Store(), VectorPolicy(config, RESOURCE), [1000.0]
                    provider = ManagedOAuthProvider(network=network, policy=policy, store=store, namespace="vectors", clock=lambda: now[0], expiry_skew=0)
                    typed = OAuthBinding(ISSUER, RESOURCE, "host-client", "client_credentials", tuple(vector["requested"]))
                    target = AuthTarget("vectors", "backend", RESOURCE, "event", None, typed)
                    binding = {
                        "type": "oauth", "issuer": ISSUER, "resource": RESOURCE,
                        "clientId": "host-client", "flow": "client_credentials", "scopes": vector["requested"],
                    }
                    delivered = []
                    async def deliver(request):
                        delivered.append(request.headers.get("authorization"))
                        return httpx.Response(204)
                    try:
                        if refreshing:
                            await provider.prepare(target, OperationBudget.after(5))
                            now[0] += 2
                        async with httpx.AsyncClient(transport=httpx.MockTransport(deliver)) as client:
                            transport = AuthenticatedHTTPTransport(
                                RESOURCE, backend={"id": "backend", "authentication": binding}, client=client,
                                auth_provider=RoutingAuthProvider(oauth=provider, namespace="vectors"),
                            )
                            message = {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
                            if vector["accepted"] and vector["usable"]:
                                await transport.notify(message)
                                self.assertEqual(delivered, ["Bearer " + vector["response"]["access_token"]])
                            else:
                                with self.assertRaises(AuthenticationFailure) as failure:
                                    await transport.notify(message)
                                self.assertEqual(failure.exception.code, vector.get("error", "access_denied"))
                                self.assertEqual(delivered, [])
                            await transport.aclose()
                            self.assertFalse(client.is_closed)
                        self.assertEqual(len(store.records), 1)
                        record = next(iter(store.records.values()))
                        self.assertEqual(record.status, "active")
                        self.assertEqual(record.token.access_token, vector["response"]["access_token"])
                        if "granted" in vector:
                            self.assertEqual(set(record.token.scopes), set(vector["granted"]))
                        else:
                            self.assertEqual(set(record.token.scopes), set(vector["response"]["scope"].split()))
                        if vector.get("expiry") == "unknown":
                            self.assertIsNone(record.token.expires_at)
                        elif vector.get("expiry") == "known":
                            self.assertEqual(record.token.expires_at, now[0] + vector["response"]["expires_in"])
                        if vector["refresh_preserved"]:
                            self.assertEqual(record.token.refresh_token, vector["response"]["refresh_token"])
                        self.assertEqual(network.tokens[-1]["grant_type"], ["refresh_token" if refreshing else "client_credentials"])
                        if refreshing:
                            self.assertEqual(network.tokens[-1]["refresh_token"], ["r1"])
                            self.assertNotIn("scope", network.tokens[-1])
                        self.assertEqual(len(network.tokens), 2 if refreshing else 1)
                        self.assertFalse(network.responses)
                        self.assertTrue(store.coordinated)
                    finally:
                        await network.client.aclose()
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_other_task_cancels_budget_owner_during_http_rotation_commits_but_never_returns_ready(self):
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
                return httpx.Response(200, json={
                    "access_token": "committed-after-owner-cancel", "token_type": "Bearer",
                    "refresh_token": "rotated-after-owner-cancel", "scope": "read",
                })
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

    def test_endpoint_and_capability_rotation_renews_outside_grant_lock_with_current_secret(self):
        from base64 import b64decode
        async def run(p, n, s, policy, target, now):
            target = replace(target, typed_binding=OAuthBinding(ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)))
            state = {"outage": False, "rotated": False}
            metadata_urls, token_requests = [], []
            async def handle(request):
                if request.method == "GET":
                    self.assertFalse(any(lock.locked() for lock in s.locks.values()))
                    metadata_urls.append(str(request.url))
                    self.assertEqual(request.url.host, "issuer.test")
                    if state["outage"]:
                        return httpx.Response(503, text="issuer metadata unavailable")
                    return httpx.Response(200, json={
                        "issuer": ISSUER,
                        "token_endpoint": ISSUER + ("/rotated-token" if state["rotated"] else "/token"),
                        "grant_types_supported": ["client_credentials", "refresh_token"] + (["authorization_code"] if state["rotated"] else []),
                        "token_endpoint_auth_methods_supported": ["client_secret_basic"] + (["client_secret_post", "none"] if state["rotated"] else []),
                    })
                self.assertTrue(any(lock.locked() for lock in s.locks.values()))
                token_requests.append(request)
                n.tokens.append(parse_qs(request.content.decode()))
                return httpx.Response(200, json={
                    "access_token": f"endpoint-access-{len(token_requests)}", "token_type": "Bearer",
                    "expires_in": 60, "refresh_token": f"endpoint-refresh-{len(token_requests)}", "scope": "read",
                })
            await n.client.aclose()
            n.client = httpx.AsyncClient(transport=httpx.MockTransport(handle), trust_env=False)
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
            policy.configuration = replace(policy.configuration, client_secret="latest-endpoint-secret")
            now[0] += 61
            renewed = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(renewed.credential.token, first.credential.token)
            self.assertEqual(set(s.records), grant_keys)
            self.assertEqual(len(metadata_urls), 2)
            self.assertFalse(any("oauth-protected-resource" in url for url in metadata_urls))
            self.assertEqual(len(token_requests), 2)
            self.assertEqual(str(token_requests[-1].url), ISSUER + "/rotated-token")
            self.assertEqual(n.tokens[-1]["grant_type"], ["refresh_token"])
            self.assertEqual(n.tokens[-1]["refresh_token"], ["endpoint-refresh-1"])
            self.assertEqual(b64decode(token_requests[-1].headers["authorization"].split()[1]), b"host-client:latest-endpoint-secret")
            self.assertTrue(all(value.token_endpoint == ISSUER + "/rotated-token" for value in s.bindings.values()))
            self.assertTrue(all(value.configuration.client_secret is None for value in s.bindings.values()))
            self.assertFalse(any(lock.locked() for lock in s.locks.values()))
            self.assertFalse(n.client.is_closed)
        self.run_async(run)

    def test_managed_missing_backend_id_fails_before_http_or_store_identity(self):
        async def run(p, n, s, policy, target, now):
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(replace(target, backend_id=""), OperationBudget.after(5))
            self.assertEqual(failure.exception.code, "invalid_configuration")
            delivered = []
            async def deliver(request):
                delivered.append(request)
                return httpx.Response(204)
            binding = {
                "type": "oauth", "issuer": ISSUER, "resource": RESOURCE,
                "clientId": "host-client", "flow": "client_credentials", "scopes": ["read"],
            }
            async with httpx.AsyncClient(transport=httpx.MockTransport(deliver)) as client:
                transport = AuthenticatedHTTPTransport(
                    RESOURCE, backend={"authentication": binding}, client=client,
                    auth_provider=RoutingAuthProvider(oauth=p, namespace="tenant"),
                )
                with self.assertRaises(AuthenticationFailure) as failure:
                    await transport.notify({"jsonrpc": "2.0", "method": "hooks/observe", "params": {}})
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
