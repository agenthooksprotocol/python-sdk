"""Real host-boundary tests. Run: uv run --extra oauth python -m unittest discover -s tests -p test_managed_oauth_runtime.py."""

import hashlib
import importlib.util
import unittest
from base64 import urlsafe_b64encode
from contextlib import asynccontextmanager
from dataclasses import replace
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx

from agenthooksprotocol.auth import (
    AuthenticationFailure,
    AuthChallenge,
    AuthContext,
    AuthTarget,
    OAuthBinding,
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


class Store:
    """CAS alone writes records; competing-writer fault injection also holds guard.

    Await before commit preserves old state on cancellation, await after commit
    exercises ambiguous persistence. Locks never reenter; every callback runs
    under its key lock. Cancellation releases locks but does not restore tokens.
    """

    def __init__(self):
        self.records = {}
        self.locks = {}
        self.transitions = []
        self.cas_hook = None

    @asynccontextmanager
    async def coordinate(self, key, budget):
        budget.remaining()
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
        assert set(required_scopes).issubset(self.configuration.scopes)
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


@unittest.skipUnless(
    importlib.util.find_spec("authlib"), "requires optional oauth extra"
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
            self.assertTrue(all(b is budget for b in n.budgets + policy.budgets))
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

    def test_refresh_transient_retains_token_but_invalid_grant_rejects(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            old = next(iter(s.records.values())).token
            now[0] += 61

            async def transient(request):
                return httpx.Response(400, json={"error": "temporarily_unavailable"})

            n.token_hook = transient
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.recovery, "retry")
            record = next(iter(s.records.values()))
            self.assertEqual(record.status, "active")
            self.assertEqual(record.token, old)

            async def rejection(request):
                return httpx.Response(400, json={"error": "invalid_grant"})

            n.token_hook = rejection
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.code, "refresh_rejected")
            record = next(iter(s.records.values()))
            self.assertEqual(record.status, "rejected")
            self.assertIsNone(record.token)

        self.run_async(run)

    def test_cancel_network_leaves_reservation_until_explicit_reset(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
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
            self.assertEqual(next(iter(s.records.values())).status, "refreshing")
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertEqual(len(n.tokens), 2)
            await p.reset(target, OperationBudget.after(5))
            n.token_hook = None
            await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])

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
                self.assertIsNone(await p.credential(replace(context, binding=None)))
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

    def test_cancel_after_store_reservation_commit_blocks_reuse(self):
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
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(len(n.tokens), 1)

        self.run_async(run)

    @unittest.skipUnless(
        importlib.util.find_spec("trustme"),
        "ephemeral TLS test requires --with trustme",
    )
    def test_pkce_full_flow_over_verified_local_tls(self):
        import json
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
        forms = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, document):
                body = json.dumps(document).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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
                forms.append(
                    parse_qs(
                        self.rfile.read(int(self.headers["Content-Length"])).decode()
                    )
                )
                self.reply(
                    {
                        "access_token": "tls-access",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                )

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        async def run():
            network = Network()
            await network.client.aclose()
            network.client = httpx.AsyncClient(verify=client_context, trust_env=False)

            async def send(request, purpose, budget):
                self.assertIn((str(request.url), purpose), network.authorized)
                # Host-controlled DNS mapping preserves the logical policy URL;
                # the borrowed HTTPX client verifies the ephemeral localhost CA.
                url = request.url.copy_with(
                    scheme="https", host="localhost", port=server.server_port
                )
                mapped = httpx.Request(
                    request.method,
                    url,
                    headers={
                        "content-type": request.headers.get(
                            "content-type", "application/json"
                        )
                    },
                    content=request.content,
                )
                return await network.client.send(mapped, follow_redirects=False)

            network.send = send
            policy = Policy("authorization_code_pkce")
            provider = ManagedOAuthProvider(
                network=network, policy=policy, store=Store(), namespace="tls"
            )
            target = AuthTarget("tls", "backend", RESOURCE, "event", None)
            try:
                budget = OperationBudget.after(10)
                login = await provider.prepare(target, budget)
                state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
                ready = await provider.complete(
                    target,
                    login,
                    "https://host.test/callback?"
                    + urlencode({"state": state, "code": "tls-code"}),
                    budget,
                )
                self.assertEqual(ready.credential.token, "tls-access")
                self.assertEqual(forms[0]["resource"], [RESOURCE])
                self.assertEqual(forms[0]["grant_type"], ["authorization_code"])
                self.assertIn("code_verifier", forms[0])
                self.assertFalse(network.client.is_closed)
            finally:
                await network.client.aclose()

        try:
            anyio.run(run)
        finally:
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

    def test_challenge_rejects_changed_discovered_client_key(self):
        async def run(p, n, s, policy, target, now):
            first = await p.prepare(target, OperationBudget.after(5))
            with anyio.CancelScope() as cancellation:
                context = AuthContext(
                    {"id": "backend"}, None, RESOURCE, "event", cancellation
                )
                challenge = AuthChallenge(
                    401, {}, RESOURCE, first.credential.identity, True
                )
                original = policy.configuration
                for change in ({"client_id": "replacement"}, {"scopes": ("write",)}):
                    with self.subTest(change=change):
                        policy.configuration = replace(original, **change)
                        with self.assertRaises(AuthenticationFailure) as failure:
                            await p.challenge(context, challenge)
                        self.assertEqual(
                            failure.exception.code, "invalid_configuration"
                        )
                        self.assertEqual(len(n.tokens), 1)
                        self.assertEqual(len(s.records), 1)
                policy.configuration = original

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
            self.assertEqual(calls[-1], (RESOURCE, (ISSUER,), ("read",)))
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

    def test_uncertain_refresh_blocks_reuse_but_client_credentials_can_reacquire(self):
        async def run(p, n, s, policy, target, now):
            await p.prepare(target, OperationBudget.after(5))
            old_token = next(iter(s.records.values())).token
            now[0] += 61

            async def uncertain(request):
                raise httpx.ReadError(
                    "response lost after possible token rotation", request=request
                )

            n.token_hook = uncertain
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(target, OperationBudget.after(5))
            record = next(iter(s.records.values()))
            self.assertEqual(record.status, "refreshing")
            self.assertEqual(record.token, old_token)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertEqual(failure.exception.code, "interaction_required")
            self.assertEqual(len(n.tokens), 2)
            await p.reset(target, OperationBudget.after(5))
            # With no refresh token (or prior code exchange), CC has no one-use
            # credential to accidentally reuse after an uncertain request.
            with self.assertRaises(AuthenticationFailure):
                await p.prepare(target, OperationBudget.after(5))
            self.assertIsNone(next(iter(s.records.values())).token)
            n.token_hook = None
            ready = await p.prepare(target, OperationBudget.after(5))
            self.assertIsInstance(ready, Ready)
            self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
            self.assertEqual(len(n.tokens), 4)

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
