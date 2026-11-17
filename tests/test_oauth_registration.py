"""Client registration (pre-registered, CIMD, RFC 7591 DCR) at real host boundaries.

Source: agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json.
Every test runs under asyncio and Trio over HTTPX, the coordinated store and a
host secret store.
"""

import base64
from dataclasses import asdict, replace
from email.utils import formatdate
import json
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx
from test_managed_oauth_runtime import (
    FIXTURES,
    ISSUER,
    RESOURCE,
    Network,
    Policy,
    Store,
    metadata,
)

from agenthooksprotocol.auth import (
    AuthChallenge,
    AuthContext,
    AuthTarget,
    AuthenticationFailure,
)
from agenthooksprotocol.oauth import (
    ManagedOAuthProvider,
    OAuthClientConfiguration,
    OAuthClientMetadataDocument,
    OAuthDynamicRegistration,
    OAuthRecord,
    OAuthRegistration,
    OperationBudget,
    PendingLogin,
    Ready,
)

LOOPBACK = "http://127.0.0.1:8765/callback"
DOCUMENT = OAuthClientMetadataDocument(
    "https://adapter.example/oauth/client.json", (LOOPBACK,)
)
DCR = OAuthDynamicRegistration("Example Adapter")
PKCE = "authorization_code_pkce"


class Secrets:
    """Host secret store: fresh references, resolution and deletion log."""

    def __init__(self):
        self.values, self.stored, self.deleted = {}, [], []

    async def store(self, value, budget):
        budget.remaining()
        reference = f"ref-{len(self.stored) + 1}"
        self.stored.append(reference)
        self.values[reference] = value
        return reference

    async def resolve(self, reference, budget):
        budget.remaining()
        return self.values.get(reference)

    async def delete(self, reference, budget):
        self.deleted.append(reference)
        self.values.pop(reference, None)


def token_client(request):
    form = parse_qs(request.content.decode())
    if "authorization" in request.headers:
        pair = base64.b64decode(request.headers["authorization"].split()[1]).decode()
        return pair.split(":")[0]
    return form.get("client_id", [None])[0]


class RegNetwork(Network):
    """Issuer metadata per host, a registration endpoint and token endpoint."""

    def __init__(self, **overrides):
        self.overrides = overrides
        self.registrations = []
        self.register_hook = None
        self.register_gate = None
        self.token_clients = []
        super().__init__()

    async def handle(self, request):
        host = request.url.host
        if request.method == "GET" and host == "other.test":
            return httpx.Response(
                200,
                json={
                    "resource": "https://other.test/api",
                    "authorization_servers": ["https://issuer2.test"],
                },
            )
        if request.method == "GET" and host != "resource.test":
            issuer = "https://" + host
            body = {
                **metadata(request),
                "issuer": issuer,
                "token_endpoint": issuer + "/token",
                "authorization_endpoint": issuer + "/authorize",
                "registration_endpoint": issuer + "/register",
                **self.overrides,
            }
            return httpx.Response(
                200, json={k: v for k, v in body.items() if v is not None}
            )
        if request.method == "POST" and request.url.path == "/register":
            if self.register_gate is not None:
                await self.register_gate(request)
            body = json.loads(request.content)
            self.registrations.append((body, dict(request.headers), str(request.url)))
            if self.register_hook is not None:
                return await self.register_hook(body)
            count = len(self.registrations)
            issued = {"client_id": f"dcr-{count}"}
            if body["token_endpoint_auth_method"] != "none":
                issued["client_secret"] = f"dcr-secret-{count}"
            return httpx.Response(201, json=issued)
        if request.method == "POST":
            self.token_clients.append(token_client(request))
        return await super().handle(request)


def rejecting(status, **json_body):
    async def hook(body):
        return httpx.Response(status, json=json_body or None)

    return hook


def issuing(env=None, lifetime=None, **extra):
    """Registration responses with per-call client ids and extra members;
    `lifetime` sets client_secret_expires_at relative to the test clock."""
    count = [0]

    async def hook(body):
        count[0] += 1
        issued = {"client_id": f"dcr-{count[0]}", **extra}
        if lifetime is not None:
            issued["client_secret_expires_at"] = int(env.now[0] + lifetime)
        if body["token_endpoint_auth_method"] != "none":
            issued["client_secret"] = f"dcr-secret-{count[0]}"
        return httpx.Response(201, json=issued)

    return hook


class Env:
    def __init__(self, test, flow, overrides, secret_store):
        self.test = test
        self.n = RegNetwork(**overrides)
        self.s = Store()
        self.secrets = secret_store
        self.policy = Policy(flow)
        changes = dict(
            client_id="",
            client_secret=None,
            token_endpoint_auth_method="none",
            dynamic_registration=DCR,
        )
        if flow == PKCE:
            changes["redirect_uri"] = LOOPBACK
        self.policy.configuration = replace(self.policy.configuration, **changes)
        self.now = [1000.0]
        self.target = AuthTarget("tenant", "backend", RESOURCE, "event", None)
        self.p = self.provider()

    def provider(self, **options):
        return ManagedOAuthProvider(
            network=self.n,
            store=self.s,
            policy=self.policy,
            namespace="tenant",
            clock=lambda: self.now[0],
            expiry_skew=0,
            commit_timeout=5,
            secret_store=self.secrets,
            **options,
        )

    def configure(self, **changes):
        self.policy.configuration = replace(self.policy.configuration, **changes)

    def registration(self):
        found = [r for r in self.s.records.values() if isinstance(r, OAuthRegistration)]
        assert len(found) <= 1, found
        return found[0] if found else None

    def grants(self):
        return {
            key: r for key, r in self.s.records.items() if isinstance(r, OAuthRecord)
        }

    def binding(self, target=None):
        from agenthooksprotocol._oauth_types import binding_key

        return self.s.bindings.get(binding_key(target or self.target))

    def dump(self):
        return repr(
            [asdict(r) for r in self.s.records.values()]
            + [asdict(m) for m in self.s.bindings.values()]
        )

    async def prepare(self, target=None, **options):
        return await self.p.prepare(
            target or self.target, OperationBudget.after(5), **options
        )

    async def complete(self, login, target=None, provider=None):
        state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
        callback = LOOPBACK + "?" + urlencode({"state": state, "code": "code"})
        return await (provider or self.p).complete(
            target or self.target, login, callback, OperationBudget.after(5)
        )

    async def login(self, target=None):
        login = await self.prepare(target)
        self.test.assertIsInstance(login, PendingLogin)
        return await self.complete(login, target)

    def context(self, backend="backend"):
        return AuthContext(
            {"id": backend}, None, RESOURCE, "event", anyio.CancelScope()
        )

    async def lookup(self, provider=None):
        return await (provider or self.p).credential(self.context())

    async def challenge(self, provider=None):
        return await (provider or self.p).challenge(
            self.context(), AuthChallenge(401, {}, RESOURCE, None, True)
        )


def reject_client(env, client):
    """Token endpoint rejecting one client with invalid_client."""

    async def hook(request):
        if token_client(request) == client:
            return httpx.Response(401, json={"error": "invalid_client"})
        return httpx.Response(
            200,
            json={
                "access_token": f"access-{len(env.n.tokens)}",
                "token_type": "Bearer",
                "expires_in": 60,
                "scope": "read",
            },
        )

    return hook


def login_url(env):
    return next(
        u for u, p in env.n.authorized if p == "authorization" and "state=" in u
    )


def client_of(login):
    return parse_qs(urlsplit(login.authorization_url).query)["client_id"][0]


class RegistrationLifecycleTests(unittest.TestCase):
    def run_env(self, test, flow="client_credentials", overrides=None, secrets=True):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):

                async def run():
                    env = Env(
                        self, flow, overrides or {}, Secrets() if secrets else None
                    )
                    try:
                        await test(env)
                    finally:
                        await env.n.client.aclose()

                anyio.run(run, backend=backend)

    async def fails(self, code, operation):
        with self.assertRaises(AuthenticationFailure) as failure:
            await operation
        self.assertEqual(failure.exception.code, code)
        return failure.exception

    # Selection order -----------------------------------------------------

    def test_client_selection_vectors_cross_http_store_and_policy(self):
        for row in FIXTURES["client_selection"]:
            value, expect = row["input"], row["expect"]
            overrides = {"registration_endpoint": None, **value["as_metadata"]}

            async def run(env, value=value, expect=expect):
                cimd = value["cimd"]
                env.configure(
                    client_id=value["preregistered_client_id"] or "",
                    flow=value["flow"],
                    redirect_uri=value["redirect"],
                    client_metadata_document=OAuthClientMetadataDocument(
                        cimd["url"], tuple(cimd["redirect_uris"])
                    )
                    if cimd
                    else None,
                    dynamic_registration=DCR if value["dcr_permitted"] else None,
                )
                if "error" in expect:
                    await self.fails(expect["error"], env.prepare())
                    self.assertFalse(env.n.registrations)
                    self.assertFalse(any(r.pending for r in env.grants().values()))
                    return
                result = await env.prepare()
                if expect["source"] == "dcr":
                    self.assertEqual(len(env.n.registrations), 1)
                    self.assertEqual(
                        env.n.registrations[0][0]["token_endpoint_auth_method"],
                        expect["token_endpoint_auth_method"],
                    )
                    client = "dcr-1"
                else:
                    self.assertFalse(env.n.registrations)
                    self.assertIsNone(env.registration())
                    client = expect["client_id"]
                if value["flow"] == PKCE:
                    self.assertEqual(client_of(result), client)
                else:
                    self.assertIsInstance(result, Ready)
                    self.assertEqual(env.n.token_clients, [client])
                self.assertEqual(env.binding().client_source, expect["source"])

            with self.subTest(row["id"]):
                self.run_env(run, value["flow"], overrides, value["secret_hook"])

    def test_registration_order_preregistered_cimd_dcr(self):
        async def run(env):
            env.configure(client_metadata_document=DOCUMENT)
            env.n.overrides["client_id_metadata_document_supported"] = True
            self.assertEqual(client_of(await env.prepare()), DOCUMENT.url)
            env.n.overrides["client_id_metadata_document_supported"] = False
            env.configure(client_metadata_document=None)
            self.assertEqual(client_of(await env.prepare()), "dcr-1")
            env.configure(client_id="host-client")
            self.assertEqual(client_of(await env.prepare()), "host-client")
            self.assertEqual(len(env.n.registrations), 1)
            env.configure(client_id="", dynamic_registration=None)
            await self.fails("credential_unavailable", env.prepare())

        self.run_env(run, PKCE)

    def test_preregistered_client_wins_and_obsoletes_recorded_selection(self):
        async def run(env):
            first = await env.prepare()
            self.assertEqual(env.n.token_clients, ["dcr-1"])
            env.configure(
                client_id="host-client",
                client_secret="host-secret",
                token_endpoint_auth_method="client_secret_basic",
            )
            second = await env.prepare()
            self.assertEqual(env.n.token_clients, ["dcr-1", "host-client"])
            self.assertNotEqual(first.credential.token, second.credential.token)
            self.assertEqual(len(env.n.registrations), 1)
            self.assertEqual(env.binding().client_source, "preregistered")
            self.assertEqual(len(env.grants()), 2)

        self.run_env(run)

    # Client ID Metadata Documents -----------------------------------------

    def test_cimd_client_completes_as_public_client(self):
        async def run(env):
            env.configure(client_metadata_document=DOCUMENT, dynamic_registration=None)
            login = await env.prepare()
            self.assertEqual(client_of(login), DOCUMENT.url)
            self.assertIsInstance(await env.complete(login), Ready)
            request = next(r for r, purpose in env.n.requests if purpose == "token")
            self.assertNotIn("authorization", request.headers)
            self.assertEqual(env.n.tokens[0]["client_id"], [DOCUMENT.url])
            self.assertNotIn("client_secret", env.n.tokens[0])
            self.assertIsNone(env.registration())
            self.assertFalse(env.secrets.stored)
            self.assertEqual(env.binding().client_source, "cimd")

        self.run_env(run, PKCE, {"client_id_metadata_document_supported": True})

    def test_cimd_document_url_is_never_requested(self):
        async def run(env):
            env.configure(client_metadata_document=DOCUMENT)
            await env.login()
            env.now[0] += 61
            self.assertIsNotNone(await env.lookup())
            touched = [str(r.url) for r, _ in env.n.requests] + [
                url for url, _ in env.n.authorized
            ]
            self.assertTrue(touched)
            hosts = {urlsplit(url).hostname for url in touched}
            self.assertNotIn(urlsplit(DOCUMENT.url).hostname, hosts)
            self.assertIn("adapter.example", login_url(env))

        self.run_env(run, PKCE, {"client_id_metadata_document_supported": True})

    def test_cimd_unadvertised_or_non_true_support_uses_dcr(self):
        for supported in (None, "true", 1, False):

            async def run(env):
                env.configure(client_metadata_document=DOCUMENT)
                self.assertEqual(client_of(await env.prepare()), "dcr-1")
                self.assertEqual(env.binding().client_source, "dcr")

            with self.subTest(supported=supported):
                self.run_env(
                    run, PKCE, {"client_id_metadata_document_supported": supported}
                )

    def test_cimd_redirect_mismatch_creates_no_login(self):
        async def run(env):
            env.configure(
                client_metadata_document=replace(
                    DOCUMENT, redirect_uris=("http://127.0.0.1:9999/callback",)
                )
            )
            await self.fails("invalid_configuration", env.prepare())
            self.assertFalse(env.grants())
            self.assertFalse(env.n.registrations)
            self.assertFalse([u for u, _ in env.n.authorized if "state=" in u])

        self.run_env(run, PKCE, {"client_id_metadata_document_supported": True})

    def test_client_credentials_never_uses_cimd(self):
        async def run(env):
            env.configure(client_metadata_document=DOCUMENT)
            await env.prepare()
            self.assertEqual(env.n.token_clients, ["dcr-1"])
            self.assertEqual(
                env.n.registrations[0][0]["token_endpoint_auth_method"],
                "client_secret_basic",
            )
            self.assertEqual(env.binding().client_source, "dcr")
            env.s.records.clear()
            env.s.bindings.clear()
            env.configure(dynamic_registration=None)
            await self.fails("credential_unavailable", env.prepare())
            self.assertEqual(len(env.n.registrations), 1)

        self.run_env(run, overrides={"client_id_metadata_document_supported": True})

    def test_cimd_invalid_client_is_configuration_without_dcr(self):
        async def run(env):
            env.configure(client_metadata_document=DOCUMENT)

            async def invalid_client(request):
                return httpx.Response(401, json={"error": "invalid_client"})

            env.n.token_hook = invalid_client
            await self.fails("invalid_configuration", env.login())
            login = await env.prepare()
            state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
            callback = (
                LOOPBACK + "?" + urlencode({"state": state, "error": "invalid_client"})
            )
            await self.fails(
                "invalid_configuration",
                env.p.complete(env.target, login, callback, OperationBudget.after(5)),
            )
            self.assertFalse(env.n.registrations)

        self.run_env(run, PKCE, {"client_id_metadata_document_supported": True})

    # DCR eligibility -----------------------------------------------------

    def test_dcr_requires_host_permission(self):
        for flow in (PKCE, "client_credentials"):

            async def run(env):
                env.configure(dynamic_registration=None)
                await self.fails("credential_unavailable", env.prepare())
                await self.fails("credential_unavailable", env.challenge())
                self.assertFalse(env.n.registrations)
                self.assertFalse(env.s.records)

            with self.subTest(flow=flow):
                self.run_env(run, flow)

    def test_registration_endpoint_destination_policy(self):
        async def insecure(env):
            env.n.overrides["registration_endpoint"] = "http://issuer.test/register"
            await self.fails("untrusted_destination", env.prepare())
            self.assertFalse(env.n.registrations)

        async def refused(env):
            authorize = env.n.authorize

            async def policy(url, purpose, budget):
                if purpose == "registration":
                    raise AuthenticationFailure(code="untrusted_destination")
                await authorize(url, purpose, budget)

            env.n.authorize = policy
            await self.fails("untrusted_destination", env.prepare())
            self.assertFalse(env.n.registrations)

        async def redirected(env):
            async def hook(body):
                return httpx.Response(307, headers={"location": "https://evil.test/r"})

            env.n.register_hook = hook
            await self.fails("untrusted_destination", env.prepare())
            self.assertEqual(len(env.n.registrations), 1)
            self.assertFalse(any("evil.test" in str(r.url) for r, _ in env.n.requests))
            self.assertEqual(env.registration().attempts, 1)

        for test in (insecure, refused, redirected):
            with self.subTest(test.__name__):
                self.run_env(test)

    def test_pkce_registers_only_in_prepare_cc_registers_anywhere(self):
        async def pkce(env):
            await self.fails("interaction_required", env.challenge())
            self.assertIsNone(await env.lookup())
            self.assertFalse(env.n.registrations)
            self.assertIsInstance(await env.prepare(), PendingLogin)
            self.assertEqual(len(env.n.registrations), 1)

        async def cc(env):
            self.assertIsNotNone(await env.challenge())
            self.assertEqual(len(env.n.registrations), 1)
            env.configure(dynamic_registration=OAuthDynamicRegistration("Renamed"))
            env.now[0] += 61
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2"])

        self.run_env(pkce, PKCE)
        self.run_env(cc)

    def test_without_secret_hook_cc_dcr_unavailable_pkce_unaffected(self):
        async def cc(env):
            await self.fails("credential_unavailable", env.prepare())
            await self.fails("credential_unavailable", env.challenge())
            self.assertFalse(env.n.registrations)

        async def pkce(env):
            self.assertEqual(client_of(await env.prepare()), "dcr-1")

        self.run_env(cc, secrets=False)
        self.run_env(pkce, PKCE, secrets=False)

    # Registration requests and records -----------------------------------

    def test_registration_response_vectors_cross_http_and_store(self):
        for row in FIXTURES["registration_responses"]:

            async def run(env, row=row):
                env.now[0] = row["now"]

                async def hook(body):
                    if row["response"] is None:
                        headers = (
                            {"location": "https://elsewhere.test/"}
                            if 300 <= row["status"] < 400
                            else {}
                        )
                        return httpx.Response(row["status"], headers=headers)
                    return httpx.Response(row["status"], json=row["response"])

                env.n.register_hook = hook
                expect = row["expect"]
                if not expect["accepted"]:
                    await self.fails(expect["error"], env.prepare())
                    self.assertEqual(env.n.registrations[0][0], row["request"])
                    self.assertIsNone(env.registration().client_id)
                    self.assertFalse(env.secrets.stored)
                    self.assertFalse(env.grants())
                    return
                await env.prepare()
                self.assertEqual(env.n.registrations[0][0], row["request"])
                record = env.registration()
                self.assertEqual(record.client_id, expect["record"]["client_id"])
                self.assertEqual(
                    record.client_secret_expires_at,
                    expect["record"]["client_secret_expires_at"],
                )
                self.assertEqual(
                    record.secret_ref is not None, expect["record"]["secret_ref"]
                )
                if record.secret_ref is not None:
                    self.assertEqual(
                        env.secrets.values[record.secret_ref],
                        row["response"]["client_secret"],
                    )
                for forbidden in (
                    "not-a-real-secret",
                    "registration_access_token",
                    "registration_client_uri",
                ):
                    self.assertNotIn(forbidden, env.dump())

            with self.subTest(row["id"]):
                self.run_env(run, row["flow"])

    def test_registration_response_validation_persists_nothing(self):
        for response in (
            {"client_id": "dcr", "client_secret": "not-a-real-secret"},
            {"client_id": "dcr", "redirect_uris": ["https://evil.example/cb"]},
            {"client_id": "dcr", "token_endpoint_auth_method": "client_secret_basic"},
        ):

            async def run(env, response=response):
                async def hook(body):
                    return httpx.Response(201, json=response)

                env.n.register_hook = hook
                failure = await self.fails("invalid_configuration", env.prepare())
                self.assertEqual(failure.recovery, "configure")  # never retry
                self.assertEqual(len(env.n.registrations), 1)
                self.assertIsNone(env.registration().client_id)
                self.assertFalse(env.grants())
                self.assertNotIn("not-a-real-secret", env.dump())

            with self.subTest(response=response):
                self.run_env(run, PKCE)

    def test_registration_management_fields_ignored(self):
        async def run(env):
            env.n.register_hook = issuing(
                registration_access_token="management-token",
                registration_client_uri=ISSUER + "/manage/1",
            )
            await env.prepare()
            env.now[0] += 61
            await env.lookup()
            record = env.registration()
            self.assertNotIn("registration_access_token", record.issued)
            self.assertNotIn("registration_client_uri", record.issued)
            self.assertNotIn("management-token", env.dump())
            self.assertNotIn("/manage/", env.dump())
            self.assertFalse(any("/manage/" in str(r.url) for r, _ in env.n.requests))
            self.assertFalse(
                any("management-token" in str(r.headers) for r, _ in env.n.requests)
            )

        self.run_env(run)

    def test_client_secret_only_in_host_secret_store(self):
        async def run(env):
            ready = await env.prepare()
            self.assertEqual(env.secrets.values, {"ref-1": "dcr-secret-1"})
            self.assertEqual(env.registration().secret_ref, "ref-1")
            self.assertNotIn("dcr-secret-1", env.dump())
            self.assertNotIn("dcr-secret-1", repr(ready))
            env.n.token_hook = rejecting(400, error="invalid_scope")
            env.now[0] += 61
            failure = await self.fails("access_denied", env.lookup())
            self.assertNotIn("dcr-secret-1", str(failure) + repr(failure.__dict__))
            self.assertNotIn("dcr-secret-1", env.dump())

        async def pkce(env):
            login = await env.prepare()
            pending = env.grants()[login.key].pending
            self.assertIsNone(pending.metadata.configuration.client_secret)
            self.assertFalse(env.secrets.stored)

        self.run_env(run)
        self.run_env(pkce, PKCE)

    def test_initial_access_token_sent_only_to_its_issuer(self):
        class TwoIssuers:
            def __init__(self, token_ref):
                self.token_ref = token_ref

            async def resource(self, target, budget):
                return target.destination

            async def select(self, target, resource, issuers, required, budget):
                (issuer,) = issuers
                return OAuthClientConfiguration(
                    issuer,
                    "",
                    "client_credentials",
                    scopes=("read",),
                    dynamic_registration=OAuthDynamicRegistration(
                        "Example Adapter",
                        initial_access_token_ref=self.token_ref
                        if issuer == ISSUER
                        else None,
                    ),
                )

        async def run(env):
            env.secrets.values["vault:iat"] = "iat-secret"
            env.policy = TwoIssuers("vault:iat")
            env.p = env.provider()
            await env.prepare()
            other = AuthTarget(
                "tenant", "other", "https://other.test/api", "event", None
            )
            await env.prepare(other)
            (first, headers_a, url_a), (_, headers_b, url_b) = env.n.registrations
            self.assertEqual(url_a, ISSUER + "/register")
            self.assertEqual(headers_a["authorization"], "Bearer iat-secret")
            self.assertEqual(url_b, "https://issuer2.test/register")
            self.assertNotIn("authorization", headers_b)
            tokens = [r for r, purpose in env.n.requests if purpose == "token"]
            self.assertFalse(any("iat-secret" in str(r.headers) for r in tokens))
            self.assertNotIn("iat-secret", env.dump())
            self.assertNotIn("iat-secret", repr(first))
            # An unresolvable reference sends nothing.
            env.policy.token_ref = "vault:missing"
            env.p = env.provider()
            env.s.records.clear()
            env.s.bindings.clear()
            await self.fails("credential_unavailable", env.prepare())
            self.assertEqual(len(env.n.registrations), 2)

        self.run_env(run)

    def test_registration_reused_across_bindings_and_partitions(self):
        async def run(env):
            await env.prepare()
            other = replace(env.target, backend_id="backend-2")
            await env.prepare(other)
            env.configure(grant_partition="shared")
            await env.prepare(replace(env.target, backend_id="backend-3"))
            self.assertEqual(len(env.n.registrations), 1)
            self.assertEqual(len(env.grants()), 3)
            self.assertEqual(env.n.token_clients, ["dcr-1"] * 3)

        self.run_env(run)

    def test_concurrent_processes_register_once(self):
        async def run(env):
            other = env.provider()
            results = []

            async def prepare(provider):
                results.append(
                    await provider.prepare(env.target, OperationBudget.after(5))
                )

            async with anyio.create_task_group() as tasks:
                for index in range(8):
                    tasks.start_soon(prepare, env.p if index % 2 else other)
            self.assertEqual(len(env.n.registrations), 1)
            self.assertEqual(len({r.credential.token for r in results}), 1)
            self.assertEqual(env.secrets.stored, ["ref-1"])

        self.run_env(run)

    def test_registration_cas_loser_uses_winner_and_deletes_only_its_secret(self):
        async def run(env):
            winner = OAuthRegistration(
                "winner-generation",
                "",
                "winner-client",
                "winner-client-generation",
                "client_secret_basic",
                1000,
                None,
                "winner-ref",
            )
            env.secrets.values["winner-ref"] = "winner-secret"

            async def compete(key, record):
                if isinstance(record, OAuthRegistration) and record.client_id:
                    env.s.records[key] = replace(
                        winner, request_digest=record.request_digest
                    )
                    env.s.cas_hook = None
                    return False
                return True

            env.s.cas_hook = compete
            await env.prepare()
            self.assertEqual(env.n.token_clients, ["winner-client"])
            self.assertEqual(env.secrets.deleted, ["ref-1"])
            self.assertIn("winner-ref", env.secrets.values)

        self.run_env(run)

    def test_expired_or_unresolvable_secret_reregisters_before_token_request(self):
        async def run(env):
            env.n.register_hook = issuing(env, lifetime=100)
            await env.prepare()
            env.now[0] = 1100
            self.assertIsNotNone(await env.lookup())
            purposes = [
                str(r.url).rsplit("/", 1)[1]
                for r, p in env.n.requests
                if p != "metadata"
            ]
            self.assertEqual(purposes, ["register", "token", "register", "token"])
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2"])
            env.secrets.values.clear()
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2", "dcr-3"])

        self.run_env(run)

    def test_policy_change_reregisters_with_new_digest(self):
        async def run(env):
            await env.prepare()
            changed = OAuthDynamicRegistration(
                "Renamed",
                software_id="adapter",
                software_version="2",
                scopes=("write", "read", "read"),
            )
            env.configure(dynamic_registration=changed)
            await env.lookup()
            body = env.n.registrations[1][0]
            self.assertEqual(body["client_name"], "Renamed")
            self.assertEqual(body["software_id"], "adapter")
            self.assertEqual(body["software_version"], "2")
            self.assertEqual(body["scope"], "read write")
            self.assertEqual(env.secrets.deleted, ["ref-1"])
            env.configure(
                dynamic_registration=replace(changed, scopes=("read", "write"))
            )
            await env.lookup()
            self.assertEqual(len(env.n.registrations), 2)
            env.secrets.values["vault:iat"] = "iat"
            env.configure(
                dynamic_registration=replace(
                    changed, initial_access_token_ref="vault:iat"
                )
            )
            await env.lookup()
            self.assertEqual(len(env.n.registrations), 3)
            self.assertEqual(env.n.registrations[2][1]["authorization"], "Bearer iat")

        self.run_env(run)

    def test_replaced_or_deleted_registration_secret_is_deleted(self):
        async def run(env):
            env.n.register_hook = issuing(env, lifetime=100)
            await env.prepare()
            env.now[0] = 1100
            await env.lookup()
            self.assertEqual(env.secrets.deleted, ["ref-1"])
            self.assertEqual(set(env.secrets.values), {"ref-2"})
            self.assertEqual(env.registration().secret_ref, "ref-2")

            async def invalid_client(request):
                return httpx.Response(401, json={"error": "invalid_client"})

            env.n.token_hook = invalid_client
            env.now[0] += 61
            await self.fails("credential_unavailable", env.lookup())
            # ref-3 replaced ref-2, then the repeated invalid_client dropped ref-3.
            self.assertEqual(env.secrets.deleted, ["ref-1", "ref-2", "ref-3"])
            self.assertFalse(env.secrets.values)
            self.assertIsNone(env.registration().secret_ref)

        self.run_env(run)

    # invalid_client ------------------------------------------------------

    def test_invalid_client_reregisters_once(self):
        async def cc(env):
            env.n.token_hook = reject_client(env, "dcr-1")
            ready = await env.prepare()
            self.assertIsInstance(ready, Ready)
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2"])
            self.assertEqual(len(env.n.registrations), 2)
            gets = [r for r, p in env.n.requests if p == "metadata"]
            self.assertEqual(len(gets), 2)
            self.assertIsNone(env.registration().next_attempt_at)

        async def repeated(env):
            env.n.token_hook = rejecting(401, error="invalid_client")
            await self.fails("credential_unavailable", env.prepare())
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(env.registration().attempts, 1)
            self.assertIsNone(env.registration().client_id)
            await self.fails("credential_unavailable", env.challenge())
            self.assertEqual(len(env.n.registrations), 2)

        async def pkce(env):
            await env.login()
            env.now[0] += 61
            env.n.token_hook = rejecting(401, error="invalid_client")
            await self.fails("interaction_required", env.lookup())
            self.assertIsNone(env.registration())
            self.assertEqual(len(env.n.registrations), 1)
            env.n.token_hook = None
            self.assertEqual(client_of(await env.prepare()), "dcr-2")

        self.run_env(cc)
        self.run_env(repeated)
        self.run_env(pkce, PKCE)

    def test_replacement_client_uses_new_grant_key(self):
        async def run(env):
            first = await env.prepare()
            old_key = first.credential.identity.key
            env.n.token_hook = reject_client(env, "dcr-1")
            env.now[0] += 61
            second = await env.lookup()
            self.assertNotEqual(second.identity.key, old_key)
            self.assertEqual(env.binding().configuration.client_id, "dcr-2")
            # The old grant is never migrated: a binding-scoped one is deleted.
            self.assertNotIn(old_key, env.grants())
            self.assertNotEqual(second.token, first.credential.token)
            self.assertEqual(
                env.grants()[second.identity.key].metadata.configuration.client_id,
                "dcr-2",
            )

        self.run_env(run)

    def test_replaced_client_old_grant_deleted_only_when_binding_scoped(self):
        for partition in (None, "shared"):

            async def invalid_client(env, partition=partition):
                env.configure(grant_partition=partition)
                first = await env.prepare()
                env.n.token_hook = reject_client(env, "dcr-1")
                env.now[0] += 61
                await env.lookup()
                kept = first.credential.identity.key in env.grants()
                self.assertEqual(kept, partition is not None)

            async def forced(env, partition=partition):
                env.configure(grant_partition=partition)
                first = await env.prepare()
                await env.prepare(force_registration=True)
                kept = first.credential.identity.key in env.grants()
                self.assertEqual(kept, partition is not None)
                self.assertEqual(len(env.grants()), 1 + kept)

            with self.subTest(partition=partition):
                self.run_env(invalid_client)
                self.run_env(forced)

    def test_registration_written_completes_despite_caller_cancel(self):
        async def written(env):
            sent, release = anyio.Event(), anyio.Event()

            async def gate(request):
                await request.extensions["trace"](
                    "http11.send_request_body.complete", {}
                )
                sent.set()
                await release.wait()

            env.n.register_gate = gate
            cancelled = []

            async def prepare():
                try:
                    await env.prepare()
                except anyio.get_cancelled_exc_class():
                    cancelled.append(True)
                    raise

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(prepare)
                await sent.wait()
                tasks.cancel_scope.cancel()
                release.set()
            self.assertEqual(cancelled, [True])
            record = env.registration()
            self.assertEqual(record.client_id, "dcr-1")
            self.assertEqual(env.secrets.values[record.secret_ref], "dcr-secret-1")
            self.assertFalse(env.n.tokens)  # Cancellation honoured after commit.
            env.n.register_gate = None
            await env.prepare()
            self.assertEqual(len(env.n.registrations), 1)
            self.assertEqual(env.n.token_clients, ["dcr-1"])

        async def unsent(env):
            reached = anyio.Event()

            async def gate(request):
                reached.set()
                await anyio.sleep_forever()

            env.n.register_gate = gate
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(env.prepare)
                await reached.wait()
                tasks.cancel_scope.cancel()
            self.assertIsNone(env.registration())
            self.assertFalse(env.secrets.stored)
            self.assertFalse(env.n.registrations)

        self.run_env(written)
        self.run_env(unsent)

    def test_registration_commit_survives_cancel_inside_secret_store(self):
        async def run(env):
            entered = anyio.Event()
            store = env.secrets.store

            async def slow_store(value, budget):
                entered.set()
                await anyio.sleep(0.05)
                return await store(value, budget)

            env.secrets.store = slow_store
            cancelled = []

            async def prepare():
                try:
                    await env.prepare()
                except anyio.get_cancelled_exc_class():
                    cancelled.append(True)
                    raise

            async with anyio.create_task_group() as tasks:
                tasks.start_soon(prepare)
                await entered.wait()
                tasks.cancel_scope.cancel()
            self.assertEqual(cancelled, [True])
            record = env.registration()
            self.assertEqual(record.client_id, "dcr-1")
            self.assertEqual(env.secrets.values[record.secret_ref], "dcr-secret-1")
            self.assertFalse(env.n.tokens)

        self.run_env(run)

    def test_pkce_completion_invalid_client_drops_binding_scoped_grant(self):
        for partition in (None, "shared"):

            async def run(env, partition=partition):
                env.configure(grant_partition=partition)

                async def no_refresh(request):
                    return httpx.Response(
                        200,
                        json={
                            "access_token": "a",
                            "token_type": "Bearer",
                            "expires_in": 60,
                        },
                    )

                env.n.token_hook = no_refresh
                await env.login()
                env.now[0] += 61  # Expired, no refresh: a new login keeps the token.
                login = await env.prepare()
                self.assertIsNotNone(env.grants()[login.key].token)
                env.n.token_hook = rejecting(401, error="invalid_client")
                await self.fails("interaction_required", env.complete(login))
                self.assertIsNone(env.registration())
                self.assertEqual(login.key in env.grants(), partition is not None)

            with self.subTest(partition=partition):
                self.run_env(run, PKCE)

    def test_shared_partition_stale_pending_login_with_reissued_client(self):
        async def run(env):
            async def hook(body):
                return httpx.Response(201, json={"client_id": "dcr-same"})

            env.n.register_hook = hook
            env.configure(grant_partition="shared")
            stale = await env.prepare()
            other = replace(env.target, backend_id="backend-2")
            fresh = await env.prepare(other, force_registration=True)
            # Same grant key, newer generation: a new login, never the stale one.
            self.assertEqual(fresh.key, stale.key)
            self.assertNotEqual(fresh.generation, stale.generation)
            newer = env.registration()
            await self.fails("interaction_required", env.complete(stale))
            self.assertEqual(env.registration(), newer)
            self.assertIn(stale.key, env.grants())  # The shared grant is kept.
            self.assertIsInstance(await env.complete(fresh, other), Ready)

        self.run_env(run, PKCE)

    def test_client_credentials_accepts_empty_redirect_uris_echo(self):
        async def run(env):
            async def hook(body):
                return httpx.Response(
                    201,
                    json={
                        "client_id": "dcr-cc",
                        "client_secret": "dcr-secret",
                        "redirect_uris": [],
                    },
                )

            env.n.register_hook = hook
            self.assertIsInstance(await env.prepare(), Ready)
            self.assertEqual(env.n.token_clients, ["dcr-cc"])

        async def non_empty(env):
            async def hook(body):
                return httpx.Response(
                    201,
                    json={
                        "client_id": "dcr-cc",
                        "client_secret": "dcr-secret",
                        "redirect_uris": ["https://evil.example/cb"],
                    },
                )

            env.n.register_hook = hook
            await self.fails("invalid_configuration", env.prepare())

        self.run_env(run)
        self.run_env(non_empty)

    def test_recorded_dcr_rechecks_eligibility_at_register_time(self):
        async def no_hook(env):
            async def long_lived(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "long",
                        "token_type": "Bearer",
                        "expires_in": 1000,
                    },
                )

            env.n.token_hook = long_lived
            await env.prepare()
            env.secrets = None
            env.p = env.provider()
            # The stored token still works; re-registration is not possible.
            self.assertEqual((await env.lookup()).token, "long")
            env.now[0] += 1001
            await self.fails("credential_unavailable", env.lookup())
            self.assertEqual(len(env.n.registrations), 1)

        async def no_method(env):
            env.n.register_hook = issuing(env, lifetime=100)
            await env.prepare()
            key = next(iter(env.s.bindings))
            env.s.bindings[key] = replace(
                env.s.bindings[key], token_endpoint_auth_methods=("private_key_jwt",)
            )
            env.now[0] += 100
            await self.fails("credential_unavailable", env.lookup())
            self.assertEqual(len(env.n.registrations), 1)

        self.run_env(no_hook)
        self.run_env(no_method)

    def test_prepare_clears_failed_marker(self):
        for flow in ("client_credentials", PKCE):

            async def run(env):
                await env.prepare()
                key, record = next(
                    (k, r)
                    for k, r in env.s.records.items()
                    if isinstance(r, OAuthRegistration)
                )
                env.s.records[key] = replace(
                    record, generation="marked", attempts=4, next_attempt_at=99999
                )
                await env.prepare()
                cleared = env.registration()
                self.assertEqual((cleared.attempts, cleared.next_attempt_at), (0, None))
                self.assertEqual(cleared.client_generation, record.client_generation)
                self.assertEqual(len(env.n.registrations), 1)

            with self.subTest(flow=flow):
                self.run_env(run, flow)

    def test_forced_reregistration_never_reuses_older_pending_login(self):
        for same_client in (False, True):

            async def run(env, same_client=same_client):
                if same_client:

                    async def hook(body):
                        return httpx.Response(201, json={"client_id": "dcr-same"})

                    env.n.register_hook = hook
                old = await env.prepare()
                new = await env.prepare(force_registration=True)
                self.assertNotEqual(new.generation, old.generation)
                self.assertEqual(len(env.n.registrations), 2)
                await self.fails("interaction_required", env.complete(old))
                self.assertIsInstance(await env.complete(new), Ready)

            with self.subTest(same_client=same_client):
                self.run_env(run, PKCE)

    def test_stale_callback_invalid_client_keeps_newer_registration(self):
        for same_client in (False, True):

            async def run(env, same_client=same_client):
                if same_client:

                    async def hook(body):
                        return httpx.Response(201, json={"client_id": "dcr-same"})

                    env.n.register_hook = hook
                stale = await env.prepare()
                generation = env.registration().client_generation
                other = replace(env.target, backend_id="backend-2")
                await env.prepare(other, force_registration=True)
                newer = env.registration()
                self.assertNotEqual(newer.client_generation, generation)
                env.n.token_hook = rejecting(401, error="invalid_client")
                await self.fails("interaction_required", env.complete(stale))
                self.assertEqual(env.registration(), newer)
                self.assertEqual(len(env.n.tokens), 1)

            with self.subTest(same_client=same_client):
                self.run_env(run, PKCE)

    def test_prepare_force_reregistration(self):
        async def cc(env):
            await env.prepare()
            record = env.registration()
            env.s.records[next(k for k, r in env.s.records.items() if r is record)] = (
                replace(record, attempts=3, next_attempt_at=99999, generation="marked")
            )
            await env.prepare(force_registration=True)
            fresh = env.registration()
            self.assertEqual(fresh.client_id, "dcr-2")
            self.assertNotEqual(fresh.client_generation, record.client_generation)
            self.assertEqual((fresh.attempts, fresh.next_attempt_at), (0, None))
            self.assertEqual(env.secrets.deleted, ["ref-1"])
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2"])

        async def pkce(env):
            login = await env.prepare()
            env.now[0] += 601  # An expired login alone never re-registers.
            renewed = await env.prepare()
            self.assertNotEqual(renewed.generation, login.generation)
            self.assertEqual(len(env.n.registrations), 1)
            self.assertEqual(
                client_of(await env.prepare(force_registration=True)), "dcr-2"
            )

        self.run_env(cc)
        self.run_env(pkce, PKCE)

    # Failed marker and backoff -------------------------------------------

    def test_failed_marker_bounds_registration_until_backoff(self):
        async def run(env):
            env.n.register_hook = rejecting(503)
            other = env.provider()
            await self.fails("provider_failed", env.prepare())
            marker = env.registration()
            self.assertEqual((marker.attempts, marker.failed_at), (1, 1000))
            self.assertEqual(marker.next_attempt_at, 1060)
            await self.fails("credential_unavailable", env.challenge(other))
            env.now[0] = 1059
            await self.fails("credential_unavailable", env.challenge())
            self.assertEqual(len(env.n.registrations), 1)
            env.now[0] = 1060
            await self.fails("provider_failed", env.challenge(other))
            marker = env.registration()
            self.assertEqual((marker.attempts, marker.next_attempt_at), (2, 1180))
            env.now[0] = 1100
            await self.fails("provider_failed", env.prepare())  # prepare ignores it
            self.assertEqual(len(env.n.registrations), 3)
            self.assertEqual(env.registration().attempts, 1)
            env.n.register_hook = None
            await env.prepare()
            self.assertIsNone(env.registration().next_attempt_at)
            # A request digest change clears a marker.
            env.n.register_hook = rejecting(503)
            env.configure(dynamic_registration=OAuthDynamicRegistration("A"))
            env.now[0] += 61
            await self.fails("provider_failed", env.lookup())
            env.configure(dynamic_registration=OAuthDynamicRegistration("B"))
            await self.fails("provider_failed", env.lookup())
            self.assertEqual(env.registration().attempts, 1)

        self.run_env(run)

    def test_transient_registration_failures_back_off(self):
        cases = [
            (503, "provider_failed"),
            (500, "provider_failed"),
            (408, "provider_failed"),
            (429, "provider_failed"),
            (401, "credential_unavailable"),
            (403, "credential_unavailable"),
            ("network", "provider_failed"),
        ]
        for status, code in cases:

            async def run(env, status=status, code=code):
                async def hook(body):
                    if status == "network":
                        raise httpx.ConnectError("refused")
                    return httpx.Response(status)

                env.n.register_hook = hook
                other = env.provider()
                await self.fails(code, env.challenge())
                for provider in (other, env.p, other):
                    await self.fails("credential_unavailable", env.challenge(provider))
                    self.assertIsNone(await env.lookup(provider))
                self.assertEqual(len(env.n.registrations), 1)
                env.now[0] += 60
                await self.fails(code, env.challenge(other))
                self.assertEqual(len(env.n.registrations), 2)

            with self.subTest(status=status):
                self.run_env(run)

    def test_retry_after_sets_next_attempt(self):
        cases = [
            ("300", {}, 1300),
            ("10", {}, 1060),
            ("99999", {}, 4600),
            (formatdate(1500, usegmt=True), {}, 1500),
            ("300", {"retry_after_max": 120}, 1120),
            ("300", {"registration_backoff": 400}, 1400),
        ]
        for header, options, expected in cases:

            async def run(env, header=header, options=options, expected=expected):
                async def hook(body):
                    return httpx.Response(429, headers={"retry-after": header})

                env.n.register_hook = hook
                env.p = env.provider(**options)
                await self.fails("provider_failed", env.prepare())
                self.assertEqual(env.registration().next_attempt_at, expected)

            with self.subTest(header=header, options=options):
                self.run_env(run)

    def test_marker_updates_are_atomic_under_lock(self):
        async def run(env):
            async def slow_failure(body):
                await anyio.sleep(0.02)
                return httpx.Response(503)

            env.n.register_hook = slow_failure
            other = env.provider()
            codes = []

            async def attempt(provider):
                try:
                    await env.challenge(provider)
                except AuthenticationFailure as error:
                    codes.append(error.code)

            for round_, expected in ((1, 1), (2, 2)):
                async with anyio.create_task_group() as tasks:
                    for index in range(6):
                        tasks.start_soon(attempt, env.p if index % 2 else other)
                self.assertEqual(len(env.n.registrations), round_)
                self.assertEqual(env.registration().attempts, expected)
                self.assertEqual(codes.count("provider_failed"), round_)
                env.now[0] += 120

        self.run_env(run)

    def test_cc_auto_repairs_after_backoff(self):
        async def run(env):
            env.n.register_hook = issuing(env, lifetime=100)
            await env.prepare()
            env.n.register_hook = rejecting(503)
            env.now[0] = 1100
            await self.fails("provider_failed", env.lookup())
            await self.fails("credential_unavailable", env.lookup())
            self.assertEqual(len(env.n.registrations), 2)
            env.n.register_hook = None
            env.now[0] = 1160
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-3"])
            self.assertIsNone(env.registration().next_attempt_at)

        self.run_env(run)

    def test_marker_blocks_only_registration_requests(self):
        async def cc(env):
            async def long_lived(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"access-{len(env.n.tokens)}",
                        "token_type": "Bearer",
                        "expires_in": 1000,
                    },
                )

            env.n.token_hook = long_lived
            env.n.register_hook = issuing(env, lifetime=100)
            first = await env.prepare()
            env.n.register_hook = rejecting(503)
            env.now[0] = 1101
            self.assertEqual((await env.lookup()).token, first.credential.token)
            self.assertEqual((await env.lookup()).token, first.credential.token)
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(len(env.n.tokens), 1)

        async def pkce(env):
            await env.login()
            env.n.register_hook = rejecting(503)
            env.configure(dynamic_registration=OAuthDynamicRegistration("Renamed"))
            self.assertIsInstance(await env.prepare(), Ready)
            self.assertEqual(env.registration().attempts, 1)
            self.assertIsNotNone(await env.lookup())
            env.now[0] += 61
            await self.fails("interaction_required", env.lookup())
            self.assertEqual(len(env.n.registrations), 2)

        self.run_env(cc)
        self.run_env(pkce, PKCE)

    # Proactive renewal ---------------------------------------------------

    def test_cc_proactive_reregistration_within_margin(self):
        async def run(env):
            # client_id_issued_at is ignored: the margin uses local registered_at.
            env.n.register_hook = issuing(env, lifetime=10000, client_id_issued_at=1)
            await env.prepare()
            env.now[0] = 9999  # min(0.1 x 10000, 3600) = 1000 before expiry
            await env.lookup()
            await env.p.renewals_settled()
            self.assertEqual(len(env.n.registrations), 1)
            env.now[0] = 10000
            # The operation acquires with the current client; renewal follows.
            await env.lookup()
            await env.p.renewals_settled()
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-1"])
            env.now[0] += 61
            await env.lookup()
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-1", "dcr-2"])

        self.run_env(run)

    def test_proactive_renewal_once_across_processes(self):
        async def run(env):
            env.n.register_hook = issuing(env, lifetime=10000)
            await env.prepare()
            env.now[0] = 10000
            other = env.provider()
            tokens = []

            async def deliver(provider):
                tokens.append((await env.lookup(provider)).token)

            async with anyio.create_task_group() as tasks:
                for index in range(6):
                    tasks.start_soon(deliver, env.p if index % 2 else other)
            await env.p.renewals_settled()
            await other.renewals_settled()
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(len(set(tokens)), 1)
            self.assertEqual(env.registration().client_id, "dcr-2")

        self.run_env(run)

    def test_proactive_renewal_failure_keeps_current_registration(self):
        async def run(env):
            env.n.register_hook = issuing(env, lifetime=10000)
            await env.prepare()
            env.n.register_hook = rejecting(429)
            env.now[0] = 10000
            self.assertIsNotNone(await env.lookup())
            await env.p.renewals_settled()
            record = env.registration()
            self.assertEqual((record.client_id, record.attempts), ("dcr-1", 1))
            env.now[0] = 10030
            self.assertIsNotNone(await env.lookup())
            await env.p.renewals_settled()
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-1"])

        self.run_env(run)

    def test_proactive_renewal_never_delays_or_changes_the_operation(self):
        async def slow(env):
            async def long_lived(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "cached",
                        "token_type": "Bearer",
                        "expires_in": 9500,
                    },
                )

            env.n.token_hook = long_lived
            env.n.register_hook = issuing(env, lifetime=10000)
            await env.prepare()
            release = anyio.Event()

            async def gate(request):
                await anyio.sleep(0.3)
                release.set()

            env.n.register_gate = gate
            env.now[0] = 10000
            # A 0.15 s deadline still serves the valid cached token at once;
            # the 0.3 s renewal runs detached and sends no token request.
            env.p = env.provider(operation_timeout=0.15)
            with anyio.fail_after(0.15):
                credential = await env.lookup()
            self.assertEqual(credential.token, "cached")
            self.assertEqual(len(env.n.tokens), 1)
            await env.p.renewals_settled()
            self.assertTrue(release.is_set())
            self.assertEqual(env.registration().client_id, "dcr-2")
            self.assertEqual(len(env.n.tokens), 1)

        self.run_env(slow)

    def test_concurrent_caller_never_waits_on_detached_renewal(self):
        async def run(env):
            async def long_lived(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "cached",
                        "token_type": "Bearer",
                        "expires_in": 9500,
                    },
                )

            env.n.token_hook = long_lived
            env.n.register_hook = issuing(env, lifetime=10000)
            await env.prepare()
            posting, release = anyio.Event(), anyio.Event()

            async def gate(request):
                posting.set()
                await anyio.sleep(0.4)
                release.set()

            env.n.register_gate = gate
            env.now[0] = 10000
            env.p = env.provider(operation_timeout=0.15)
            with anyio.fail_after(0.15):
                self.assertEqual((await env.lookup()).token, "cached")
            await posting.wait()  # The renewal holds the registration lock.
            other = env.provider(operation_timeout=0.15)
            for provider in (env.p, other):
                with anyio.fail_after(0.15):
                    self.assertEqual((await env.lookup(provider)).token, "cached")
            self.assertFalse(release.is_set())
            await env.p.renewals_settled()
            await other.renewals_settled()
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(len(env.n.tokens), 1)

        self.run_env(run)

    def test_detached_renewal_failure_is_logged_without_secrets(self):
        async def run(env):
            env.n.register_hook = issuing(env, lifetime=10000)
            await env.prepare()

            async def broken(value, budget):
                raise RuntimeError(value)  # Would leak the secret if logged.

            env.secrets.store = broken
            env.now[0] = 10000
            with self.assertLogs("agenthooksprotocol.oauth", "WARNING") as logs:
                self.assertIsNotNone(await env.lookup())
                await env.p.renewals_settled()
            self.assertEqual(len(logs.records), 1)
            self.assertIn("RuntimeError", logs.output[0])
            self.assertNotIn("dcr-secret", logs.output[0])
            self.assertEqual(env.registration().client_id, "dcr-1")

        self.run_env(run)

    def test_metadata_change_keeps_recorded_selection(self):
        async def dcr(env):
            await env.login()
            env.n.overrides.update(
                registration_endpoint=None, client_id_metadata_document_supported=True
            )
            env.configure(client_metadata_document=DOCUMENT)
            env.now[0] += 61
            self.assertIsInstance(await env.prepare(), Ready)
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-1"])
            self.assertEqual(env.binding().client_source, "dcr")
            self.assertEqual(len(env.n.registrations), 1)

        async def cimd(env):
            env.configure(client_metadata_document=DOCUMENT)
            env.n.overrides["client_id_metadata_document_supported"] = True
            await env.login()
            env.n.overrides["client_id_metadata_document_supported"] = None
            env.now[0] += 61
            self.assertIsInstance(await env.prepare(), Ready)
            self.assertEqual(env.n.token_clients, [DOCUMENT.url, DOCUMENT.url])
            self.assertFalse(env.n.registrations)

        self.run_env(dcr, PKCE)
        self.run_env(cimd, PKCE)

    def test_lookup_never_registers_pkce(self):
        async def pkce(env):
            await env.login()
            env.configure(dynamic_registration=OAuthDynamicRegistration("Renamed"))
            self.assertIsNotNone(await env.lookup())  # A valid token still works.
            env.now[0] += 61
            await self.fails("interaction_required", env.lookup())
            await self.fails("interaction_required", env.challenge())
            self.assertEqual(len(env.n.registrations), 1)
            self.assertIsNone(env.registration())

        async def cc(env):
            await env.prepare()
            env.configure(dynamic_registration=OAuthDynamicRegistration("Renamed"))
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(len(env.n.registrations), 2)

        self.run_env(pkce, PKCE)
        self.run_env(cc)


if __name__ == "__main__":
    unittest.main()
