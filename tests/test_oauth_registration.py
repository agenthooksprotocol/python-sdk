"""Client registration (pre-registered, CIMD, RFC 7591 DCR) at real host boundaries.

PKCE registers per login (no registration record); client credentials keep a
persisted registration record with a shared failure backoff.

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
    pending_logins,
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
from agenthooksprotocol._oauth_types import client_identity, grant_key

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
                    self.assertFalse(pending_logins(env.p))
                    self.assertFalse(env.grants())
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
                    client = expect["client_id"]
                if value["flow"] == PKCE:
                    # A PKCE client never leaves a registration record.
                    self.assertIsNone(env.registration())
                    self.assertEqual(client_of(result), client)
                    self.assertEqual(result.key, grant_key(env.target, env.binding()))
                else:
                    self.assertIsInstance(result, Ready)
                    self.assertEqual(env.n.token_clients, [client])
                self.assertEqual(env.binding().client_source, expect["source"])
                self.assertEqual(
                    client_identity(env.binding()), expect["client_identity"]
                )

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
        for declared in (
            "http://127.0.0.1:8765/other",
            "https://127.0.0.1:8765/callback",
            "http://[::1]:8765/callback",
        ):

            async def run(env, declared=declared):
                env.configure(
                    client_metadata_document=replace(
                        DOCUMENT, redirect_uris=(declared,)
                    )
                )
                await self.fails("invalid_configuration", env.prepare())
                self.assertFalse(env.grants())
                self.assertFalse(pending_logins(env.p))
                self.assertFalse(env.n.registrations)
                self.assertFalse([u for u, _ in env.n.authorized if "state=" in u])

            with self.subTest(declared=declared):
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

    def test_pkce_registers_per_login_with_its_exact_redirect(self):
        async def pkce(env):
            await self.fails("interaction_required", env.challenge())
            # The binding is now known: the lookup needs a login too.
            await self.fails("interaction_required", env.lookup())
            self.assertFalse(env.n.registrations)
            first = await env.prepare()
            second = await env.prepare(redirect_uri="http://127.0.0.1:50123/callback")
            remote = await env.prepare(redirect_uri="https://host.test/callback")
            self.assertEqual(
                [client_of(login) for login in (first, second, remote)],
                ["dcr-1", "dcr-2", "dcr-3"],
            )
            bodies = [body for body, _, _ in env.n.registrations]
            self.assertEqual(
                [body["redirect_uris"] for body in bodies],
                [
                    [LOOPBACK],
                    ["http://127.0.0.1:50123/callback"],
                    ["https://host.test/callback"],
                ],
            )
            # application_type native only for a loopback redirect.
            self.assertEqual(
                [body.get("application_type") for body in bodies],
                ["native", "native", None],
            )
            self.assertIsNone(env.registration())
            # Each login completes with its own client and exact redirect.
            state = parse_qs(urlsplit(second.authorization_url).query)["state"][0]
            await env.p.complete(
                env.target,
                second,
                "http://127.0.0.1:50123/callback?"
                + urlencode({"state": state, "code": "c"}),
                OperationBudget.after(5),
            )
            self.assertEqual(env.n.token_clients, ["dcr-2"])
            self.assertEqual(
                env.n.tokens[-1]["redirect_uri"], ["http://127.0.0.1:50123/callback"]
            )

        async def cc(env):
            self.assertIsNotNone(await env.challenge())
            self.assertEqual(len(env.n.registrations), 1)
            env.now[0] += 61
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(len(env.n.registrations), 1)
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-1"])

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
                pkce = row["flow"] == PKCE
                if not expect["accepted"]:
                    await self.fails(expect["error"], env.prepare())
                    self.assertEqual(env.n.registrations[0][0], row["request"])
                    record = env.registration()
                    if pkce:
                        self.assertIsNone(record)
                    else:
                        self.assertIsNone(record.client_id)
                    self.assertFalse(env.secrets.stored)
                    self.assertFalse(env.grants())
                    self.assertFalse(pending_logins(env.p))
                    return
                result = await env.prepare()
                self.assertEqual(env.n.registrations[0][0], row["request"])
                if pkce:
                    # No registration record: the login holds the client.
                    self.assertIsNone(env.registration())
                    self.assertEqual(client_of(result), expect["record"]["client_id"])
                    self.assertFalse(expect["record"]["secret_ref"])
                    self.assertFalse(env.secrets.stored)
                else:
                    record = env.registration()
                    self.assertEqual(record.client_id, expect["record"]["client_id"])
                    self.assertEqual(
                        record.client_secret_expires_at,
                        expect["record"]["client_secret_expires_at"],
                    )
                    self.assertEqual(
                        record.secret_ref is not None, expect["record"]["secret_ref"]
                    )
                    self.assertEqual(
                        env.secrets.values[record.secret_ref],
                        row["response"]["client_secret"],
                    )
                    self.assertEqual(
                        record.token_endpoint_auth_method,
                        row["request"]["token_endpoint_auth_method"],
                    )
                for forbidden in (
                    "not-a-real-secret",
                    "registration_access_token",
                    "registration_client_uri",
                ):
                    self.assertNotIn(forbidden, env.dump())
                    if pkce:
                        self.assertNotIn(forbidden, repr(pending_logins(env.p)))

            with self.subTest(row["id"]):
                self.run_env(run, row["flow"])

    def test_registration_response_validation_persists_nothing(self):
        for response in (
            {"client_id": "dcr", "redirect_uris": LOOPBACK},
            {"client_id": "dcr", "redirect_uris": None},
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
                self.assertIsNone(env.registration())
                self.assertFalse(env.grants())
                self.assertFalse(pending_logins(env.p))

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
            env.n.register_hook = issuing(client_secret="ignored-secret")
            login = await env.prepare()
            (pending,) = pending_logins(env.p)
            self.assertIsNone(pending.metadata.configuration.client_secret)
            await env.complete(login)
            self.assertFalse(env.secrets.stored)
            self.assertNotIn("ignored-secret", env.dump())
            self.assertNotIn("client_secret", env.n.tokens[0])

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
                "winner-client",
                "client_secret_basic",
                None,
                "winner-ref",
            )
            env.secrets.values["winner-ref"] = "winner-secret"

            async def compete(key, record):
                if isinstance(record, OAuthRegistration) and record.client_id:
                    env.s.records[key] = winner
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
            env.now[0] += 61
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2", "dcr-3"])

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
            # The grant key ignores the replacement client.
            self.assertEqual(list(env.grants()), [ready.credential.identity.key])

        async def repeated(env):
            env.n.token_hook = rejecting(401, error="invalid_client")
            await self.fails("credential_unavailable", env.prepare())
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(env.registration().attempts, 1)
            self.assertIsNone(env.registration().client_id)
            # It counts as a failed registration: a server that accepts
            # registrations but rejects their clients is not re-registered on
            # every operation, by any process sharing the store.
            marker = env.registration()
            self.assertEqual(marker.failure, "credential_unavailable")
            self.assertEqual(marker.next_attempt_at, 1060)
            other = env.provider()
            for provider in (env.p, other):
                await self.fails("credential_unavailable", env.challenge(provider))
            self.assertEqual(len(env.n.registrations), 2)
            env.now[0] = 1060
            await self.fails("credential_unavailable", env.challenge(other))
            self.assertEqual(len(env.n.registrations), 4)
            # Doubling per failure, like any failed registration.
            self.assertEqual(env.registration().attempts, 2)
            self.assertEqual(env.registration().next_attempt_at, 1060 + 120)

        self.run_env(cc)
        self.run_env(repeated)

    def test_invalid_client_retry_skips_stale_uncoordinated_read(self):
        async def run(env):
            await env.prepare()
            stale = env.registration()
            plain_load = env.s.load

            async def eventually_consistent(key, budget):
                if key.startswith("ahp.oauth.registration:"):
                    return stale
                return await plain_load(key, budget)

            env.s.load = eventually_consistent  # Always serves dcr-1.

            async def lagging_delete(reference, budget):
                env.secrets.deleted.append(reference)  # Still resolvable.

            env.secrets.delete = lagging_delete
            env.n.token_hook = reject_client(env, "dcr-1")
            env.now[0] += 61
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-1", "dcr-2"])
            self.assertEqual(len(env.n.registrations), 2)

        self.run_env(run)

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

    def test_pkce_invalid_client_ends_login_or_compare_and_deletes_grant(self):
        async def completion(env):
            ready = await env.login()
            key = ready.credential.identity.key
            # Expired without refresh material: the next prepare logs in anew.
            env.now[0] += 61
            kept = env.grants()[key]
            env.s.records[key] = replace(
                kept, token=replace(kept.token, refresh_token=None)
            )
            login = await env.prepare()
            self.assertEqual(client_of(login), "dcr-2")
            env.n.token_hook = reject_client(env, "dcr-2")
            await self.fails("interaction_required", env.complete(login))
            # Only that login ended; the grant with the older client is kept.
            self.assertFalse(pending_logins(env.p))
            self.assertEqual(
                env.grants()[key].metadata.configuration.client_id, "dcr-1"
            )
            self.assertEqual(
                env.grants()[key].token.access_token, ready.credential.token
            )
            self.assertIsNone(env.registration())

        async def refresh(env):
            ready = await env.login()
            key = ready.credential.identity.key
            env.now[0] += 61
            env.n.token_hook = reject_client(env, "dcr-1")
            await self.fails("interaction_required", env.lookup())
            self.assertNotIn(key, env.grants())
            self.assertIsNone(env.registration())
            self.assertEqual(len(env.n.registrations), 1)
            env.n.token_hook = None
            self.assertEqual(client_of(await env.prepare()), "dcr-2")

        async def newer_grant_kept(env):
            ready = await env.login()
            key = ready.credential.identity.key
            env.now[0] += 61
            newer = replace(
                env.grants()[key],
                generation="newer",
                metadata=replace(
                    env.grants()[key].metadata,
                    configuration=replace(
                        env.grants()[key].metadata.configuration, client_id="dcr-9"
                    ),
                ),
            )

            async def hook(request):
                # A newer login commits another client and tokens while the
                # refresh is in flight (outside this lock).
                env.s.records[key] = newer
                return httpx.Response(401, json={"error": "invalid_client"})

            env.n.token_hook = hook
            await self.fails("interaction_required", env.lookup())
            self.assertEqual(env.grants()[key], newer)

        async def rotated_refresh_kept(env):
            ready = await env.login()
            key = ready.credential.identity.key
            env.now[0] += 61
            record = env.grants()[key]

            async def hook(request):
                # Same client, but another process rotated the refresh token.
                current = env.s.records[key]
                env.s.records[key] = replace(
                    current,
                    generation="rotated",
                    token=replace(current.token, refresh_token="rotated"),
                )
                return httpx.Response(401, json={"error": "invalid_client"})

            env.n.token_hook = hook
            await self.fails("interaction_required", env.lookup())
            self.assertEqual(env.grants()[key].token.refresh_token, "rotated")
            self.assertEqual(
                env.grants()[key].metadata.configuration.client_id,
                record.metadata.configuration.client_id,
            )

        for test in (completion, refresh, newer_grant_kept, rotated_refresh_kept):
            with self.subTest(test.__name__):
                self.run_env(test, PKCE)

    def test_null_echoed_fields_and_expiry_are_never_absent(self):
        cases = [
            ("client_credentials", "client_secret_expires_at"),
            ("client_credentials", "redirect_uris"),
            ("client_credentials", "grant_types"),
            ("client_credentials", "token_endpoint_auth_method"),
            (PKCE, "redirect_uris"),
            (PKCE, "grant_types"),
            (PKCE, "token_endpoint_auth_method"),
        ]
        for flow, member in cases:

            async def run(env, member=member):
                async def hook(body):
                    issued = {"client_id": "dcr-null", member: None}
                    if body["token_endpoint_auth_method"] != "none":
                        issued["client_secret"] = "dcr-secret"
                    return httpx.Response(201, json=issued)

                env.n.register_hook = hook
                await self.fails("invalid_configuration", env.prepare())
                self.assertFalse(env.secrets.stored)
                self.assertFalse(env.grants())
                self.assertFalse(pending_logins(env.p))

            with self.subTest(flow=flow, member=member):
                self.run_env(run, flow)

    def test_client_credentials_redirect_uris_echo_must_be_a_list(self):
        for echo, accepted in (
            ([], True),
            (["https://evil.example/cb"], True),
            (None, False),
            ("https://host.test/cb", False),
            ({"uri": "https://host.test/cb"}, False),
        ):

            async def run(env, echo=echo, accepted=accepted):
                async def hook(body):
                    return httpx.Response(
                        201,
                        json={
                            "client_id": "dcr-cc",
                            "client_secret": "dcr-secret",
                            "redirect_uris": echo,
                        },
                    )

                env.n.register_hook = hook
                if accepted:
                    self.assertIsInstance(await env.prepare(), Ready)
                    self.assertEqual(env.n.token_clients, ["dcr-cc"])
                else:
                    await self.fails("invalid_configuration", env.prepare())
                    self.assertIsNone(env.registration().client_id)

            with self.subTest(echo=echo):
                self.run_env(run)

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

    def test_prepare_force_registration_replaces_cc_registration(self):
        async def cc(env):
            first = await env.prepare()
            record = env.registration()
            # The stored token is still valid, but a forced replacement
            # acquires a new one with the new client.
            forced = await env.prepare(force_registration=True)
            self.assertIsInstance(forced, Ready)
            self.assertNotEqual(forced.credential.token, first.credential.token)
            fresh = env.registration()
            self.assertEqual(fresh.client_id, "dcr-2")
            self.assertNotEqual(fresh.generation, record.generation)
            self.assertEqual(env.secrets.deleted, ["ref-1"])
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2"])
            # Later operations serve the new client's token.
            self.assertEqual((await env.lookup()).token, forced.credential.token)
            # A failed replacement keeps the current registration, unmarked,
            # and returns the failure.
            env.n.register_hook = rejecting(503)
            failure = await self.fails(
                "provider_failed", env.prepare(force_registration=True)
            )
            self.assertEqual(failure.recovery, "retry")
            kept = env.registration()
            self.assertEqual(
                (kept.client_id, kept.secret_ref), (fresh.client_id, fresh.secret_ref)
            )
            # The failure is recorded in the backoff (host prepare bypasses it).
            self.assertEqual(
                (kept.failure, kept.attempts, kept.next_attempt_at),
                ("provider_failed", 1, env.now[0] + 60),
            )
            await self.fails("provider_failed", env.prepare(force_registration=True))
            self.assertEqual(env.registration().attempts, 2)
            self.assertEqual(env.registration().next_attempt_at, env.now[0] + 120)
            self.assertEqual(len(env.n.registrations), 4)
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2"])
            self.assertEqual((await env.lookup()).token, forced.credential.token)
            # The kept client still works; its next successful token request
            # clears the backoff.
            env.now[0] += 61
            self.assertIsNotNone(await env.lookup())
            cleared = env.registration()
            self.assertEqual(
                (cleared.failure, cleared.attempts, cleared.next_attempt_at),
                (None, 0, None),
            )

        self.run_env(cc)

    # Client-credentials registration backoff ------------------------------

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
                failure = await self.fails(code, env.challenge())
                marker = env.registration()
                self.assertEqual((marker.attempts, marker.next_attempt_at), (1, 1060))
                self.assertEqual(marker.failure, code)
                # Shared through the store: no process registers during the
                # backoff, and each returns the last failure's code.
                for provider in (other, env.p, other):
                    again = await self.fails(code, env.challenge(provider))
                    self.assertEqual(again.recovery, failure.recovery)
                    self.assertIsNone(await env.lookup(provider))
                self.assertEqual(len(env.n.registrations), 1)
                if code == "provider_failed":
                    self.assertEqual(failure.recovery, "retry")
                env.now[0] = 1060
                await self.fails(code, env.challenge(other))
                self.assertEqual(len(env.n.registrations), 2)
                # Doubling per failure.
                self.assertEqual(env.registration().next_attempt_at, 1060 + 120)
                # Host prepare bypasses the backoff; success clears it.
                env.n.register_hook = None
                self.assertIsInstance(await env.prepare(), Ready)
                self.assertEqual(len(env.n.registrations), 3)
                self.assertIsNone(env.registration().next_attempt_at)

            with self.subTest(status=status):
                self.run_env(run)

    def test_retry_after_sets_next_attempt(self):
        cases = [
            ("300", {}, 1300),
            ("10", {}, 1060),
            ("99999", {}, 4600),
            (formatdate(1500, usegmt=True), {}, 1500),
            ("300", {"registration_backoff_max": 120}, 1120),
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

    def test_backoff_updates_are_atomic_under_lock(self):
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
                self.assertEqual(codes, ["provider_failed"] * 6 * round_)
                env.now[0] += 120

        self.run_env(run)

    def test_backoff_keeps_serving_a_valid_cc_token(self):
        async def run(env):
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
            self.assertIsNotNone(await env.lookup())  # A valid token still works.
            env.now[0] += 61
            # Refresh presents the stored client; nothing registers.
            self.assertIsNotNone(await env.lookup())
            await env.p.reset(env.target, OperationBudget.after(5))
            await self.fails("interaction_required", env.lookup())
            await self.fails("interaction_required", env.challenge())
            self.assertEqual(len(env.n.registrations), 1)
            self.assertIsNone(env.registration())

        async def cc(env):
            self.assertIsNone(await env.lookup())  # Unbound: anonymous.
            await env.prepare()
            env.now[0] += 61
            env.s.records.pop(
                next(
                    k
                    for k, r in env.s.records.items()
                    if isinstance(r, OAuthRegistration)
                )
            )
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(len(env.n.registrations), 2)

        self.run_env(pkce, PKCE)
        self.run_env(cc)

    def test_cimd_loopback_redirect_is_compared_without_its_port(self):
        """Canonical lifecycle: cimd-portless-loopback-redirect-matches."""
        cases = [
            ("http://127.0.0.1/callback", "http://127.0.0.1:51004/callback"),
            ("http://127.0.0.1:8765/callback", "http://127.0.0.1:9999/callback"),
            ("http://[::1]/callback", "http://[::1]:51004/callback"),
        ]
        for declared, redirect in cases:

            async def run(env, declared=declared, redirect=redirect):
                env.configure(
                    client_metadata_document=replace(
                        DOCUMENT, redirect_uris=(declared,)
                    )
                )
                login = await env.prepare(redirect_uri=redirect)
                self.assertEqual(client_of(login), DOCUMENT.url)
                query = parse_qs(urlsplit(login.authorization_url).query)
                # The exact redirect, with its port, is what is sent.
                self.assertEqual(query["redirect_uri"], [redirect])
                callback = (
                    redirect
                    + "?"
                    + urlencode({"state": query["state"][0], "code": "c"})
                )
                await env.p.complete(
                    env.target, login, callback, OperationBudget.after(5)
                )
                self.assertEqual(env.n.tokens[-1]["redirect_uri"], [redirect])

            with self.subTest(declared=declared, redirect=redirect):
                self.run_env(run, PKCE, {"client_id_metadata_document_supported": True})
        # localhost is never accepted, even when declared verbatim.
        for redirect in (
            "http://localhost:51004/callback",
            "http://localhost/callback",
        ):

            async def localhost(env, redirect=redirect):
                env.configure(
                    client_metadata_document=replace(
                        DOCUMENT, redirect_uris=(redirect,)
                    )
                )
                await self.fails(
                    "invalid_configuration", env.prepare(redirect_uri=redirect)
                )
                self.assertFalse(env.n.registrations)
                self.assertFalse(pending_logins(env.p))

            with self.subTest(redirect=redirect):
                self.run_env(
                    localhost, PKCE, {"client_id_metadata_document_supported": True}
                )

    def test_issued_client_is_committed_with_the_grant(self):
        async def run(env):
            ready = await env.login()
            key = ready.credential.identity.key
            record = env.grants()[key]
            self.assertEqual(record.metadata.configuration.client_id, "dcr-1")
            self.assertIsNotNone(record.token.refresh_token)
            # The binding holds no issued client, and the key no client_id.
            self.assertEqual(env.binding().configuration.client_id, "")
            self.assertNotIn("dcr-1", key)
            # A re-registered client replaces it under the same key.
            again = await env.prepare(required_scopes=("read",))
            self.assertIsInstance(again, Ready)  # A valid grant is served.
            await env.p.reset(env.target, OperationBudget.after(5))
            second = await env.login()
            self.assertEqual(second.credential.identity.key, key)
            self.assertEqual(
                env.grants()[key].metadata.configuration.client_id, "dcr-2"
            )
            # Refresh uses the stored client, without registering.
            env.now[0] += 61
            self.assertIsNotNone(await env.lookup())
            self.assertEqual(env.n.token_clients, ["dcr-1", "dcr-2", "dcr-2"])
            self.assertEqual(env.n.tokens[-1]["grant_type"], ["refresh_token"])
            self.assertEqual(len(env.n.registrations), 2)
            self.assertEqual(
                env.grants()[key].metadata.configuration.client_id, "dcr-2"
            )

        self.run_env(run, PKCE)

    def test_redirect_supplied_only_to_prepare_works_for_every_client_source(self):
        redirect = "http://127.0.0.1:50555/callback"
        sources = {
            "preregistered": dict(client_id="host-client", dynamic_registration=None),
            "cimd": dict(
                client_metadata_document=replace(
                    DOCUMENT, redirect_uris=("http://127.0.0.1/callback",)
                ),
                dynamic_registration=None,
            ),
            "dcr": {},
        }
        for source, changes in sources.items():

            async def run(env, source=source, changes=changes):
                # The host configures no redirect; each login brings its own.
                env.configure(redirect_uri=None, **changes)
                await self.fails("invalid_configuration", env.prepare())
                self.assertFalse(pending_logins(env.p))
                self.assertFalse(env.n.registrations)
                login = await env.prepare(redirect_uri=redirect)
                state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
                ready = await env.p.complete(
                    env.target,
                    login,
                    redirect + "?" + urlencode({"state": state, "code": "c"}),
                    OperationBudget.after(5),
                )
                self.assertEqual(env.binding().client_source, source)
                self.assertIsNone(env.binding().configuration.redirect_uri)
                # Lookup, challenge and prepare work without any redirect.
                self.assertEqual((await env.lookup()).token, ready.credential.token)
                self.assertIsNotNone(await env.challenge())
                env.now[0] += 61
                self.assertIsNotNone(await env.lookup())
                self.assertIsInstance(await env.prepare(), Ready)
                self.assertEqual(
                    [form["grant_type"][0] for form in env.n.tokens],
                    ["authorization_code", "refresh_token"],
                )
                # A localhost redirect for a login is still rejected first.
                await env.p.reset(env.target, OperationBudget.after(5))
                await self.fails(
                    "invalid_configuration",
                    env.prepare(redirect_uri="http://localhost:50555/callback"),
                )
                self.assertEqual(len(env.n.registrations), source == "dcr")

            with self.subTest(source=source):
                self.run_env(run, PKCE, {"client_id_metadata_document_supported": True})

    def test_failure_count_resets_after_a_successful_token_request(self):
        async def run(env):
            env.n.register_hook = rejecting(503)
            await self.fails("provider_failed", env.prepare())
            await self.fails("provider_failed", env.prepare())  # bypasses backoff
            self.assertEqual(env.registration().attempts, 2)
            env.n.register_hook = issuing(env, lifetime=100)
            await env.prepare()
            # The count reached the new client, then its token succeeded.
            self.assertEqual(env.registration().attempts, 0)
            self.assertEqual(env.registration().client_id, "dcr-1")
            # A later failure (here at secret expiry) starts the backoff anew,
            # as an invalid_client would.
            env.n.register_hook = rejecting(503)
            env.now[0] = 1100
            await self.fails("provider_failed", env.lookup())
            marker = env.registration()
            self.assertEqual((marker.attempts, marker.next_attempt_at), (1, 1160))

        async def rejected_until_success(env):
            # Repeated invalid_client keeps counting across re-registrations
            # until a token request succeeds.
            env.n.token_hook = rejecting(401, error="invalid_client")
            await self.fails("credential_unavailable", env.prepare())
            await self.fails("credential_unavailable", env.prepare())
            self.assertEqual(env.registration().attempts, 2)
            env.n.token_hook = None
            await env.prepare()
            self.assertEqual(env.registration().attempts, 0)

        self.run_env(run)
        self.run_env(rejected_until_success)

    def test_failure_count_reset_is_best_effort_after_the_grant_lock(self):
        async def run(env):
            env.n.register_hook = rejecting(503)
            await self.fails("provider_failed", env.prepare())
            env.n.register_hook = None
            coordinate = env.s.coordinate
            held = []

            def failing(key, budget):
                if key.startswith("ahp.oauth.registration:") and env.n.tokens:
                    # The reset runs after the grant lock is released.
                    held.extend(
                        lock.locked()
                        for name, lock in env.s.locks.items()
                        if name.startswith("ahp.oauth.grant:")
                    )
                    raise RuntimeError("store unavailable")
                return coordinate(key, budget)

            env.s.coordinate = failing
            # The token is committed: the failed reset never fails prepare.
            ready = await env.prepare()
            self.assertIsInstance(ready, Ready)
            self.assertEqual(held, [False])
            self.assertEqual(env.registration().attempts, 1)
            self.assertEqual(
                env.grants()[ready.credential.identity.key].token.access_token,
                ready.credential.token,
            )
            env.s.coordinate = coordinate
            env.now[0] += 61
            await env.lookup()
            self.assertEqual(env.registration().attempts, 0)

        self.run_env(run)


if __name__ == "__main__":
    unittest.main()
