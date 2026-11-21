"""Canonical `scope_decisions` and `completions` vectors at real host boundaries.

Source: agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json
(vendored), fields as defined in spec/draft/sdk-auth-lifecycle.md (Executable
coverage). Every vector runs under asyncio and Trio over HTTPX, the
coordinated store, host trust policy and a host secret store. Every field a
vector defines is asserted; an unknown field fails the run. A vector whose
`requires` names a feature Python lacks is skipped, never remapped.

Python mappings:
- `binding` `stored`: binding metadata stored by an earlier operation, with
  the vector's `grant` (or none) written to the grant record;
  `stored_without_metadata`: the same without the persisted
  authorization-server metadata; `preset`: an
  explicit OAuth binding preset (its `scopes` only when `preset_scopes` is
  present); `unbound`: neither.
- `path` `cached` and `credential`: bound delivery (`credential` with the
  binding; a stored binding is passed without `scopes`, which is no
  constraint); `preemptive`: the up-front lookup (no binding); `challenge`:
  `challenge` with the attempt for generation `sent`; `prepare`: host
  `prepare`; `fresh`: bound delivery for a preset, else an anonymous request
  receiving the vector's 401, handled by `challenge`.
- `host_error` `client_selection` is `OAuthTrustPolicy.select`;
  `destination` is `OAuthNetwork.authorize` for the named endpoint.
- `required` is the R `decide` computed for the operation.
"""

import unittest
from contextlib import asynccontextmanager, contextmanager
from dataclasses import replace
from functools import partial
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx

import test_managed_oauth_runtime as base
from test_managed_oauth_runtime import FIXTURES, ISSUER, RESOURCE, Policy, Store
from test_oauth_registration import DCR, RegNetwork, Secrets

from agenthooksprotocol.auth import (
    AuthChallenge,
    AuthContext,
    AuthenticationFailure,
    AuthTarget,
    OAuthBinding,
    normalize_auth_target,
)
from agenthooksprotocol.oauth import (
    ManagedOAuthProvider,
    OAuthClientMetadataDocument,
    OAuthPendingLogins,
    OAuthRecord,
    OperationBudget,
    PendingLogin,
    Ready,
    StoredToken,
    _Attempt,
)
from agenthooksprotocol._oauth_types import binding_key, grant_key

SCOPED = ("access_denied", "interaction_required")
# Optional SDK features the vectors may require, and those Python has.
KNOWN_FEATURES = {
    "complete_handle",
    "legacy_prepare_time_host_required",
    "token_validation_callback",
}
# Python's previous release persisted the prepare-time host-required scopes
# on pending logins (metadata.configuration.required_scopes).
PYTHON_FEATURES = {"complete_handle", "legacy_prepare_time_host_required"}
REDIRECT = "https://host.test/callback?tenant=a"
DOCUMENT = OAuthClientMetadataDocument(
    "https://adapter.example/oauth/client.json", (REDIRECT,)
)
# The fields the spec defines; any other fails the run.
FIELDS = {
    "scope_decisions": (
        {
            "flow",
            "path",
            "binding",
            "requested",
            "host_required",
            "explicit",
            "ceiling",
            "preset_scopes",
            "grant",
            "sent",
            "challenge",
            "prior_401_hint",
            "host_error",
            "target_error",
            "client_source",
            "force_registration",
        },
        {
            "code",
            "scopes",
            "required",
            "action",
            "acquisition_scopes",
            "retired",
            "authorization_server_requests",
            "network_calls",
            "network_calls_max",
            "authorization_server_requests_min",
        },
    ),
    "completions": (
        {
            "pending",
            "handle",
            "client_source",
            "source_permitted",
            "callback",
            "host_error",
            "claim",
            "exchange",
            "stored_required",
            "prepare_time_host_required",
            "current_host_required",
            "granted",
            "ceiling",
        },
        {"code", "scopes", "login_ended", "grant_persisted"},
    ),
    "token_errors": (
        {"grant_type", "client_source", "error", "refetch"},
        {"code", "reregistrations"},
    ),
}
GRANT_FIELDS = {"generation", "granted", "token", "refresh"}
HOST_ERROR_FIELDS = {"callback", "target", "code", "scopes"}
TARGET_ERROR_FIELDS = {"check", "code"}
# Host destination checks by vector target.
DESTINATIONS = {
    "registration_endpoint": ("registration", "issuer.test"),
    "issuer_metadata": ("metadata", "issuer.test"),
    "token_endpoint": ("token", "issuer.test"),
    "protected_resource_metadata": ("metadata", "resource.test"),
}
PATHS = {"fresh", "cached", "prepare", "credential", "challenge", "preemptive"}
CHALLENGE_FIELDS = {"status", "www_authenticate"}
CLAIM_FIELDS = {"outcome", "error_code", "reread"}


@contextmanager
def recording():
    """Record `decide`'s outcome (or failure) and R for every call."""
    from agenthooksprotocol import oauth
    from agenthooksprotocol._scope_decision import DecisionFailure

    decisions = []
    original = oauth.decide

    def recorded(op, policy, explicit, challenge, *args, **kwargs):
        required = tuple(
            sorted(
                set(policy.host_required)
                | (set(explicit) if isinstance(explicit, tuple) else set())
                | set(challenge.scopes)
            )
        )
        try:
            decision = original(op, policy, explicit, challenge, *args, **kwargs)
        except DecisionFailure as failure:
            decisions.append((failure, required))
            raise
        decisions.append((decision, required))
        return decision

    oauth.decide = recorded
    try:
        yield decisions
    finally:
        oauth.decide = original


def budget():
    return OperationBudget.after(5)


def granting(n, scope, *, kind="Bearer"):
    async def token(request):
        return httpx.Response(
            200,
            json={
                "access_token": f"access-{len(n.tokens)}",
                "token_type": kind,
                "expires_in": 60,
                "scope": scope,
                "refresh_token": f"refresh-{len(n.tokens)}",
            },
        )

    return token


def responding(status, body=None):
    async def token(request):
        return httpx.Response(status, json=body)

    return token


async def unreachable(request):
    raise httpx.ConnectError("unreachable", request=request)


def state_of(login):
    return parse_qs(urlsplit(login.authorization_url).query)["state"][0]


def url_scopes(login):
    query = parse_qs(urlsplit(login.authorization_url).query)
    return sorted(query.get("scope", [""])[0].split())


class Env:
    def __init__(self, flow, overrides=None):
        self.n = RegNetwork(**(overrides or {}))
        self.s = Store()
        self.policy = Policy(flow)
        self.now = [1000.0]
        self.p = ManagedOAuthProvider(
            network=self.n,
            store=self.s,
            policy=self.policy,
            namespace="tenant",
            clock=lambda: self.now[0],
            expiry_skew=0,
            commit_timeout=5,
            secret_store=Secrets(),
        )

        async def select(target, resource, issuers, required_scopes, budget):
            await anyio.lowlevel.checkpoint()
            return self.policy.configuration

        self.select = select
        self.policy.select = select

    def configure(self, **changes):
        self.policy.configuration = replace(self.policy.configuration, **changes)

    def grants(self):
        return {k: r for k, r in self.s.records.items() if isinstance(r, OAuthRecord)}

    def server_requests(self):
        return sum(1 for r, _ in self.n.requests if r.url.host == "issuer.test")


class ScopeVectorTests(unittest.TestCase):
    def run_vectors(self, kind, run):
        inputs, expects = FIELDS[kind]
        for vector in FIXTURES[kind]:
            given, expect = vector["input"], vector["expect"]
            required = set(vector.get("requires", ()))
            self.assertLessEqual(required, KNOWN_FEATURES, vector["id"])
            self.assertLessEqual(set(vector), {"id", "requires", "input", "expect"})
            self.assertLessEqual(set(given), inputs, vector["id"])
            self.assertLessEqual(set(expect), expects, vector["id"])
            for name, fields in (
                ("grant", GRANT_FIELDS),
                ("host_error", HOST_ERROR_FIELDS),
                ("target_error", TARGET_ERROR_FIELDS),
                ("challenge", CHALLENGE_FIELDS),
                ("claim", CLAIM_FIELDS),
            ):
                if isinstance(given.get(name), dict):
                    self.assertLessEqual(set(given[name]), fields, vector["id"])
            for backend in ("asyncio", "trio"):
                with self.subTest(vector=vector["id"], backend=backend):
                    missing = required - PYTHON_FEATURES
                    if missing:
                        self.skipTest("requires " + ", ".join(sorted(missing)))
                    with recording() as decisions:
                        anyio.run(partial(run, vector, decisions), backend=backend)

    def test_scope_decision_vectors(self):
        self.run_vectors("scope_decisions", self.decision)

    def test_completion_vectors(self):
        self.run_vectors("completions", self.completion)

    def test_token_error_vectors(self):
        self.run_vectors("token_errors", self.token_error)

    # token_errors ------------------------------------------------------

    async def token_error(self, vector, decisions):
        given, expect = vector["input"], vector["expect"]
        refresh = given["grant_type"] == "refresh"
        self.assertIn(given["grant_type"], ("refresh", "client_credentials"))
        source = given["client_source"]
        env = Env(
            "authorization_code_pkce" if refresh else "client_credentials",
            {"client_id_metadata_document_supported": True} if source == "cimd" else {},
        )
        try:
            target = AuthTarget("tenant", "backend", RESOURCE, "event", None)
            if refresh:
                env.configure(redirect_uri=REDIRECT)
            if source == "cimd":
                self.assertTrue(refresh)
                env.configure(client_id="", client_metadata_document=DOCUMENT)
            elif source == "dcr":
                env.configure(
                    client_id="",
                    client_secret=None,
                    token_endpoint_auth_method="none",
                    dynamic_registration=DCR,
                )
            else:
                self.assertEqual(source, "preregistered")
            # A stored, now expired grant.
            env.n.token_hook = granting(env.n, "read")
            first = await env.p.prepare(target, budget())
            if refresh:
                await env.p.complete(
                    target,
                    first,
                    REDIRECT
                    + "&"
                    + urlencode({"state": state_of(first), "code": "valid"}),
                    budget(),
                )
            env.now[0] += 61
            env.n.token_hook = {
                "invalid_grant": responding(400, {"error": "invalid_grant"}),
                "invalid_client": responding(401, {"error": "invalid_client"}),
                "unauthorized_client": responding(
                    400, {"error": "unauthorized_client"}
                ),
                "access_denied": responding(400, {"error": "access_denied"}),
                "invalid_scope": responding(400, {"error": "invalid_scope"}),
                "server_error": responding(500, {"error": "server_error"}),
                "unreachable": unreachable,
                "not_found": responding(404),
                "invalid_response": granting(env.n, "read", kind="mac"),
            }[given["error"]]
            refetch = given.get("refetch")
            if refetch is not None:
                self.assertIn(given["error"], ("unreachable", "not_found"))
                if refetch == "failed":
                    send = env.n.send

                    # The stale-metadata refetch itself fails.
                    async def failing(request, purpose, budget):
                        if purpose == "metadata" and request.url.host == "issuer.test":
                            return httpx.Response(500, request=request)
                        return await send(request, purpose, budget)

                    env.n.send = failing
                else:
                    self.assertLessEqual(set(refetch), HOST_ERROR_FIELDS)
                    self.assertEqual(refetch["callback"], "destination")
                    purpose, host = DESTINATIONS[refetch["target"]]
                    raised = AuthenticationFailure(
                        code=refetch["code"], required_scopes=tuple(refetch["scopes"])
                    )
                    authorize = env.n.authorize

                    async def destination(url, kind, budget):
                        if kind == purpose and urlsplit(url).hostname == host:
                            raise raised
                        await authorize(url, kind, budget)

                    env.n.authorize = destination
            registrations, tokens = len(env.n.registrations), len(env.n.tokens)
            with (
                anyio.CancelScope() as scope,
                self.assertRaises(AuthenticationFailure) as failure,
            ):
                await env.p.credential(
                    AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
                )
            self.assertEqual(
                (failure.exception.code, failure.exception.required_scopes),
                (expect["code"], ()),
            )
            self.assertGreater(len(env.n.tokens), tokens)
            self.assertEqual(
                env.n.tokens[tokens]["grant_type"],
                ["refresh_token" if refresh else "client_credentials"],
            )
            cc_dcr = (
                not refresh and source == "dcr" and given["error"] == "invalid_client"
            )
            self.assertEqual("reregistrations" in expect, cc_dcr)
            if "reregistrations" in expect:
                self.assertEqual(
                    len(env.n.registrations) - registrations, expect["reregistrations"]
                )
        finally:
            await env.n.client.aclose()

    # scope_decisions ---------------------------------------------------

    async def decision(self, vector, decisions):
        env = Env(vector["input"]["flow"])
        try:
            await self.decide(env, vector["input"], vector["expect"], decisions)
        finally:
            await env.n.client.aclose()

    async def write_grant(self, env, target, given):
        """Replace the stored grant with the vector's (or remove it)."""
        metadata = env.s.bindings[binding_key(target)]
        key = grant_key(target, metadata)
        env.s.records.pop(key, None)
        grant = given["grant"]
        if grant is None:
            return key, None
        token = StoredToken(
            f"access-g{grant['generation']}",
            env.now[0] + (3600 if grant["token"] == "valid" else -1),
            f"refresh-g{grant['generation']}" if grant["refresh"] else None,
            tuple(sorted(grant["granted"])),
        )
        env.s.records[key] = OAuthRecord(
            str(grant["generation"]), "active", metadata, token
        )
        return key, token.access_token

    async def decide(self, env, given, expect, decisions):
        flow = given["flow"]
        # An unknown path or binding fails the run.
        self.assertIn(given["path"], PATHS)
        self.assertIn(
            given["binding"], ("stored", "stored_without_metadata", "preset", "unbound")
        )
        requested = tuple(sorted(given["requested"]))
        ceiling = tuple(sorted(given.get("ceiling", requested)))
        preset = given.get("preset_scopes")
        wire = {
            "type": "oauth",
            "flow": flow,
            "issuer": ISSUER,
            "resource": RESOURCE,
            "clientId": "host-client",
        }
        if flow == "client_credentials":
            wire["clientSecretRef"] = "host/secret"
        presetted_wire = dict(
            wire, **({"scopes": preset} if preset is not None else {})
        )
        typed = OAuthBinding(
            ISSUER,
            RESOURCE,
            "host-client",
            flow,
            tuple(sorted(preset)) if preset is not None else None,
            wire.get("clientSecretRef"),
        )
        plain = AuthTarget("tenant", "backend", RESOURCE, "event", None)
        presetted = AuthTarget(
            "tenant", "backend", RESOURCE, "event", presetted_wire, typed
        )
        bound = given["binding"]
        # An unbound target's client source (present exactly then).
        forcing = given.get("force_registration", False)
        if "force_registration" in given:
            self.assertIs(forcing, True)
            self.assertEqual(given["path"], "prepare")
        self.assertEqual("client_source" in given, bound == "unbound" or forcing)
        # Forced re-registration replaces only a client-credentials DCR client.
        replacing = (
            forcing
            and given["flow"] == "client_credentials"
            and given.get("client_source") == "dcr"
        )
        self.assertEqual("authorization_server_requests_min" in expect, replacing)
        source = given.get("client_source", "preregistered")
        if source == "cimd":
            env.n.overrides["client_id_metadata_document_supported"] = True
            env.configure(
                client_id="",
                client_secret=None,
                token_endpoint_auth_method="none",
                client_metadata_document=DOCUMENT,
                redirect_uri=REDIRECT,
            )
        elif source == "dcr":
            env.configure(
                client_id="",
                client_secret=None,
                token_endpoint_auth_method="none",
                dynamic_registration=DCR,
            )
        else:
            self.assertEqual(source, "preregistered")
        target = presetted if bound == "preset" else plain
        stored_token = None
        key = None
        stored_binding = bound in ("stored", "stored_without_metadata")
        if stored_binding or given["grant"] is not None:
            # An earlier operation stores the binding.
            env.configure(
                scopes=requested,
                allowed_scopes=tuple(
                    sorted(
                        set(requested)
                        | set(ceiling)
                        | set(given["grant"]["granted"] if given["grant"] else ())
                    )
                ),
            )
            env.n.token_hook = granting(env.n, " ".join(requested))
            first = await env.p.prepare(target, budget())
            if isinstance(first, PendingLogin):
                await env.p.cancel(target, first, budget())
            key, stored_token = await self.write_grant(env, target, given)
            if bound == "unbound":
                # A usable grant without a stored binding (for example one
                # shared through a grant partition).
                del env.s.bindings[binding_key(target)]
            if bound == "stored_without_metadata":
                # The binding record lacks persisted authorization-server
                # metadata: a token request first fetches the issuer's.
                stored = env.s.bindings[binding_key(target)]
                env.s.bindings[binding_key(target)] = replace(
                    stored, token_endpoint="", authorization_endpoint=None
                )
        # The operation's context and the attempt for generation `sent`.
        path = given["path"]
        context_binding = (
            presetted_wire
            if bound == "preset"
            else wire
            if path in ("cached", "credential")
            else None
        )
        if path == "fresh" and bound == "preset":
            context_binding = presetted_wire
        with anyio.CancelScope() as scope:
            context = AuthContext(
                {"id": "backend"}, context_binding, RESOURCE, "event", scope
            )
            if "prior_401_hint" in given:
                # An earlier operation's 401 hint; then the vector's grant.
                env.configure(
                    scopes=requested, allowed_scopes=ceiling, required_scopes=()
                )
                await env.p.challenge(
                    context,
                    AuthChallenge(
                        401,
                        {
                            "www-authenticate": 'Bearer scope="'
                            + " ".join(given["prior_401_hint"])
                            + '"'
                        },
                        RESOURCE,
                        None,
                        True,
                    ),
                )
                key, stored_token = await self.write_grant(env, target, given)
            env.configure(
                scopes=requested,
                allowed_scopes=tuple(given["ceiling"]) if "ceiling" in given else None,
                required_scopes=tuple(given["host_required"]),
            )
            env.n.token_hook = granting(env.n, " ".join(ceiling))
            failure = given.get("host_error")
            if failure is not None:
                raised = AuthenticationFailure(
                    code=failure["code"], required_scopes=tuple(failure["scopes"])
                )

                async def refuse(*args):
                    raise raised

                if failure["callback"] == "client_selection":
                    env.policy.select = refuse
                else:
                    self.assertEqual(failure["callback"], "destination")
                    purpose, host = DESTINATIONS[failure["target"]]
                    if purpose == "registration":
                        env.configure(
                            client_id="",
                            client_secret=None,
                            token_endpoint_auth_method="none",
                            dynamic_registration=DCR,
                        )
                    authorize = env.n.authorize

                    async def destination(url, kind, budget):
                        if kind == purpose and urlsplit(url).hostname == host:
                            raise raised
                        await authorize(url, kind, budget)

                    env.n.authorize = destination
            attempt = None
            challenge = None
            if "challenge" in given:
                sent = given.get("sent")
                if sent is not None:
                    attempt = _Attempt(
                        key,
                        str(sent),
                        normalize_auth_target(context, namespace="tenant").identity,
                    )
                challenge = AuthChallenge(
                    given["challenge"]["status"],
                    {
                        # The vectors' resource is this host's resource.
                        "www-authenticate": given["challenge"][
                            "www_authenticate"
                        ].replace("https://api.example/", "https://resource.test/")
                    },
                    RESOURCE,
                    attempt,
                    True,
                )
            sent_token = (
                stored_token
                if challenge is not None
                and given.get("sent") is not None
                and given["grant"] is not None
                and given["grant"]["generation"] == given["sent"]
                else None
            )
            # A target or configuration check that fails before any decide
            # step: the operation's binding is unsupported.
            checked = context
            if "target_error" in given:
                self.assertEqual(given["target_error"]["check"], "unsupported_binding")
                checked = replace(
                    context, binding=dict(wire, flow="device_authorization")
                )
            del decisions[:]
            requests, server, tokens = (
                len(env.n.requests),
                env.server_requests(),
                len(env.n.tokens),
            )
            result = error = None
            try:
                if path == "prepare":
                    result = await env.p.prepare(
                        target,
                        budget(),
                        required_scopes=tuple(given["explicit"]),
                        force_registration=forcing,
                    )
                elif path == "fresh" and bound != "preset":
                    # First use of an unbound target: an anonymous request
                    # receives the vector's 401 (else a bare Bearer one),
                    # which the provider handles.
                    raw = given.get("challenge", {"status": 401})
                    header = raw.get("www_authenticate", "Bearer")
                    result = await env.p.challenge(
                        context,
                        AuthChallenge(
                            raw["status"],
                            # The vectors' resource is this host's resource.
                            {
                                "www-authenticate": header.replace(
                                    "https://api.example/", "https://resource.test/"
                                )
                            },
                            RESOURCE,
                            None,
                            True,
                        ),
                    )
                elif path == "challenge":
                    result = await env.p.challenge(checked, challenge)
                elif path in ("fresh", "cached", "credential", "preemptive"):
                    result = await env.p.credential(checked)
                else:
                    self.fail("unknown path " + repr(path))
            except AuthenticationFailure as caught:
                error = caught
        code = error.code if error is not None else None
        self.assertEqual(code, expect["code"])
        self.assertEqual("scopes" in expect, code in SCOPED)
        if error is not None:
            self.assertEqual(list(error.required_scopes), expect.get("scopes", []))
        if "required" in expect:
            self.assertTrue(decisions)
            self.assertEqual(list(decisions[-1][1]), expect["required"])
        action = expect.get("action")
        self.assertEqual(action is not None, code is None)
        if action is not None:
            self.assertEqual(decisions[-1][0].action, action)
            if action == "use":
                served = result.credential if isinstance(result, Ready) else result
                self.assertEqual(served.token, stored_token)
                self.assertEqual(len(env.n.tokens), tokens)
            elif action in ("refresh", "acquire"):
                self.assertEqual(len(env.n.tokens), tokens + 1)
                self.assertEqual(
                    env.n.tokens[-1]["grant_type"],
                    ["refresh_token" if action == "refresh" else "client_credentials"],
                )
            else:
                self.assertIsInstance(result, PendingLogin)
        self.assertEqual("acquisition_scopes" in expect, action in ("acquire", "login"))
        if "acquisition_scopes" in expect:
            sent_scopes = (
                url_scopes(result)
                if action == "login"
                else sorted(env.n.tokens[-1].get("scope", [""])[0].split())
            )
            self.assertEqual(sent_scopes, expect["acquisition_scopes"])
        self.assertEqual(
            "retired" in expect, challenge is not None and challenge.status == 401
        )
        if "retired" in expect:
            retired = sent_token is not None and not any(
                r.token is not None and r.token.access_token == sent_token
                for r in env.grants().values()
            )
            self.assertEqual(retired, expect["retired"])
        if "authorization_server_requests" in expect:
            self.assertEqual(
                env.server_requests() - server, expect["authorization_server_requests"]
            )
        if "network_calls" in expect:
            self.assertEqual(len(env.n.requests) - requests, expect["network_calls"])
        if "authorization_server_requests_min" in expect:
            self.assertGreaterEqual(
                env.server_requests() - server,
                expect["authorization_server_requests_min"],
            )
            # The replaced client's token is never served.
            self.assertNotEqual(result.credential.token, stored_token)
        if "network_calls_max" in expect:
            self.assertLessEqual(
                len(env.n.requests) - requests, expect["network_calls_max"]
            )

    # completions -------------------------------------------------------

    async def completion(self, vector, decisions):
        given = vector["input"]
        source = given["client_source"]
        env = Env(
            "authorization_code_pkce",
            {"client_id_metadata_document_supported": True} if source == "cimd" else {},
        )
        try:
            await self.complete(env, given, vector["expect"], source)
        finally:
            await env.n.client.aclose()

    async def complete(self, env, given, expect, source):
        env.configure(redirect_uri=REDIRECT)
        if source == "cimd":
            env.configure(client_id="", client_metadata_document=DOCUMENT)
        elif source == "dcr":
            env.configure(client_id="", dynamic_registration=DCR)
        target = AuthTarget("tenant", "backend", RESOURCE, "event", None)
        legacy = given["stored_required"] is None
        stored = set(given["stored_required"] or ())
        ceiling = set(given["ceiling"])
        wide = tuple(sorted(stored | ceiling))
        env.configure(
            scopes=wide,
            allowed_scopes=wide,
            required_scopes=tuple(given.get("prepare_time_host_required", ())),
        )
        login = await env.p.prepare(
            target, budget(), required_scopes=tuple(sorted(stored))
        )
        self.assertIsInstance(login, PendingLogin)
        named = state_of(login)
        handle = {"matching": login, "none": None}.get(given["handle"])
        if given["handle"] == "other":
            handle = await env.p.prepare(target, budget())
        if legacy:
            # An older release's record: no stored R.
            for key, record in list(env.p._logins.records.items()):
                env.p._logins.records[key] = OAuthPendingLogins(
                    record.generation,
                    tuple(
                        replace(
                            item,
                            required_scopes=None,
                            # A record lacking the prepare-time requirement
                            # (the absent-field fallback) reads as None.
                            metadata=item.metadata
                            if "prepare_time_host_required" in given
                            else replace(
                                item.metadata,
                                configuration=replace(
                                    item.metadata.configuration, required_scopes=None
                                ),
                            ),
                        )
                        for item in record.logins
                    ),
                )
        pending = given["pending"]
        if pending == "expired":
            env.now[0] = login.expires_at
        elif pending == "ended":
            await env.p.cancel(target, login, budget())
        elif pending == "unknown":
            named = "unknown-state"
        # Current host policy.
        env.configure(
            scopes=tuple(sorted(ceiling)),
            allowed_scopes=None,
            required_scopes=tuple(given.get("current_host_required", ())),
        )
        if not given["source_permitted"]:
            env.configure(
                **{
                    "preregistered": {"client_id": "other-client"},
                    "cimd": {"client_metadata_document": None},
                    "dcr": {"dynamic_registration": None},
                }[source]
            )
        failure = given.get("host_error")
        if failure is not None:
            raised = AuthenticationFailure(
                code=failure["code"], required_scopes=tuple(failure["scopes"])
            )
            if failure["callback"] == "client_selection":

                async def refuse(*args):
                    raise raised

                env.policy.select = refuse
            else:
                self.assertEqual(failure["callback"], "destination")
                purpose, host = DESTINATIONS[failure["target"]]
                authorize = env.n.authorize

                async def destination(url, kind, budget):
                    if kind == purpose and urlsplit(url).hostname == host:
                        raise raised
                    await authorize(url, kind, budget)

                env.n.authorize = destination
        exchange = given["exchange"]
        env.n.token_hook = {
            "ok": granting(env.n, " ".join(sorted(given["granted"]))),
            "invalid_grant": responding(400, {"error": "invalid_grant"}),
            "invalid_client": responding(401, {"error": "invalid_client"}),
            "unauthorized_client": responding(400, {"error": "unauthorized_client"}),
            "access_denied": responding(400, {"error": "access_denied"}),
            "invalid_scope": responding(400, {"error": "invalid_scope"}),
            "server_error": responding(500, {"error": "server_error"}),
            "unreachable": unreachable,
            "not_found": responding(404),
            "invalid_response": granting(env.n, "read", kind="mac"),
        }[exchange]
        self.claim(env, given["claim"])
        query = [("state", named), ("code", "valid")]
        base_url, suffix = "https://host.test/callback?tenant=a", ""
        defect = given["callback"]
        if defect == "valid_with_server_params":
            query.append(("session_state", "server-added"))
        elif defect == "denied":
            query = [("state", named), ("error", "access_denied")]
        elif defect == "denied_invalid_client":
            query = [("state", named), ("error", "invalid_client")]
        elif defect == "redirect_mismatch":
            base_url = "https://evil.test/callback?tenant=a"
        elif defect == "redirect_query_mismatch":
            base_url = "https://host.test/callback?tenant=b"
        elif defect == "state_duplicated":
            query.append(("state", named))
        elif defect == "iss_mismatch":
            query.append(("iss", "https://other.test"))
        elif defect == "fragment":
            suffix = "#fragment"
        elif defect == "userinfo":
            base_url = "https://user@host.test/callback?tenant=a"
        elif defect == "missing_code":
            query = [("state", named)]
        elif defect == "code_and_error":
            query.append(("error", "access_denied"))
        elif defect == "duplicate_param":
            query.append(("code", "again"))
        elif defect == "unparseable":
            base_url = "https://host.test:99999999/callback?tenant=a"
        else:
            self.assertEqual(defect, "valid")
        if pending == "absent":
            query = [(k, v) for k, v in query if k != "state"]
        url = base_url + "&" + urlencode(query) + suffix
        before = {k: r.generation for k, r in env.grants().items()}
        error = None
        try:
            ready = await env.p.complete(target, handle, url, budget())
        except AuthenticationFailure as caught:
            error = caught
        code = error.code if error is not None else None
        self.assertEqual(code, expect["code"])
        self.assertEqual("scopes" in expect, code in SCOPED)
        self.assertEqual("login_ended" in expect, code is not None)
        if error is None:
            self.assertIsInstance(ready, Ready)
        else:
            self.assertEqual(list(error.required_scopes), expect.get("scopes", []))
            self.assertIs(error.login_ended, expect["login_ended"])
            states = [item.state for item in base.pending_logins(env.p)]
            if pending == "pending" and given["claim"] == "ok":
                # login_ended describes the login named by the state.
                self.assertEqual(named in states, not expect["login_ended"])
            if given["handle"] == "other" and not expect["login_ended"]:
                self.assertIn(handle.generation, states)
        after = {k: r.generation for k, r in env.grants().items()}
        self.assertEqual(after != before, expect["grant_persisted"])

    @staticmethod
    def claim(env, claim):
        """An uncertain claim: the store errors at the claim, then the
        re-read finds the login gone, pending or cannot tell."""
        if claim == "ok":
            return
        assert claim["outcome"] == "uncertain"
        logins = env.p._logins
        original = logins.coordinate
        state = {"claimed": False}

        @asynccontextmanager
        async def coordinate(key, budget):
            if state["claimed"] and claim["reread"] == "undetermined":
                raise AuthenticationFailure(code=claim["error_code"])
            async with original(key, budget) as guard:

                class Uncertain:
                    async def load(self):
                        return await guard.load()

                    async def compare_and_swap(self, expected, record):
                        if state["claimed"]:
                            return await guard.compare_and_swap(expected, record)
                        state["claimed"] = True
                        if claim["reread"] == "gone":
                            await guard.compare_and_swap(expected, record)
                        raise AuthenticationFailure(code=claim["error_code"])

                yield Uncertain()

        logins.coordinate = coordinate


if __name__ == "__main__":
    unittest.main()
