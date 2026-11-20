"""Canonical `scope_decisions` and `completions` vectors at real host boundaries.

Source: agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json
(vendored). Every vector runs under asyncio and Trio over HTTPX, the
coordinated store, host trust policy and a host secret store.

Mapping of vector inputs to Python host boundaries:
- binding `stored`: binding metadata is stored by an earlier operation (with
  no grant when `granted` is null); `preset`: an explicit OAuth binding
  preset; `unbound`: neither, so discovery starts at protected-resource
  metadata.
- path `credential`: bound delivery (`credential` with the binding);
  `preemptive`: the up-front lookup for an unbound destination; `fresh`,
  `cached`, `prepare`: host `prepare`; `challenge`: `challenge` with the
  presented credential.
- host_error `client_selection` is `OAuthTrustPolicy.select`; `destination` is
  `OAuthNetwork.authorize` for the named endpoint.
- A vector's `requires` names optional SDK features; a vector needing one
  Python lacks is skipped, never remapped onto another mechanism, and an
  unknown feature fails.
- `acquisition_scopes` is read from the token request, the login's
  authorization URL, or (after `interaction_required`) the login a host
  `prepare` with the same challenge and the error's scopes creates.
"""

import unittest
from contextlib import contextmanager
from dataclasses import replace
from functools import partial
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx

from test_managed_oauth_runtime import FIXTURES, ISSUER, RESOURCE, Policy, Store
from test_oauth_registration import DCR, RegNetwork, Secrets

from agenthooksprotocol.auth import (
    AuthChallenge,
    AuthContext,
    AuthenticationFailure,
    AuthTarget,
    OAuthBinding,
)
from agenthooksprotocol.oauth import (
    ManagedOAuthProvider,
    OAuthClientMetadataDocument,
    OAuthRecord,
    OperationBudget,
    PendingLogin,
    Ready,
)

SCOPED = ("access_denied", "interaction_required")
# Optional SDK features the vectors may require, and those Python has.
KNOWN_FEATURES = {"complete_handle", "token_validation_callback"}
PYTHON_FEATURES = {"complete_handle"}
# Vectors of the vendored spec revision that scope contract v2 changes; they
# are replaced when the v2 spec is vendored.
SUPERSEDED = {
    # v2 step 3: a 401 hint is used only by a client-credentials acquisition.
    "challenge-401-scope-not-required",
}
# Every field a vector defines is asserted; an unknown field fails the run.
FIELDS = {
    "scope_decisions": (
        {
            "flow",
            "path",
            "binding",
            "requested",
            "preset_scopes",
            "ceiling",
            "host_required",
            "explicit",
            "granted",
            "challenge",
            "host_error",
        },
        {
            "code",
            "scopes",
            "required",
            "action",
            "acquisition_scopes",
            "network_calls",
            "authorization_server_requests",
            "retired",
        },
    ),
    "completions": (
        {
            "pending",
            "handle",
            "client_source",
            "callback",
            "exchange",
            "stored_required",
            "granted",
            "ceiling",
            "host_error",
        },
        {"code", "scopes", "login_ended", "grant_persisted", "failed"},
    ),
}
CALLBACK = "https://host.test/callback"
DOCUMENT = OAuthClientMetadataDocument(
    "https://adapter.example/oauth/client.json", (CALLBACK,)
)


@contextmanager
def recording():
    """Record every outcome `decide` returns to the provider."""
    from agenthooksprotocol import oauth

    decisions = []
    original = oauth.decide

    def recorded(*args, **kwargs):
        decision = original(*args, **kwargs)
        decisions.append(decision)
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
            },
        )

    return token


def responding(status, body):
    async def token(request):
        return httpx.Response(status, json=body)

    return token


def state_of(login):
    return parse_qs(urlsplit(login.authorization_url).query)["state"][0]


def url_scopes(login):
    query = parse_qs(urlsplit(login.authorization_url).query)
    return sorted(query.get("scope", [""])[0].split())


class Env:
    def __init__(self, flow, overrides=None):
        self.flow = flow
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

        self.policy.select = select

    def configure(self, **changes):
        self.policy.configuration = replace(self.policy.configuration, **changes)

    def grants(self):
        return {k: r for k, r in self.s.records.items() if isinstance(r, OAuthRecord)}

    def server_requests(self):
        return sum(1 for r, _ in self.n.requests if r.url.host == "issuer.test")

    async def finish(self, target, login):
        return await self.p.complete(
            target,
            login,
            CALLBACK + "?" + urlencode({"state": state_of(login), "code": "valid"}),
            budget(),
        )


class ScopeDecisionVectorTests(unittest.TestCase):
    def run_vectors(self, kind, run):
        inputs, expects = FIELDS[kind]
        for vector in FIXTURES[kind]:
            required = set(vector.get("requires", ()))
            self.assertLessEqual(required, KNOWN_FEATURES, vector["id"])
            self.assertLessEqual(set(vector), {"id", "input", "expect", "requires"})
            self.assertLessEqual(set(vector["input"]), inputs, vector["id"])
            self.assertLessEqual(set(vector["expect"]), expects, vector["id"])
            for backend in ("asyncio", "trio"):
                with self.subTest(vector=vector["id"], backend=backend):
                    missing = required - PYTHON_FEATURES
                    if missing:
                        self.skipTest("requires " + ", ".join(sorted(missing)))
                    if vector["id"] in SUPERSEDED:
                        self.skipTest("superseded by scope contract v2")
                    with recording() as decisions:
                        anyio.run(partial(run, vector, decisions), backend=backend)

    def test_scope_decision_vectors(self):
        self.run_vectors("scope_decisions", self.decision)

    def test_completion_vectors(self):
        self.run_vectors("completions", self.completion)

    async def decision(self, vector, decisions):
        given, expect = vector["input"], vector["expect"]
        flow = given["flow"]
        env = Env(flow)
        try:
            await self.decide(env, flow, given, expect, decisions)
        finally:
            await env.n.client.aclose()

    async def decide(self, env, flow, given, expect, decisions):
        requested = tuple(sorted(given["requested"]))
        ceiling = tuple(sorted(given.get("ceiling", requested)))
        preset = tuple(sorted(given.get("preset_scopes", requested)))
        wire = {
            "type": "oauth",
            "flow": flow,
            "issuer": ISSUER,
            "resource": RESOURCE,
            "clientId": "host-client",
            "scopes": list(preset),
        }
        typed = OAuthBinding(ISSUER, RESOURCE, "host-client", flow, preset)
        plain = AuthTarget("tenant", "backend", RESOURCE, "event", None)
        presetted = AuthTarget("tenant", "backend", RESOURCE, "event", wire, typed)
        target = presetted if given["binding"] == "preset" else plain
        granted = given["granted"]
        presented = None
        if granted is not None or given["binding"] == "stored":
            env.configure(
                scopes=requested,
                allowed_scopes=tuple(
                    sorted(set(requested) | set(ceiling) | set(granted or ()))
                ),
            )
            env.n.token_hook = granting(env.n, " ".join(sorted(granted or ())))
            first = await env.p.prepare(
                target,
                budget(),
                required_scopes=tuple(sorted(set(granted or ()) - set(requested))),
            )
            if isinstance(first, PendingLogin):
                if granted is None:
                    await env.p.cancel(target, first, budget())
                else:
                    first = await env.finish(target, first)
            if isinstance(first, Ready):
                presented = first.credential
                if granted is None:
                    for key in list(env.grants()):
                        env.s.records.pop(key)
        env.configure(
            scopes=requested,
            allowed_scopes=tuple(given["ceiling"]) if "ceiling" in given else None,
            required_scopes=tuple(sorted(given["host_required"])),
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
                self.assertEqual(failure["target"], "registration_endpoint")
                env.configure(
                    client_id="",
                    client_secret=None,
                    token_endpoint_auth_method="none",
                    dynamic_registration=DCR,
                )
                authorize = env.n.authorize

                async def destination(url, purpose, budget):
                    if purpose == "registration":
                        raise raised
                    await authorize(url, purpose, budget)

                env.n.authorize = destination
        challenge = None
        if "challenge" in given:
            challenge = AuthChallenge(
                given["challenge"]["status"],
                {"www-authenticate": given["challenge"]["www_authenticate"]},
                RESOURCE,
                presented.identity if presented is not None else None,
                True,
            )
        del decisions[:]  # Only the operation under test.
        requests, server, tokens = (
            len(env.n.requests),
            env.server_requests(),
            len(env.n.tokens),
        )
        result = error = None
        with anyio.CancelScope() as scope:
            path = given["path"]
            bound = wire if path == "credential" else None
            context = AuthContext({"id": "backend"}, bound, RESOURCE, "event", scope)
            try:
                if path in ("fresh", "cached", "prepare"):
                    result = await env.p.prepare(
                        target,
                        budget(),
                        required_scopes=tuple(given["explicit"]),
                    )
                elif path in ("credential", "preemptive"):
                    result = await env.p.credential(context)
                else:
                    result = await env.p.challenge(context, challenge)
            except AuthenticationFailure as caught:
                error = caught
        self.assertEqual(error.code if error else None, expect["code"])
        if error is not None:
            if "scopes" in expect:
                self.assertEqual(list(error.required_scopes), expect["scopes"])
            if error.code not in SCOPED:
                self.assertEqual(error.required_scopes, ())
            if error.code == "interaction_required" and "required" in expect:
                self.assertEqual(list(error.required_scopes), expect["required"])
        if "network_calls" in expect:
            self.assertEqual(len(env.n.requests) - requests, expect["network_calls"])
        if "authorization_server_requests" in expect:
            self.assertEqual(
                env.server_requests() - server,
                expect["authorization_server_requests"],
            )
        if expect.get("retired"):
            self.assertIsNotNone(presented)
            self.assertFalse(
                any(
                    r.token is not None and r.token.access_token == presented.token
                    for r in env.grants().values()
                )
            )
        action = expect.get("action")
        if action is not None:
            # The operation went through decide, whose final outcome is the
            # vector's action with its required set.
            self.assertEqual(decisions[-1].action, action)
            self.assertEqual(list(decisions[-1].required), expect["required"])
        if action == "use":
            self.assertIsInstance(result, Ready)
            self.assertEqual(result.credential.token, presented.token)
            self.assertEqual(len(env.n.tokens), tokens)
        elif action == "acquire":
            self.assertIsNotNone(result)
            self.assertEqual(len(env.n.tokens), tokens + 1)
        elif action == "login":
            self.assertIsInstance(result, PendingLogin)
            stored = [
                login
                for record in env.s.records.values()
                for login in getattr(record, "logins", ())
            ] or list(
                login
                for record in env.p._logins.records.values()
                for login in record.logins
            )
            self.assertEqual(list(stored[-1].required_scopes), expect["required"])
        if "acquisition_scopes" in expect:
            if isinstance(result, PendingLogin):
                sent = url_scopes(result)
            elif action == "acquire":
                sent = sorted(env.n.tokens[-1]["scope"][0].split())
            else:
                self.assertEqual(error.code, "interaction_required")
                login = await env.p.prepare(
                    presetted if given["binding"] == "preset" else plain,
                    budget(),
                    challenge=challenge,
                    required_scopes=error.required_scopes,
                )
                self.assertIsInstance(login, PendingLogin)
                sent = url_scopes(login)
            self.assertEqual(sent, expect["acquisition_scopes"])

    async def completion(self, vector, decisions):
        given, expect = vector["input"], vector["expect"]
        source = given["client_source"]
        env = Env(
            "authorization_code_pkce",
            {"client_id_metadata_document_supported": True} if source == "cimd" else {},
        )
        try:
            await self.complete(env, given, expect, source)
        finally:
            await env.n.client.aclose()

    async def complete(self, env, given, expect, source):
        if source == "cimd":
            env.configure(client_id="", client_metadata_document=DOCUMENT)
        elif source == "dcr":
            env.configure(client_id="", dynamic_registration=DCR)
        target = AuthTarget("tenant", "backend", RESOURCE, "event", None)
        stored, ceiling = set(given["stored_required"]), set(given["ceiling"])
        wide = tuple(sorted(stored | ceiling))
        env.configure(scopes=wide, allowed_scopes=wide)
        login = await env.p.prepare(
            target, budget(), required_scopes=tuple(sorted(stored))
        )
        self.assertIsInstance(login, PendingLogin)
        named = state_of(login)
        if given["callback"] == "state_mismatch":
            # The callback names another pending login than the handle.
            named = state_of(await env.p.prepare(target, budget()))
        if given["pending"] == "expired":
            env.now[0] = login.expires_at
        elif given["pending"] == "ended":
            await env.p.cancel(target, login, budget())
        elif given["pending"] == "unknown":
            named = "unknown-state"
        env.configure(scopes=tuple(sorted(ceiling)), allowed_scopes=None)
        exchange = given["exchange"]
        env.n.token_hook = {
            "ok": granting(env.n, " ".join(sorted(given["granted"]))),
            "invalid_grant": responding(400, {"error": "invalid_grant"}),
            "invalid_client": responding(401, {"error": "invalid_client"}),
            "token_endpoint_failure": responding(500, {"error": "server_error"}),
            "invalid_response": granting(env.n, "read", kind="mac"),
        }[exchange]
        query = {"state": named, "code": "valid"}
        base, suffix = CALLBACK, ""
        defect = given["callback"]
        if defect == "denied":
            query = {"state": named, "error": "access_denied"}
        elif defect == "redirect_mismatch":
            base = "https://evil.test/callback"
        elif defect == "iss_mismatch":
            query["iss"] = "https://other.test"
        elif defect == "fragment":
            suffix = "#fragment"
        elif defect == "userinfo":
            base = "https://user@host.test/callback"
        elif defect == "missing_code":
            del query["code"]
        elif defect == "missing_state":
            del query["state"]
        url = base + "?" + urlencode(query) + suffix
        if defect == "duplicate_param":
            url += "&code=again"
        before = {k: r.generation for k, r in env.grants().items()}
        handle = login if given["handle"] == "matching" else None
        select = env.policy.select
        failure = given.get("host_error")
        if failure is not None:
            self.assertEqual(failure["callback"], "client_selection")
            raised = AuthenticationFailure(
                code=failure["code"], required_scopes=tuple(failure["scopes"])
            )

            async def refuse(*args):
                raise raised

            env.policy.select = refuse
        error = None
        try:
            ready = await env.p.complete(target, handle, url, budget())
        except AuthenticationFailure as caught:
            error = caught
        env.policy.select = select
        if expect.get("code") is None and not expect.get("failed"):
            self.assertIsNone(error)
            self.assertIsInstance(ready, Ready)
        else:
            self.assertIsNotNone(error)
            if "code" in expect:
                self.assertEqual(error.code, expect["code"])
            self.assertEqual(list(error.required_scopes), expect.get("scopes", []))
            self.assertIs(error.login_ended, expect["login_ended"])
            if not expect["login_ended"]:
                after = {k: r.generation for k, r in env.grants().items()}
                self.assertEqual(after != before, expect["grant_persisted"])
                # Still pending: the matching callback completes it.
                env.n.token_hook = granting(env.n, " ".join(sorted(stored)))
                self.assertIsInstance(
                    await env.p.complete(
                        target,
                        None,
                        CALLBACK + "?" + urlencode({"state": named, "code": "c"}),
                        budget(),
                    ),
                    Ready,
                )
                return
        after = {k: r.generation for k, r in env.grants().items()}
        self.assertEqual(after != before, expect["grant_persisted"])


if __name__ == "__main__":
    unittest.main()
