"""The cross-SDK scope and step-up contract, one test per rule (1-12).

Every test runs under asyncio and Trio and asserts exact codes and exact
sorted scope tuples.
"""

import unittest
from dataclasses import replace
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx

import test_managed_oauth_runtime as base
from agenthooksprotocol._auth_challenge import insufficient_scope
from agenthooksprotocol.auth import (
    AuthChallenge,
    AuthContext,
    AuthenticationFailure,
    OAuthBinding,
)
from agenthooksprotocol.oauth import (
    OAuthClientConfiguration,
    OperationBudget,
    PendingLogin,
    Ready,
)

RESOURCE, ISSUER = base.RESOURCE, base.ISSUER

# Scope-contract lifecycle ids map to ScopeContractTests; the canonical
# scope_decisions and completions vectors run in test_scope_vectors.
SCOPE_CONTRACT_TESTS = {
    "preset-scopes-requested-not-required": "test_rule_01_preset_scopes_are_requested_not_required",
    "ceiling-refusal-before-network-every-path": "test_rule_03_ceiling_refusal_is_local_on_every_path",
    "requested-outside-ceiling-invalid-configuration": "test_rule_04_requested_outside_ceiling_is_invalid_configuration",
    "challenge-401-scope-requested-not-required": "test_rule_05_401_scope_is_requested_never_required",
    "malformed-challenge-scope-denied": "test_rule_07_malformed_scope_fails_closed",
    "insufficient-scope-already-granted-denied": "test_rule_08_server_insufficient_but_recorded_granted",
    "complete-enforces-stored-required-set": "test_rule_09_complete_enforces_the_logins_required_set",
    "grant-narrower-than-required-denied": "test_rule_10_narrower_grant_fails_with_r_and_persists",
    "host-policy-errors-carry-no-scopes": "test_rule_11_host_policy_errors_never_carry_scopes",
    "complete-error-login-ended": "test_rule_12_complete_errors_report_login_ended",
}


def insufficient(scope=None, identity=None, *, raw=None):
    header = 'Bearer error="insufficient_scope"'
    if raw is not None:
        header += ", " + raw
    elif scope is not None:
        header += ', scope="' + scope + '"'
    return AuthChallenge(403, {"www-authenticate": header}, RESOURCE, identity, True)


def rejected(identity, scope=None):
    header = "Bearer" + (' scope="' + scope + '"' if scope is not None else "")
    return AuthChallenge(401, {"www-authenticate": header}, RESOURCE, identity, True)


def granting(n, scope, *, refresh=True):
    async def token(request):
        return httpx.Response(
            200,
            json={
                "access_token": f"access-{len(n.tokens)}",
                "token_type": "Bearer",
                "expires_in": 60,
                "scope": scope,
                **({"refresh_token": f"refresh-{len(n.tokens)}"} if refresh else {}),
            },
        )

    return token


def calls(n):
    """Every network touch: host authorization checks and sends."""
    return len(n.authorized) + len(n.requests)


class ScopeContractTests(unittest.TestCase):
    run_async = base.ManagedOAuthRuntimeTests.run_async
    complete_login = base.ManagedOAuthRuntimeTests.complete_login

    @staticmethod
    def permissive(policy):
        """Host policy that never refuses: the SDK's own checks decide."""

        async def select(target, resource, issuers, required_scopes, budget):
            await anyio.lowlevel.checkpoint()
            return policy.configuration

        policy.select = select

    async def challenge(self, p, challenge):
        with anyio.CancelScope() as scope:
            context = AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
            return await p.challenge(context, challenge)

    async def credential(self, p):
        with anyio.CancelScope() as scope:
            return await p.credential(
                AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)
            )

    def assertFailure(self, failure, code, scopes=()):
        self.assertEqual(
            (failure.exception.code, failure.exception.required_scopes),
            (code, scopes),
        )

    def test_rule_01_preset_scopes_are_requested_not_required(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            preset = replace(
                target,
                typed_binding=OAuthBinding(
                    ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)
                ),
            )
            # The grant lacks the preset's scope: R is empty, so it is usable.
            n.token_hook = granting(n, "write")
            first = await p.prepare(preset, OperationBudget.after(5))
            self.assertIsInstance(first, Ready)
            self.assertEqual(n.tokens[-1]["scope"], ["read"])
            self.assertEqual(next(iter(s.records.values())).token.scopes, ("write",))
            again = await p.prepare(preset, OperationBudget.after(5))
            self.assertEqual(again.credential.token, first.credential.token)
            self.assertEqual(len(n.tokens), 1)
            # The preset scope never enters an error's scope set.
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    preset, OperationBudget.after(5), required_scopes=("admin",)
                )
            self.assertFailure(failure, "access_denied", ("admin",))
            # A preset must equal the selected client's configured scopes.
            other = replace(
                preset,
                backend_id="other",
                typed_binding=replace(preset.typed_binding, scopes=("files",)),
            )
            before = calls(n)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(other, OperationBudget.after(5))
            self.assertFailure(failure, "invalid_configuration")
            self.assertEqual(calls(n), before)

        self.run_async(run)

    def test_rule_02_one_scope_set_fresh_cached_and_interaction(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                base.Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write", "extra"),
                required_scopes=("write",),
            )
            full = ("admin", "delete", "write")
            # Fresh: discovery-time refusal names H ∪ E ∪ Ch.
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    target,
                    OperationBudget.after(5),
                    challenge=insufficient("admin"),
                    required_scopes=("delete",),
                )
            self.assertFailure(failure, "access_denied", full)
            self.assertFalse(s.bindings)
            n.token_hook = granting(n, "read write")
            first = await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            # Cached: the same set.
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    target,
                    OperationBudget.after(5),
                    challenge=insufficient("admin"),
                    required_scopes=("delete",),
                )
            self.assertFailure(failure, "access_denied", full)
            # Step-up consent names H ∪ Ch, not Ch alone.
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.challenge(
                    p, insufficient("extra", first.credential.identity)
                )
            self.assertFailure(failure, "interaction_required", ("extra", "write"))

        self.run_async(run)

    def test_rule_03_ceiling_refusal_is_local_on_every_path(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            first = await p.prepare(target, OperationBudget.after(5))
            self.assertTrue(s.bindings)
            # A host-required scope outside the ceiling is constructible and
            # refused as access_denied with R, never ValueError.
            policy.configuration = replace(
                policy.configuration, required_scopes=("admin",)
            )
            before = calls(n)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertFailure(failure, "access_denied", ("admin",))
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.credential(p)
            self.assertFailure(failure, "access_denied", ("admin",))
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.challenge(
                    p, insufficient("admin", first.credential.identity)
                )
            self.assertFailure(failure, "access_denied", ("admin",))
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    target, OperationBudget.after(5), required_scopes=("delete",)
                )
            self.assertFailure(failure, "access_denied", ("admin", "delete"))
            # No protected-resource or authorization-server rediscovery.
            self.assertEqual(calls(n), before)
            # A 401 retires the rejected token first, then refuses locally.
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.challenge(p, rejected(first.credential.identity))
            self.assertFailure(failure, "access_denied", ("admin",))
            self.assertEqual(calls(n), before)
            record = next(iter(s.records.values()))
            self.assertIsNone(record.token.access_token)
            self.assertEqual(record.token.refresh_token, "refresh-1")
            # Fresh with a preset binding: refused before any network I/O.
            other = replace(
                target,
                backend_id="other",
                typed_binding=OAuthBinding(
                    ISSUER, RESOURCE, "host-client", "client_credentials", ("read",)
                ),
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(other, OperationBudget.after(5))
            self.assertFailure(failure, "access_denied", ("admin",))
            self.assertEqual(calls(n), before)
            # Unbound: only the protected-resource metadata fetch that client
            # selection needs, and no authorization-server request.
            sent = len(n.requests)
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    replace(target, backend_id="unbound"), OperationBudget.after(5)
                )
            self.assertFailure(failure, "access_denied", ("admin",))
            self.assertEqual(
                [(r.url.host, purpose) for r, purpose in n.requests[sent:]],
                [("resource.test", "metadata")],
            )

        self.run_async(run)

    def test_rule_04_requested_outside_ceiling_is_invalid_configuration(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)

            # Built inside the host's select: never a native error or
            # provider_failed.
            async def select(target, resource, issuers, required_scopes, budget):
                return OAuthClientConfiguration(
                    ISSUER,
                    "host-client",
                    "client_credentials",
                    scopes=("read", "admin"),
                    allowed_scopes=("read",),
                    client_secret="client-secret",
                    token_endpoint_auth_method="client_secret_basic",
                )

            policy.select = select
            preset = replace(
                target,
                typed_binding=OAuthBinding(
                    ISSUER,
                    RESOURCE,
                    "host-client",
                    "client_credentials",
                    ("admin", "read"),
                ),
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(preset, OperationBudget.after(5))
            self.assertFailure(failure, "invalid_configuration")
            self.assertEqual(failure.exception.recovery, "configure")
            self.assertEqual(calls(n), 0)
            # The same on the cached-binding path.
            self.permissive(policy)
            await p.prepare(target, OperationBudget.after(5))
            before = calls(n)
            policy.configuration = replace(
                policy.configuration, scopes=("read", "admin"), allowed_scopes=("read",)
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.credential(p)
            self.assertFailure(failure, "invalid_configuration")
            self.assertEqual(calls(n), before)

        self.run_async(run)

    def test_rule_05_401_scope_is_requested_never_required(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            # Client credentials without refresh tokens: each 401 reissues.
            n.token_hook = granting(n, "read", refresh=False)
            first = await p.prepare(target, OperationBudget.after(5))
            # The server grants less than the hint: still not a step-up.
            second = await self.challenge(
                p, rejected(first.credential.identity, "write")
            )
            self.assertEqual(second.token, "access-2")
            self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
            self.assertEqual(n.tokens[-1]["scope"], ["read write"])
            # Out-of-ceiling hints are simply not requested.
            third = await self.challenge(p, rejected(second.identity, "admin"))
            self.assertEqual(third.token, "access-3")
            self.assertEqual(n.tokens[-1]["scope"], ["read"])
            # The hint was this operation's only: a later acquisition does
            # not request it.
            now[0] += 61
            later = await self.credential(p)
            self.assertEqual(later.token, "access-4")
            self.assertEqual(n.tokens[-1]["scope"], ["read"])
            # PKCE: a sign-in never requests a 401 hint, and R ignores it.
            policy.configuration = replace(
                base.Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write"),
            )
            pkce = replace(target, backend_id="pkce")
            login = await p.prepare(
                pkce, OperationBudget.after(5), challenge=rejected(None, "write")
            )
            self.assertIsInstance(login, PendingLogin)
            query = parse_qs(urlsplit(login.authorization_url).query)
            self.assertEqual(query["scope"], ["read"])
            n.token_hook = granting(n, "read")
            self.assertIsInstance(await self.complete_login(p, pkce, login), Ready)

        self.run_async(run)

    def test_rule_06_403_without_scope_uses_host_and_explicit(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            first = await p.prepare(target, OperationBudget.after(5))
            count = len(n.tokens)
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.challenge(p, insufficient(None, first.credential.identity))
            self.assertFailure(failure, "access_denied")
            self.assertEqual(failure.exception.recovery, "none")
            self.assertEqual(len(n.tokens), count)
            policy.configuration = replace(
                policy.configuration, required_scopes=("write",)
            )
            n.token_hook = granting(n, "read write")
            stepped = await self.challenge(
                p, insufficient(None, first.credential.identity)
            )
            self.assertEqual(stepped.token, f"access-{count + 1}")
            self.assertEqual(n.tokens[-1]["scope"], ["read write"])

        self.run_async(run)

    def test_rule_07_malformed_scope_fails_closed(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            first = await p.prepare(target, OperationBudget.after(5))
            count = calls(n)
            for raw in (
                'scope=""',
                'scope="read  write"',
                'scope=" read"',
                'scope="read "',
                'scope="read\\\\write"',
                'scope="read", scope="write"',
            ):
                with self.subTest(raw=raw):
                    challenge = insufficient(
                        raw=raw, identity=first.credential.identity
                    )
                    # The transport routes it; the provider refuses it.
                    self.assertTrue(insufficient_scope(challenge.headers))
                    with self.assertRaises(AuthenticationFailure) as failure:
                        await self.challenge(p, challenge)
                    self.assertFailure(failure, "access_denied")
                    self.assertEqual(failure.exception.recovery, "none")
            self.assertEqual(calls(n), count)
            # A malformed explicit requirement is a configuration error, never
            # an emptied set.
            for scopes in (("bad scope",), ("write", ""), "write", ("w\\x",)):
                with self.subTest(scopes=scopes):
                    with self.assertRaises(AuthenticationFailure) as failure:
                        await p.prepare(
                            target, OperationBudget.after(5), required_scopes=scopes
                        )
                    self.assertFailure(failure, "invalid_configuration")
            self.assertEqual(calls(n), count)

        self.run_async(run)

    def test_rule_08_server_insufficient_but_recorded_granted(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                base.Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write"),
            )
            n.token_hook = granting(n, "read write")
            first = await self.complete_login(
                p,
                target,
                await p.prepare(
                    target, OperationBudget.after(5), required_scopes=("write",)
                ),
            )
            count = calls(n)
            records = dict(s.records)
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.challenge(
                    p, insufficient("write", first.credential.identity)
                )
            self.assertFailure(failure, "access_denied", ("write",))
            # No replay, refresh, consent loop or login.
            self.assertEqual(calls(n), count)
            self.assertEqual(s.records, records)
            self.assertFalse(base.pending_logins(p))
            # A host prepare for the same challenge does not loop either.
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    target,
                    OperationBudget.after(5),
                    challenge=insufficient("write", first.credential.identity),
                )
            self.assertFailure(failure, "access_denied", ("write",))
            self.assertFalse(base.pending_logins(p))

        self.run_async(run)

    def test_rule_09_complete_enforces_the_logins_required_set(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                base.Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write", "extra"),
                required_scopes=("extra",),
            )
            login = await p.prepare(
                target,
                OperationBudget.after(5),
                challenge=insufficient("write"),
                required_scopes=("read",),
            )
            self.assertEqual(
                base.pending_logins(p)[0].required_scopes, ("extra", "read", "write")
            )
            # Host-required scopes change after prepare: the stored R decides.
            policy.configuration = replace(policy.configuration, required_scopes=())
            n.token_hook = granting(n, "read extra")
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            self.assertFailure(failure, "access_denied", ("extra", "read", "write"))
            self.assertIs(failure.exception.login_ended, True)
            # The grant and refresh token are persisted; the login is consumed.
            token = next(iter(s.records.values())).token
            self.assertEqual(token.scopes, ("extra", "read"))
            self.assertEqual(token.refresh_token, "refresh-1")
            self.assertFalse(base.pending_logins(p))
            # A current ceiling that hides a stored required scope: the grant
            # persists, the login is consumed, the stored R is named.
            login = await p.prepare(
                target, OperationBudget.after(5), required_scopes=("write",)
            )
            ceiling = policy.configuration
            policy.configuration = replace(ceiling, allowed_scopes=("read",))
            n.token_hook = granting(n, "read write")
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            self.assertFailure(failure, "access_denied", ("write",))
            self.assertIs(failure.exception.login_ended, True)
            token = next(iter(s.records.values())).token
            self.assertEqual(token.scopes, ("read", "write"))
            self.assertFalse(base.pending_logins(p))
            # Within the restored ceiling the persisted grant covers R.
            policy.configuration = ceiling
            ready = await p.prepare(
                target, OperationBudget.after(5), required_scopes=("write",)
            )
            self.assertIsInstance(ready, Ready)

        self.run_async(run)

    def test_rule_10_narrower_grant_fails_with_r_and_persists(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                policy.configuration,
                allowed_scopes=("read", "write"),
                required_scopes=("write",),
            )
            n.token_hook = granting(n, "read")
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    target, OperationBudget.after(5), required_scopes=("read",)
                )
            self.assertFailure(failure, "access_denied", ("read", "write"))
            token = next(iter(s.records.values())).token
            self.assertEqual(token.scopes, ("read",))
            self.assertEqual(token.access_token, "access-1")
            # Refresh narrower than R (PKCE), with the rotation persisted.
            policy.configuration = replace(
                base.Policy("authorization_code_pkce").configuration,
                allowed_scopes=("read", "write"),
            )
            pkce = replace(target, backend_id="pkce")
            n.token_hook = granting(n, "read write")
            await self.complete_login(
                p, pkce, await p.prepare(pkce, OperationBudget.after(5))
            )
            now[0] += 61
            n.token_hook = granting(n, "read")
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(
                    pkce, OperationBudget.after(5), required_scopes=("write",)
                )
            self.assertFailure(failure, "access_denied", ("write",))
            self.assertEqual(n.tokens[-1]["grant_type"], ["refresh_token"])
            refreshed = [
                r.token
                for r in s.records.values()
                if r.token.refresh_token == "refresh-3"
            ]
            self.assertEqual(len(refreshed), 1)
            self.assertEqual(refreshed[0].scopes, ("read",))

        self.run_async(run)

    def test_rule_11_host_policy_errors_never_carry_scopes(self):
        async def run(p, n, s, policy, target, now):
            raised = AuthenticationFailure(
                code="access_denied", required_scopes=("secret",)
            )
            self.assertEqual(raised.required_scopes, ("secret",))

            async def select(target, resource, issuers, required_scopes, budget):
                raise AuthenticationFailure(
                    code="interaction_required", required_scopes=("secret",)
                )

            async def resource(target, budget):
                raise AuthenticationFailure(
                    code="access_denied", required_scopes=("secret",)
                )

            original = policy.select
            policy.select = select
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertFailure(failure, "interaction_required")
            policy.select = original
            original_resource = policy.resource
            policy.resource = resource
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertFailure(failure, "access_denied")
            policy.resource = original_resource

            # Destination check (host network policy) on the token endpoint.
            async def authorize(url, purpose, budget):
                if purpose == "token":
                    raise AuthenticationFailure(
                        code="access_denied", required_scopes=("secret",)
                    )
                n.authorized.append((url, purpose))

            n.authorize = authorize
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertFailure(failure, "access_denied")

        self.run_async(run)

    def test_rule_12_complete_errors_report_login_ended(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = base.Policy("authorization_code_pkce").configuration
            budget = lambda: OperationBudget.after(5)  # noqa: E731

            def state(login):
                return parse_qs(urlsplit(login.authorization_url).query)["state"][0]

            async def complete(login, url, code, ended, handle=True):
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.complete(target, login if handle else None, url, budget())
                self.assertEqual(
                    (failure.exception.code, failure.exception.login_ended),
                    (code, ended),
                )

            login = await p.prepare(target, budget())
            good = "https://host.test/callback?" + urlencode(
                {"state": state(login), "code": "valid"}
            )
            # Rejected before the claim: still pending.
            await complete(
                login,
                "https://evil.test/callback?"
                + urlencode({"state": state(login), "code": "valid"}),
                "access_denied",
                False,
            )
            await complete(
                login,
                good + "&iss=" + "https%3A%2F%2Fother.test",
                "access_denied",
                False,
            )
            original = policy.select

            async def failing(*args):
                raise AuthenticationFailure(code="provider_failed")

            policy.select = failing
            await complete(login, good, "provider_failed", False)
            policy.select = original
            self.assertEqual(len(base.pending_logins(p)), 1)
            # The handle names another login than the callback's state: an
            # invalid callback, both logins pending.
            second = await p.prepare(target, budget())
            await complete(
                login,
                "https://host.test/callback?"
                + urlencode({"state": state(second), "code": "valid"}),
                "access_denied",
                False,
            )
            # Duplicated parameters, or both code and error.
            await complete(login, good + "&code=again", "access_denied", False)
            await complete(login, good + "&error=access_denied", "access_denied", False)
            self.assertEqual(len(base.pending_logins(p)), 2)
            # Unknown, absent or ended state: interaction_required, whatever
            # handle is passed.
            await complete(
                login,
                "https://host.test/callback?state=unknown&code=valid",
                "interaction_required",
                True,
            )
            await complete(
                None,
                "https://host.test/callback?state=unknown&code=valid",
                "interaction_required",
                True,
                handle=False,
            )
            await complete(
                None,
                "https://host.test/callback?code=valid",
                "interaction_required",
                True,
                handle=False,
            )
            # Consumed by a consent denial.
            await complete(
                login,
                "https://host.test/callback?"
                + urlencode({"state": state(login), "error": "access_denied"}),
                "access_denied",
                True,
            )
            await complete(login, good, "interaction_required", True)
            # Consumed by a failed exchange.
            login = await p.prepare(target, budget())

            async def invalid_grant(request):
                return httpx.Response(400, json={"error": "invalid_grant"})

            n.token_hook = invalid_grant
            await complete(
                login,
                "https://host.test/callback?"
                + urlencode({"state": state(login), "code": "spent"}),
                "interaction_required",
                True,
            )
            # Expired.
            n.token_hook = None
            login = await p.prepare(target, budget())
            now[0] = login.expires_at
            await complete(
                login,
                "https://host.test/callback?"
                + urlencode({"state": state(login), "code": "valid"}),
                "interaction_required",
                True,
            )

        self.run_async(run)


if __name__ == "__main__":
    unittest.main()
