"""Scope contract v2, section 7: the decision table, entry-point routing
(including the auth transport), the generation race, a pending record from an
older release, and host failures that never carry scopes.

Every provider test runs under asyncio and Trio.
"""

import unittest
from contextlib import asynccontextmanager
from dataclasses import replace
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx

import test_managed_oauth_runtime as base
from test_registration_auth import intercept_request
from test_scope_vectors import recording

from agenthooksprotocol.auth import (
    AuthChallenge,
    AuthContext,
    AuthenticatedHTTPTransport,
    AuthenticationFailure,
    RoutingAuthProvider,
)
from agenthooksprotocol.oauth import (
    OAuthPendingLogins,
    OAuthRecord,
    OperationBudget,
    Ready,
)
from agenthooksprotocol.runtime import ProtocolError
from agenthooksprotocol._scope_decision import (
    DecisionFailure,
    Grant,
    Policy,
    classify,
    classify_challenge,
    decide,
)

RESOURCE = base.RESOURCE

# Scope-contract v2 lifecycle ids map to ProviderTests.
SCOPE_DECIDE_TESTS = {
    "entry-points-route-through-decide": "test_every_entry_point_goes_through_decide",
    "transport-challenge-routing": "test_transport_routes_to_the_provider",
    "replay-rejection-retires-token": "test_transport_routes_to_the_provider",
    "complete-token-endpoint-errors-classified": "test_complete_token_endpoint_errors_are_classified",
    "renewal-token-errors-classified": "test_refresh_and_reissue_token_errors_are_classified",
}
PKCE, CC = "authorization_code_pkce", "client_credentials"


def challenge(status, header=None):
    headers = {} if header is None else {"www-authenticate": header}
    return AuthChallenge(status, headers, RESOURCE, None, True)


def insufficient(scope=None):
    value = 'Bearer error="insufficient_scope"'
    return challenge(403, value if scope is None else value + f', scope="{scope}"')


def grant(granted, *, generation="g1", valid=True, refresh=False):
    return Grant(generation, tuple(granted), valid, refresh)


def policy(flow=PKCE, S=("read",), C=None, H=(), preset=None):
    return Policy(flow, tuple(S), tuple(C if C is not None else S), tuple(H), preset)


PENDING = object()

# (name, op, policy, explicit, challenge, grant, sent) -> expected outcome:
# ("fail", code, scopes, retire) or (action, required, request, retire).
TABLE = [
    # 1. Configuration, before everything else.
    (
        "requested outside ceiling",
        "prepare",
        policy(S=("read", "admin"), C=("read",)),
        (),
        None,
        None,
        None,
        ("fail", "invalid_configuration", (), False),
    ),
    (
        "preset differs",
        "credential",
        policy(preset=("files",)),
        (),
        None,
        None,
        None,
        ("fail", "invalid_configuration", (), False),
    ),
    (
        "preset mismatch before ceiling",
        "prepare",
        policy(preset=("files",), H=("admin",)),
        (),
        None,
        None,
        None,
        ("fail", "invalid_configuration", (), False),
    ),
    (
        "omitted preset is no constraint",
        "credential",
        policy(preset=None),
        (),
        None,
        grant(("read",)),
        None,
        ("use", (), (), False),
    ),
    (
        "invalid explicit token",
        "prepare",
        policy(),
        ("bad scope",),
        None,
        None,
        None,
        ("fail", "invalid_configuration", (), False),
    ),
    (
        "explicit not a tuple",
        "prepare",
        policy(),
        "write",
        None,
        None,
        None,
        ("fail", "invalid_configuration", (), False),
    ),
    (
        "config before malformed challenge",
        "challenge",
        policy(S=("a",), C=()),
        (),
        challenge(403, "Bearer scope="),
        None,
        None,
        ("fail", "invalid_configuration", (), False),
    ),
    # 2. Challenge form.
    (
        "malformed scope",
        "challenge",
        policy(C=("read", "write")),
        (),
        insufficient("read  write"),
        grant(("read",)),
        "g1",
        ("fail", "access_denied", (), False),
    ),
    (
        "two Bearer challenges, still retired",
        "challenge",
        policy(),
        (),
        challenge(401, "Bearer, Bearer"),
        grant(("read",)),
        "g1",
        ("fail", "access_denied", (), True),
    ),
    (
        "malformed 401 still retires",
        "challenge",
        policy(flow=CC),
        (),
        challenge(401, 'Bearer scope="a  b"'),
        grant(("read",)),
        "g1",
        ("fail", "access_denied", (), True),
    ),
    (
        "401 config error still retires",
        "challenge",
        policy(S=("a",), C=()),
        (),
        challenge(401, "Bearer"),
        grant(("read",)),
        "g1",
        ("fail", "invalid_configuration", (), True),
    ),
    (
        "403 other",
        "challenge",
        policy(),
        (),
        challenge(403, 'Bearer error="invalid_token"'),
        grant(("read",)),
        "g1",
        ("fail", "access_denied", (), False),
    ),
    (
        "403 without header",
        "challenge",
        policy(),
        (),
        challenge(403),
        grant(("read",)),
        "g1",
        ("fail", "access_denied", (), False),
    ),
    (
        "bare insufficient without H or E",
        "challenge",
        policy(),
        (),
        insufficient(),
        grant(("read",)),
        "g1",
        ("fail", "access_denied", (), False),
    ),
    (
        "bare insufficient uses H",
        "challenge",
        policy(S=("read", "write"), H=("write",)),
        (),
        insufficient(),
        grant(("read",)),
        "g1",
        ("fail", "interaction_required", ("write",), False),
    ),
    # 0/3. 401: retire first; the hint is this client-credentials
    # acquisition's only.
    (
        "401 retires and acquires with hint",
        "challenge",
        policy(flow=CC, C=("read", "write")),
        (),
        challenge(401, 'Bearer scope="write admin"'),
        grant(("read",), generation="g2", valid=False),
        "g1",
        ("acquire", (), ("read", "write"), True),
    ),
    (
        "401 hint is never a PKCE requirement",
        "challenge",
        policy(C=("read", "write"), H=("read",)),
        (),
        challenge(401, 'Bearer scope="write"'),
        grant(("read",), generation="g2", valid=False),
        "g1",
        ("fail", "interaction_required", ("read",), True),
    ),
    (
        "401 insufficient_scope error is a 401",
        "challenge",
        policy(S=("read", "write"), H=("read",)),
        (),
        challenge(401, 'Bearer error="insufficient_scope", scope="write"'),
        grant(("read",), generation="g2", valid=False),
        "g1",
        ("fail", "interaction_required", ("read",), True),
    ),
    (
        "401 for an older generation uses the current",
        "challenge",
        policy(flow=CC, H=("read",)),
        (),
        challenge(401, "Bearer"),
        grant(("read",), generation="g2"),
        "g1",
        ("use", ("read",), (), True),
    ),
    # 4. Ceiling.
    (
        "ceiling refusal names R",
        "prepare",
        policy(H=("read", "admin")),
        ("files",),
        insufficient("delete"),
        None,
        None,
        ("fail", "access_denied", ("admin", "delete", "files", "read"), False),
    ),
    (
        "ceiling refusal retires on 401",
        "challenge",
        policy(flow=CC, H=("admin",)),
        (),
        challenge(401, "Bearer"),
        PENDING,
        "g1",
        ("fail", "access_denied", ("admin",), True),
    ),
    (
        "ceiling before the grant",
        "credential",
        policy(H=("admin",)),
        (),
        None,
        PENDING,
        None,
        ("fail", "access_denied", ("admin",), False),
    ),
    (
        "pre-phase proceeds",
        "prepare",
        policy(),
        (),
        None,
        PENDING,
        None,
        ("proceed", (), (), False),
    ),
    # 5. The server disagrees with our record.
    (
        "insufficient but recorded",
        "challenge",
        policy(S=("read", "write"), H=("read",)),
        (),
        insufficient("write"),
        grant(("read", "write")),
        "g1",
        ("fail", "access_denied", ("read", "write"), False),
    ),
    (
        "insufficient, nothing sent",
        "challenge",
        policy(S=("read", "write")),
        (),
        insufficient("write"),
        grant(("read", "write")),
        None,
        ("fail", "access_denied", ("write",), False),
    ),
    (
        "insufficient, newer generation used",
        "challenge",
        policy(S=("read", "write")),
        (),
        insufficient("write"),
        grant(("read", "write"), generation="g2"),
        "g1",
        ("use", ("write",), (), False),
    ),
    # 6. Use.
    (
        "use",
        "credential",
        policy(H=("read",)),
        (),
        None,
        grant(("read",)),
        None,
        ("use", ("read",), (), False),
    ),
    (
        "narrowed ceiling hides a granted scope",
        "credential",
        policy(S=(), C=(), H=()),
        (),
        None,
        grant(("read",)),
        None,
        ("use", (), (), False),
    ),
    # 7. Refresh.
    (
        "refresh",
        "credential",
        policy(H=("read",)),
        (),
        None,
        grant(("read",), valid=False, refresh=True),
        None,
        ("refresh", ("read",), (), False),
    ),
    (
        "no refresh for a wider R",
        "credential",
        policy(flow=CC, S=("read", "write")),
        ("write",),
        None,
        grant(("read",), valid=False, refresh=True),
        None,
        ("acquire", ("write",), ("read", "write"), False),
    ),
    # Client credentials never refresh: they always reissue.
    (
        "client credentials reissue despite a refresh token",
        "credential",
        policy(flow=CC, H=("read",)),
        (),
        None,
        grant(("read",), valid=False, refresh=True),
        None,
        ("acquire", ("read",), ("read",), False),
    ),
    # 8. Client credentials.
    (
        "acquire keeps previous",
        "prepare",
        policy(flow=CC, C=("read", "write")),
        ("write",),
        None,
        grant(("other",), valid=False),
        None,
        ("acquire", ("write",), ("other", "read", "write"), False),
    ),
    # 9. PKCE.
    (
        "login stores R",
        "prepare",
        policy(S=("files", "read", "write"), H=("read",)),
        ("files",),
        None,
        None,
        None,
        ("login", ("files", "read"), ("files", "read", "write"), False),
    ),
    (
        "delivery needs interaction",
        "credential",
        policy(H=("read",)),
        (),
        None,
        None,
        None,
        ("fail", "interaction_required", ("read",), False),
    ),
    (
        "step-up needs interaction",
        "challenge",
        policy(S=("read", "write"), H=("read",)),
        (),
        insufficient("write"),
        grant(("read",)),
        "g1",
        ("fail", "interaction_required", ("read", "write"), False),
    ),
]


class DecisionTableTests(unittest.TestCase):
    def test_decide_table(self):
        for name, op, scope, explicit, raw, stored, sent, expected in TABLE:
            with self.subTest(name):
                classified = classify_challenge(raw)
                arguments = (op, scope, explicit, classified)
                try:
                    if stored is PENDING:
                        outcome = decide(*arguments, sent=sent)
                    else:
                        outcome = decide(*arguments, stored, sent)
                except DecisionFailure as failure:
                    code, recovery, scopes = classify(failure)
                    self.assertEqual(
                        ("fail", code, scopes, failure.retire), expected, name
                    )
                else:
                    self.assertEqual(
                        (
                            outcome.action,
                            outcome.required,
                            outcome.request,
                            outcome.retire,
                        ),
                        expected,
                    )

    def test_classify_strips_everything_but_decide(self):
        for error in (
            AuthenticationFailure(code="access_denied", required_scopes=("a",)),
            AuthenticationFailure(code="interaction_required", required_scopes=("a",)),
            ValueError("host"),
        ):
            self.assertEqual(classify(error)[2], ())
        self.assertEqual(
            classify(DecisionFailure("access_denied", ("b", "a", "a"))),
            ("access_denied", None, ("a", "b")),
        )
        self.assertEqual(classify(DecisionFailure("provider_failed", ("a",)))[2], ())


class ProviderTests(unittest.TestCase):
    run_async = base.ManagedOAuthRuntimeTests.run_async
    complete_login = base.ManagedOAuthRuntimeTests.complete_login

    @staticmethod
    def permissive(policy):
        async def select(target, resource, issuers, required_scopes, budget):
            return policy.configuration

        policy.select = select

    @staticmethod
    def context(scope):
        return AuthContext({"id": "backend"}, None, RESOURCE, "event", scope)

    def test_every_entry_point_goes_through_decide(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                policy.configuration, allowed_scopes=("read", "write")
            )
            with recording() as decisions, anyio.CancelScope() as scope:
                first = await p.prepare(target, OperationBudget.after(5))
                self.assertEqual(decisions[-1][0].action, "acquire")
                count = len(decisions)
                # Bound delivery and the up-front lookup.
                bound = AuthContext(
                    {"id": "backend"},
                    {
                        "type": "oauth",
                        "flow": CC,
                        "issuer": base.ISSUER,
                        "resource": RESOURCE,
                        "clientId": "host-client",
                    },
                    RESOURCE,
                    "event",
                    scope,
                )
                for entry in (bound, self.context(scope)):
                    credential = await p.credential(entry)
                    self.assertEqual(credential.token, first.credential.token)
                    self.assertEqual(decisions[-1][0].action, "use")
                    self.assertGreater(len(decisions), count)
                    count = len(decisions)
                # challenge (401 and 403).
                renewed = await p.challenge(
                    self.context(scope),
                    AuthChallenge(
                        401,
                        {"www-authenticate": "Bearer"},
                        RESOURCE,
                        first.credential.identity,
                        True,
                    ),
                )
                self.assertTrue(decisions[-1][0].retire)
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(
                        self.context(scope),
                        AuthChallenge(
                            403,
                            {
                                "www-authenticate": 'Bearer error="insufficient_scope",'
                                ' scope="read  write"'
                            },
                            RESOURCE,
                            renewed.identity,
                            True,
                        ),
                    )
                self.assertEqual(
                    (failure.exception.code, failure.exception.required_scopes),
                    ("access_denied", ()),
                )

        self.run_async(run)

    def test_transport_routes_to_the_provider(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            await p.prepare(target, OperationBudget.after(5))
            message = intercept_request()

            async def over(responses, seen=None):
                seen = [] if seen is None else seen

                async def deliver(request):
                    seen.append(request.headers.get("authorization"))
                    response = responses[min(len(seen), len(responses)) - 1]
                    if response == "ok":
                        return httpx.Response(
                            200,
                            json={
                                "jsonrpc": "2.0",
                                "id": message["id"],
                                "result": {"protocolVersion": "draft", "effects": []},
                            },
                        )
                    return response

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
                    try:
                        await transport.request(message)
                    finally:
                        await transport.aclose()
                return seen

            # A malformed-scope 403 insufficient_scope reaches the provider,
            # which refuses it: not a raw 403.
            malformed = httpx.Response(
                403,
                headers={
                    "www-authenticate": 'Bearer error="insufficient_scope", scope=""'
                },
            )
            with self.assertRaises(AuthenticationFailure) as failure:
                await over([malformed])
            self.assertEqual(failure.exception.code, "access_denied")
            # A 401 with an insufficient_scope error is a 401: retired and
            # renewed, then replayed once.
            stepped = httpx.Response(
                401,
                headers={
                    "www-authenticate": 'Bearer error="insufficient_scope", scope="write"'
                },
            )
            seen = await over([stepped, "ok"])
            self.assertEqual(len(seen), 2)
            self.assertNotEqual(seen[0], seen[1])
            # A token rejected on the replay goes to the provider: retired.
            rejected = httpx.Response(401, headers={"www-authenticate": "Bearer"})
            seen = []
            with self.assertRaises(ProtocolError):
                await over([rejected], seen)
            self.assertEqual(len(seen), 2)
            record = next(iter(s.records.values()))
            # The replayed token was retired and renewed, never kept.
            self.assertNotIn("Bearer " + str(record.token.access_token), seen)
            # Any other 403 is returned without a retry.
            other = httpx.Response(403, headers={"www-authenticate": "Basic"})
            with self.assertRaises(ProtocolError):
                seen = await over([other])

        self.run_async(run)

    def test_401_retires_before_every_other_step(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            first = await p.prepare(target, OperationBudget.after(5))
            count = len(n.requests)

            async def refuse(*args):
                raise AuthenticationFailure(code="access_denied")

            # Even a malformed challenge with host policy refusing: the token
            # that was sent is retired first.
            policy.select = refuse
            with (
                anyio.CancelScope() as scope,
                self.assertRaises(AuthenticationFailure) as failure,
            ):
                await p.challenge(
                    self.context(scope),
                    AuthChallenge(
                        401,
                        {"www-authenticate": 'Bearer scope=" bad"'},
                        RESOURCE,
                        first.credential.identity,
                        True,
                    ),
                )
            self.assertEqual(failure.exception.required_scopes, ())
            record = next(iter(s.records.values()))
            self.assertIsNone(record.token.access_token)
            self.assertEqual(record.token.refresh_token, "refresh-1")
            # No token request: only a protected-resource fetch to repair the
            # binding the host refused.
            self.assertFalse(
                [r for r, purpose in n.requests[count:] if purpose == "token"]
            )

        self.run_async(run)

    def test_401_retires_before_target_and_configuration_checks(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            first = await p.prepare(target, OperationBudget.after(5))

            def retired():
                record = next(iter(s.records.values()))
                return record.token.access_token is None

            rejected = AuthChallenge(
                401,
                {"www-authenticate": "Bearer"},
                RESOURCE,
                first.credential.identity,
                True,
            )
            with anyio.CancelScope() as scope:
                # A target the attempt does not belong to (a bearer binding):
                # the target check fails, after the token is retired.
                bearer = AuthContext(
                    {"id": "backend"},
                    {"type": "bearer", "tokenEnv": "TOKEN"},
                    RESOURCE,
                    "event",
                    scope,
                )
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(bearer, rejected)
            self.assertEqual(
                (failure.exception.code, failure.exception.required_scopes),
                ("invalid_configuration", ()),
            )
            self.assertTrue(retired())
            # A configuration failure (requested outside the ceiling): the
            # renewed token is retired first too.
            second = await p.prepare(target, OperationBudget.after(5))
            policy.configuration = replace(
                policy.configuration, scopes=("read", "admin"), allowed_scopes=("read",)
            )
            with (
                anyio.CancelScope() as scope,
                self.assertRaises(AuthenticationFailure) as failure,
            ):
                await p.challenge(
                    self.context(scope),
                    replace(rejected, attempted_identity=second.credential.identity),
                )
            self.assertEqual(failure.exception.code, "invalid_configuration")
            self.assertTrue(retired())

        self.run_async(run)

    def test_destination_check_runs_before_claiming_a_consent_denial(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = base.Policy(PKCE).configuration
            login = await p.prepare(target, OperationBudget.after(5))
            authorize = n.authorize
            checked = []

            async def refuse(url, purpose, budget):
                if purpose == "authorization" and url.startswith(
                    "https://host.test/callback"
                ):
                    checked.append(url)
                    raise AuthenticationFailure(
                        code="untrusted_destination", required_scopes=("read",)
                    )
                await authorize(url, purpose, budget)

            n.authorize = refuse
            state = parse_qs(urlsplit(login.authorization_url).query)["state"][0]
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.complete(
                    target,
                    login,
                    "https://host.test/callback?"
                    + urlencode({"state": state, "error": "access_denied"}),
                    OperationBudget.after(5),
                )
            self.assertEqual(
                (
                    failure.exception.code,
                    failure.exception.required_scopes,
                    failure.exception.login_ended,
                ),
                ("untrusted_destination", (), False),
            )
            self.assertTrue(checked)
            self.assertEqual([item.state for item in base.pending_logins(p)], [state])

        self.run_async(run)

    def test_pkce_step_up_needing_consent_makes_no_server_request(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                base.Policy(PKCE).configuration, scopes=("read", "write")
            )
            first = await self.complete_login(
                p, target, await p.prepare(target, OperationBudget.after(5))
            )
            authorize = n.authorize

            async def refuse(url, purpose, budget):
                # Every authorization-server destination is refused.
                if urlsplit(url).hostname == "issuer.test":
                    raise AuthenticationFailure(code="untrusted_destination")
                await authorize(url, purpose, budget)

            n.authorize = refuse
            count = len(n.requests)
            with (
                anyio.CancelScope() as scope,
                self.assertRaises(AuthenticationFailure) as failure,
            ):
                await p.challenge(
                    self.context(scope),
                    AuthChallenge(
                        403,
                        {
                            "www-authenticate": 'Bearer error="insufficient_scope",'
                            ' scope="write"'
                        },
                        RESOURCE,
                        first.credential.identity,
                        True,
                    ),
                )
            self.assertEqual(
                (failure.exception.code, failure.exception.required_scopes),
                ("interaction_required", ("write",)),
            )
            self.assertEqual(len(n.requests), count)

        self.run_async(run)

    def test_newer_generation_than_the_one_sent_is_used(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                policy.configuration,
                scopes=("read", "write"),
                required_scopes=("write",),
            )
            n.token_hook = None

            async def token(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"access-{len(n.tokens)}",
                        "token_type": "Bearer",
                        "expires_in": 60,
                        "scope": "read write",
                    },
                )

            n.token_hook = token
            first = await p.prepare(target, OperationBudget.after(5))
            now[0] += 61
            second = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(first.credential.token, second.credential.token)
            count = len(n.tokens)
            with anyio.CancelScope() as scope:
                # The first token is rejected as insufficient, but a newer
                # generation covering R exists: it is used, not refused.
                used = await p.challenge(
                    self.context(scope),
                    AuthChallenge(
                        403,
                        {
                            "www-authenticate": 'Bearer error="insufficient_scope",'
                            ' scope="write"'
                        },
                        RESOURCE,
                        first.credential.identity,
                        True,
                    ),
                )
                self.assertEqual(used.token, second.credential.token)
                # The same for the newest generation itself is refused.
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.challenge(
                        self.context(scope),
                        AuthChallenge(
                            403,
                            {
                                "www-authenticate": 'Bearer error="insufficient_scope",'
                                ' scope="write"'
                            },
                            RESOURCE,
                            second.credential.identity,
                            True,
                        ),
                    )
            self.assertEqual(
                (failure.exception.code, failure.exception.required_scopes),
                ("access_denied", ("write",)),
            )
            self.assertEqual(len(n.tokens), count)

        self.run_async(run)

    def test_pending_record_from_an_older_release(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                base.Policy(PKCE).configuration,
                scopes=("read", "write"),
                required_scopes=("write",),
            )
            login = await p.prepare(target, OperationBudget.after(5))
            # An older release stored no R on the pending login.
            for key, record in list(p._logins.records.items()):
                p._logins.records[key] = OAuthPendingLogins(
                    record.generation,
                    tuple(
                        replace(item, required_scopes=None) for item in record.logins
                    ),
                )
            # The current host no longer requires write; the prepare-time H
            # (held by the record) still applies.
            policy.configuration = replace(policy.configuration, required_scopes=())

            async def narrow(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "narrow",
                        "token_type": "Bearer",
                        "scope": "read",
                    },
                )

            n.token_hook = narrow
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            self.assertEqual(
                (
                    failure.exception.code,
                    failure.exception.required_scopes,
                    failure.exception.login_ended,
                ),
                ("access_denied", ("write",), True),
            )
            records = [r for r in s.records.values() if isinstance(r, OAuthRecord)]
            self.assertEqual(records[0].token.scopes, ("read",))

        self.run_async(run)

    def test_host_failures_carry_no_scopes(self):
        scoped = AuthenticationFailure(
            code="interaction_required", required_scopes=("secret",)
        )

        async def raise_scoped(*args, **kwargs):
            raise scoped

        def assert_stripped(test, failure, code="interaction_required"):
            test.assertEqual(
                (failure.exception.code, failure.exception.required_scopes),
                (code, ()),
            )

        async def store_failure(p, n, s, policy, target, now):
            s.load_binding = raise_scoped
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            assert_stripped(self, failure)

        async def coordinated_store_failure(p, n, s, policy, target, now):
            original = s.coordinate

            @asynccontextmanager
            async def coordinate(key, budget):
                raise scoped
                async with original(key, budget) as guard:  # pragma: no cover
                    yield guard

            s.coordinate = coordinate
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            assert_stripped(self, failure)

        async def network_failure(p, n, s, policy, target, now):
            n.send = raise_scoped
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            assert_stripped(self, failure)

        async def destination_failure(p, n, s, policy, target, now):
            n.authorize = raise_scoped
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            assert_stripped(self, failure)

        async def callback_failure(p, n, s, policy, target, now):
            policy.configuration = base.Policy(PKCE).configuration
            login = await p.prepare(target, OperationBudget.after(5))
            policy.select = raise_scoped
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            assert_stripped(self, failure)
            self.assertIs(failure.exception.login_ended, False)

        async def source_failure(p, n, s, policy, target, now):
            policy.configuration = base.Policy(PKCE).configuration
            login = await p.prepare(target, OperationBudget.after(5))
            # Host policy now selects another client: the login's client
            # source is no longer permitted. The login stays pending.
            policy.configuration = replace(policy.configuration, client_id="other")
            self.permissive(policy)
            with self.assertRaises(AuthenticationFailure) as failure:
                await self.complete_login(p, target, login)
            assert_stripped(self, failure, "invalid_configuration")
            self.assertIs(failure.exception.login_ended, False)
            self.assertEqual(len(base.pending_logins(p)), 1)

        async def unparseable_callback(p, n, s, policy, target, now):
            policy.configuration = base.Policy(PKCE).configuration
            login = await p.prepare(target, OperationBudget.after(5))
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.complete(
                    target,
                    login,
                    "https://host.test:99999999/callback?state=x",
                    OperationBudget.after(5),
                )
            assert_stripped(self, failure, "access_denied")
            self.assertIs(failure.exception.login_ended, False)

        for test in (
            store_failure,
            coordinated_store_failure,
            network_failure,
            destination_failure,
            callback_failure,
            source_failure,
            unparseable_callback,
        ):
            with self.subTest(test.__name__):
                self.run_async(test)

    def test_complete_token_endpoint_errors_are_classified(self):
        async def unreachable(request):
            raise httpx.ConnectError("unreachable", request=request)

        def answer(status, body=None):
            async def respond(request):
                return httpx.Response(status, json=body)

            return respond

        cases = (
            (answer(400, {"error": "invalid_grant"}), "interaction_required"),
            (answer(401, {"error": "invalid_client"}), "credential_unavailable"),
            (answer(400, {"error": "unauthorized_client"}), "provider_failed"),
            (answer(400, {"error": "access_denied"}), "provider_failed"),
            (answer(400, {"error": "invalid_scope"}), "provider_failed"),
            (answer(500, {"error": "server_error"}), "provider_failed"),
            (answer(404), "provider_failed"),
            (unreachable, "provider_failed"),
            (
                answer(200, {"access_token": "t", "token_type": "mac"}),
                "provider_failed",
            ),
        )

        async def run(p, n, s, policy, target, now):
            policy.configuration = base.Policy(PKCE).configuration
            for hook, code in cases:
                login = await p.prepare(target, OperationBudget.after(5))
                n.token_hook = hook
                with self.assertRaises(AuthenticationFailure) as failure:
                    await self.complete_login(p, target, login)
                self.assertEqual(
                    (
                        failure.exception.code,
                        failure.exception.required_scopes,
                        failure.exception.login_ended,
                    ),
                    (code, (), True),
                )
                self.assertFalse(base.pending_logins(p))
                n.token_hook = None

        self.run_async(run)

    def test_refresh_and_reissue_token_errors_are_classified(self):
        async def unreachable(request):
            raise httpx.ConnectError("unreachable", request=request)

        def answer(status, body=None):
            async def respond(request):
                return httpx.Response(status, json=body)

            return respond

        pkce_cases = (
            (answer(400, {"error": "invalid_grant"}), "refresh_rejected"),
            (answer(401, {"error": "invalid_client"}), "credential_unavailable"),
            (answer(400, {"error": "unauthorized_client"}), "credential_unavailable"),
            (answer(400, {"error": "access_denied"}), "provider_failed"),
            (answer(400, {"error": "invalid_scope"}), "provider_failed"),
            (answer(500, {"error": "server_error"}), "provider_failed"),
            (unreachable, "provider_failed"),
            (
                answer(200, {"access_token": "t", "token_type": "mac"}),
                "provider_failed",
            ),
        )
        cc_cases = (
            (answer(400, {"error": "invalid_grant"}), "credential_unavailable"),
            (answer(400, {"error": "unauthorized_client"}), "credential_unavailable"),
            (answer(401, {"error": "invalid_client"}), "credential_unavailable"),
            (answer(400, {"error": "access_denied"}), "provider_failed"),
            (answer(400, {"error": "invalid_scope"}), "provider_failed"),
        )

        async def refresh(p, n, s, policy, target, now):
            policy.configuration = replace(
                base.Policy(PKCE).configuration, required_scopes=("read",)
            )
            for hook, code in pkce_cases:
                s.records.clear()
                await self.complete_login(
                    p, target, await p.prepare(target, OperationBudget.after(5))
                )
                now[0] += 61
                n.token_hook = hook
                with (
                    anyio.CancelScope() as scope,
                    self.assertRaises(AuthenticationFailure) as failure,
                ):
                    await p.credential(self.context(scope))
                self.assertEqual(
                    (failure.exception.code, failure.exception.required_scopes),
                    (code, ()),
                )
                self.assertIsNone(failure.exception.login_ended)
                self.assertEqual(n.tokens[-1]["grant_type"], ["refresh_token"])
                n.token_hook = None

        async def reissue(p, n, s, policy, target, now):
            policy.configuration = replace(
                policy.configuration, required_scopes=("read",)
            )
            await p.prepare(target, OperationBudget.after(5))
            for hook, code in cc_cases:
                now[0] += 61
                n.token_hook = hook
                with self.assertRaises(AuthenticationFailure) as failure:
                    await p.prepare(target, OperationBudget.after(5))
                self.assertEqual(
                    (failure.exception.code, failure.exception.required_scopes),
                    (code, ()),
                )
                self.assertEqual(n.tokens[-1]["grant_type"], ["client_credentials"])
                n.token_hook = None

        for test in (refresh, reissue):
            with self.subTest(test.__name__):
                self.run_async(test)

    def test_handle_from_another_grant_key_is_an_invalid_callback(self):
        async def run(p, n, s, policy, target, now):
            policy.configuration = base.Policy(PKCE).configuration
            older = await p.prepare(target, OperationBudget.after(5))
            # Host policy moves to another client: a new grant key.
            policy.configuration = replace(policy.configuration, client_id="other")
            self.permissive(policy)
            current = await p.prepare(target, OperationBudget.after(5))
            self.assertNotEqual(older.key, current.key)
            state = parse_qs(urlsplit(current.authorization_url).query)["state"][0]
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.complete(
                    target,
                    older,
                    "https://host.test/callback?"
                    + urlencode({"state": state, "code": "valid"}),
                    OperationBudget.after(5),
                )
            self.assertEqual(
                (
                    failure.exception.code,
                    failure.exception.required_scopes,
                    failure.exception.login_ended,
                ),
                ("access_denied", (), False),
            )
            states = {item.state for item in base.pending_logins(p)}
            self.assertIn(state, states)
            self.assertIn(older.generation, states)
            self.assertFalse(n.tokens)

        self.run_async(run)

    def test_legacy_record_with_empty_prepare_time_requirement(self):
        async def run(p, n, s, policy, target, now):
            self.permissive(policy)
            policy.configuration = replace(
                base.Policy(PKCE).configuration, scopes=("read", "write")
            )
            login = await p.prepare(target, OperationBudget.after(5))
            for key, record in list(p._logins.records.items()):
                p._logins.records[key] = OAuthPendingLogins(
                    record.generation,
                    tuple(
                        replace(item, required_scopes=None) for item in record.logins
                    ),
                )
            # The record holds an empty prepare-time requirement: the current
            # host-required scopes do not apply to it.
            policy.configuration = replace(
                policy.configuration, required_scopes=("write",)
            )

            async def narrow(request):
                return httpx.Response(
                    200,
                    json={
                        "access_token": "narrow",
                        "token_type": "Bearer",
                        "scope": "read",
                    },
                )

            n.token_hook = narrow
            self.assertIsInstance(await self.complete_login(p, target, login), Ready)

        self.run_async(run)

    def test_login_ended_only_on_complete_errors(self):
        async def run(p, n, s, policy, target, now):
            async def refuse(*args):
                failure = AuthenticationFailure(code="access_denied")
                failure.login_ended = True
                raise failure

            policy.select = refuse
            with self.assertRaises(AuthenticationFailure) as failure:
                await p.prepare(target, OperationBudget.after(5))
            self.assertIsNone(failure.exception.login_ended)

        self.run_async(run)


if __name__ == "__main__":
    unittest.main()
