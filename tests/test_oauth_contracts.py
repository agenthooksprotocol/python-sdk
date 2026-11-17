"""Dependency-light validation of bounded managed OAuth contracts.

Canonical vector source: agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json.
"""

import json
from pathlib import Path
import subprocess
import unittest

import anyio

from agenthooksprotocol.oauth import (
    _ExchangeError,
    ManagedOAuthProvider,
    OAuthClientConfiguration,
    OperationBudget,
)
from agenthooksprotocol.auth import AuthenticationFailure
from agenthooksprotocol._auth_routing import AuthTarget
from agenthooksprotocol._oauth_types import (
    OAuthMetadata,
    StoredToken,
    binding_key,
    grant_key,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/sdk-auth-lifecycle.json"
FIXTURES = json.loads(FIXTURE.read_text())


class OAuthContractTests(unittest.TestCase):
    def test_lifetimes_must_be_finite_and_positive(self):
        for value in (float("nan"), float("inf"), float("-inf"), 0, -1, 601):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    OAuthClientConfiguration(
                        "https://issuer.test",
                        "client",
                        "client_credentials",
                        login_lifetime=value,
                    )
                if value != 601:
                    with self.assertRaises(ValueError):
                        OperationBudget.after(value)

    def test_absolute_deadline_must_be_finite(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                OperationBudget(value)

    def test_budget_keeps_enclosing_deadline(self):
        async def run():
            with anyio.fail_after(1) as scope:
                budget = OperationBudget.after(10)
                self.assertEqual(budget.deadline, scope.deadline)
                self.assertLessEqual(budget.remaining(), 1)

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)


class CanonicalVectorTests(unittest.TestCase):
    def test_vendored_fixture_is_byte_identical_at_pinned_protocol_ref(self):
        lock = json.loads((ROOT / "ahp-codegen.lock.json").read_text())
        protocol = ROOT.parent / "agent-hooks-protocol"
        if not (protocol / ".git").exists():
            self.skipTest("requires the sibling protocol checkout")
        canonical = subprocess.run(
            ["git", "-C", str(protocol), "show",
             lock["sourceCommit"] + ":conformance/draft/sdk-auth-lifecycle.json"],
            capture_output=True, check=True,
        ).stdout
        self.assertEqual(FIXTURE.read_bytes(), canonical)

    def test_recovery_vectors(self):
        for vector in FIXTURES["recovery"]:
            with self.subTest(code=vector["code"]):
                error = AuthenticationFailure(code=vector["code"])
                self.assertEqual(error.recovery, vector["recovery"])

    def test_key_vectors(self):
        for vector in FIXTURES["keys"]:
            with self.subTest(id=vector["id"]):
                value = vector["input"]
                target = AuthTarget(
                    value["namespace"],
                    value["backend_id"],
                    value["destination"],
                    value["purpose"],
                    None,
                )
                config = OAuthClientConfiguration(
                    value["issuer"],
                    value["client_id"],
                    value["flow"],
                    allowed_scopes=tuple(value["allowed_scopes"]),
                    grant_partition=value.get("grant_partition"),
                    client_secret=value.get("client_secret"),
                )
                metadata = OAuthMetadata(
                    value["resource"], config, "https://issuer.example/token"
                )
                self.assertEqual(binding_key(target), vector["binding_key"])
                self.assertEqual(grant_key(target, metadata), vector["grant_key"])

    def test_token_response_vectors(self):
        provider = ManagedOAuthProvider(
            network=None,
            policy=None,
            store=None,
            namespace="fixture",
            clock=lambda: 1000,
        )
        for vector in FIXTURES["token_responses"]:
            with self.subTest(id=vector["id"]):
                prior = tuple(vector.get("previous_granted", ()))
                previous = (
                    StoredToken(
                        "previous-access",
                        refresh_token="previous-refresh",
                        scopes=prior,
                    )
                    if vector.get("exchange") == "refresh"
                    else None
                )
                # (Re)acquisition records within previous grant ∪ its ceiling.
                arguments = (
                    vector["response"],
                    tuple(vector["requested"]),
                    tuple(sorted(set(prior) | set(vector["allowed"]))),
                    previous,
                )
                if not vector["accepted"]:
                    with self.assertRaises(_ExchangeError) as failure:
                        provider._token(*arguments)
                    self.assertEqual(failure.exception.code, "invalid")
                    continue
                token = provider._token(*arguments)
                self.assertEqual(set(token.scopes), set(vector["granted"]))
                effective = set(token.scopes) & set(vector["allowed"])
                self.assertEqual(effective, set(vector.get("effective", vector["granted"])))
                self.assertEqual(
                    token.expires_at is None, vector["expiry"] == "unknown"
                )
                self.assertEqual(set(vector["required"]) <= effective, vector["usable"])
                if vector["refresh_preserved"]:
                    self.assertEqual(
                        token.refresh_token, vector["response"]["refresh_token"]
                    )

    def test_scope_policy_validation(self):
        for scope in ("bad scope", 'quote"', "back\\slash", "nonasciié", ""):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                OAuthClientConfiguration(
                    "https://issuer.test",
                    "client",
                    "client_credentials",
                    scopes=(scope,),
                )
        with self.assertRaises(ValueError):
            OAuthClientConfiguration(
                "https://issuer.test",
                "client",
                "client_credentials",
                scopes=("read",),
                required_scopes=("admin",),
            )
