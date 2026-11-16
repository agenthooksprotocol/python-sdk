"""Dependency-light validation of bounded managed OAuth contracts.

Canonical vector source: agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json.
"""

import json
from pathlib import Path
import unittest

import anyio

from agenthooksprotocol.oauth import (
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

FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures/sdk-auth-lifecycle.json").read_text()
)


class OAuthContractTests(unittest.TestCase):
    def test_lifetimes_must_be_finite_and_positive(self):
        for value in (float("nan"), float("inf"), float("-inf"), 0, -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    OAuthClientConfiguration(
                        "https://issuer.test",
                        "client",
                        "client_credentials",
                        login_lifetime=value,
                    )
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
                self.assertEqual(
                    ManagedOAuthProvider._key(target, metadata), vector["grant_key"]
                )

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
                config = OAuthClientConfiguration(
                    "https://issuer.example",
                    "client",
                    "client_credentials",
                    scopes=tuple(vector["requested"]),
                    allowed_scopes=tuple(vector["allowed"]),
                    required_scopes=tuple(vector["required"]),
                )
                metadata = OAuthMetadata(
                    "https://api.example", config, "https://issuer.example/token"
                )
                previous = (
                    StoredToken(
                        "previous-access",
                        refresh_token="previous-refresh",
                        scopes=tuple(vector["previous_granted"]),
                    )
                    if "previous_granted" in vector
                    else None
                )
                if not vector["accepted"]:
                    with self.assertRaises(AuthenticationFailure):
                        provider._token(vector["response"], metadata, previous)
                    continue
                token = provider._token(vector["response"], metadata, previous)
                self.assertEqual(set(token.scopes), set(vector["granted"]))
                self.assertEqual(
                    token.expires_at is None, vector["expiry"] == "unknown"
                )
                self.assertEqual(
                    set(config.required_scopes).issubset(token.scopes), vector["usable"]
                )
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
