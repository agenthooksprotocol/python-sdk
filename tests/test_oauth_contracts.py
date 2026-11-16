"""Dependency-light validation of bounded managed OAuth contracts."""

import unittest

import anyio

from agenthooksprotocol.oauth import OAuthClientConfiguration, OperationBudget


class OAuthContractTests(unittest.TestCase):
    def test_lifetimes_must_be_finite_and_positive(self):
        for value in (float("nan"), float("inf"), float("-inf"), 0, -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    OAuthClientConfiguration(
                        "https://issuer.test", "client", "client_credentials",
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
