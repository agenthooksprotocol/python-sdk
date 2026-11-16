"""Opt-in Authlib compatibility/security probes, not adapter acceptance tests.

Run with:
  uv run --extra oauth python -m unittest discover -s tests \
      -p test_managed_oauth.py

The base installation has no Authlib dependency; these tests skip without it.
The managed adapter is tested separately by test_managed_oauth_runtime.py and
test_oauth_discovery.py against capability-auth.md:101-155. These lower-level
probes retain evidence of library behavior that the adapter must constrain.

Shared parity IDs exercised as library primitives: pkce-completion,
client-credentials, deadline-cancel, redaction.
"""

import hashlib
import importlib.util
import unittest
from base64 import urlsafe_b64encode
from urllib.parse import parse_qs, urlsplit

import anyio
import httpx


@unittest.skipUnless(importlib.util.find_spec("authlib"), "optional Authlib spike")
class AuthlibCompatibilitySpike(unittest.TestCase):
    def both_backends(self, operation):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(operation, backend=backend)

    def test_pkce_s256_state_and_resource_are_explicit(self):
        async def run():
            from authlib.integrations.httpx_client import AsyncOAuth2Client

            requests = []

            def handle(request):
                requests.append(request)
                return httpx.Response(
                    200,
                    json={
                        "access_token": "test-access",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    },
                )

            async with AsyncOAuth2Client(
                "client",
                redirect_uri="https://host.test/callback",
                scope="read",
                code_challenge_method="S256",
                token_endpoint_auth_method="none",
                transport=httpx.MockTransport(handle),
            ) as client:
                verifier = "a" * 64
                url, state = client.create_authorization_url(
                    "https://issuer.test/authorize",
                    state="host-state",
                    code_verifier=verifier,
                    resource="https://resource.test/api",
                )
                params = parse_qs(urlsplit(url).query)
                challenge = (
                    urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                    .rstrip(b"=")
                    .decode()
                )
                self.assertEqual(state, "host-state")
                self.assertEqual(params["code_challenge"], [challenge])
                self.assertEqual(params["code_challenge_method"], ["S256"])
                self.assertEqual(params["resource"], ["https://resource.test/api"])
                # Authlib validates state only when authorization_response is used.
                # The host must separately validate callback endpoint and issuer.
                with self.assertRaises(Exception):
                    await client.fetch_token(
                        "https://issuer.test/token",
                        state=state,
                        authorization_response="https://host.test/callback?code=c&state=wrong",
                        code_verifier=verifier,
                        resource="https://resource.test/api",
                    )
                self.assertEqual(requests, [])
                token = await client.fetch_token(
                    "https://issuer.test/token",
                    state=state,
                    authorization_response="https://host.test/callback?code=c&state=host-state",
                    code_verifier=verifier,
                    resource="https://resource.test/api",
                )
                body = parse_qs(requests[0].content.decode())
                self.assertEqual(body["grant_type"], ["authorization_code"])
                self.assertEqual(body["code_verifier"], [verifier])
                self.assertEqual(body["resource"], ["https://resource.test/api"])
                self.assertEqual(body["redirect_uri"], ["https://host.test/callback"])
                self.assertEqual(token["access_token"], "test-access")
                self.assertIn("expires_at", token)

        self.both_backends(run)

    def test_client_credentials_and_refresh_require_resource_each_time(self):
        async def run():
            from authlib.integrations.httpx_client import AsyncOAuth2Client

            requests = []

            def handle(request):
                requests.append(request)
                return httpx.Response(
                    200,
                    json={
                        "access_token": "test-access",
                        "token_type": "Bearer",
                        "refresh_token": "test-refresh",
                        "expires_in": 3600,
                    },
                )

            async with AsyncOAuth2Client(
                "client",
                "test-secret",
                scope="read",
                transport=httpx.MockTransport(handle),
            ) as client:
                token = await client.fetch_token(
                    "https://issuer.test/token",
                    grant_type="client_credentials",
                    resource="https://resource.test/api",
                )
                self.assertEqual(
                    parse_qs(requests[0].content.decode())["resource"],
                    ["https://resource.test/api"],
                )
                self.assertTrue(
                    requests[0].headers["authorization"].startswith("Basic ")
                )
                await client.refresh_token(
                    "https://issuer.test/token",
                    refresh_token=token["refresh_token"],
                    resource="https://resource.test/api",
                )
                self.assertEqual(
                    parse_qs(requests[1].content.decode())["resource"],
                    ["https://resource.test/api"],
                )
                # Resource is NOT remembered/enforced by the library on refresh.
                await client.refresh_token(
                    "https://issuer.test/token",
                    refresh_token="test-refresh",
                )
                self.assertNotIn("resource", parse_qs(requests[2].content.decode()))
                self.assertEqual(client.token["access_token"], "test-access")

        self.both_backends(run)

    def test_native_cancel_propagates_from_real_httpx_transport(self):
        async def run():
            from authlib.integrations.httpx_client import AsyncOAuth2Client

            entered = anyio.Event()

            async def handle(request):
                entered.set()
                await anyio.sleep_forever()

            async with AsyncOAuth2Client(
                "client",
                "test-secret",
                transport=httpx.MockTransport(handle),
            ) as client:
                cancelled = []

                async def exchange():
                    try:
                        await client.fetch_token(
                            "https://issuer.test/token",
                            grant_type="client_credentials",
                            resource="https://resource.test/api",
                        )
                    except anyio.get_cancelled_exc_class():
                        cancelled.append(True)
                        raise

                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(exchange)
                    await entered.wait()
                    tasks.cancel_scope.cancel()
                self.assertEqual(cancelled, [True])
                self.assertFalse(client.is_closed)

        self.both_backends(run)

    def test_library_errors_are_not_safe_public_errors(self):
        async def run():
            from authlib.integrations.httpx_client import AsyncOAuth2Client

            def handle(request):
                return httpx.Response(
                    400,
                    json={
                        "error": "invalid_grant",
                        "error_description": "private-token-marker",
                    },
                )

            async with AsyncOAuth2Client(
                "client",
                "test-secret",
                transport=httpx.MockTransport(handle),
            ) as client:
                with self.assertRaises(Exception) as caught:
                    await client.fetch_token(
                        "https://issuer.test/token",
                        grant_type="client_credentials",
                    )
                self.assertIn("private-token-marker", str(caught.exception))
                # A shipping adapter must replace this error and suppress its chain.

        self.both_backends(run)

    def test_redirects_need_host_policy_not_just_oauth_library(self):
        async def run():
            from authlib.integrations.httpx_client import AsyncOAuth2Client

            seen = []

            def handle(request):
                seen.append(request)
                if len(seen) == 1:
                    return httpx.Response(
                        307, headers={"location": "https://other.test/token"}
                    )
                return httpx.Response(
                    200, json={"access_token": "test-access", "token_type": "Bearer"}
                )

            async with AsyncOAuth2Client(
                "client",
                "test-secret",
                token_endpoint_auth_method="client_secret_post",
                follow_redirects=True,
                transport=httpx.MockTransport(handle),
            ) as client:
                await client.fetch_token(
                    "https://issuer.test/token",
                    grant_type="client_credentials",
                    resource="https://resource.test/api",
                )
                self.assertEqual(seen[1].url.host, "other.test")
                # HTTPX strips cross-origin Authorization headers, but 307 preserves
                # the body, including client_secret_post. Explicit policy is vital.
                self.assertEqual(
                    parse_qs(seen[1].content.decode())["client_secret"], ["test-secret"]
                )

        self.both_backends(run)


if __name__ == "__main__":
    unittest.main()
