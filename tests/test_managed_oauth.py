"""Compatibility probes for Authlib's supported transport-independent API."""

import hashlib
import importlib.util
import subprocess
import sys
import unittest
from base64 import urlsafe_b64encode
from urllib.parse import parse_qs, urlsplit


@unittest.skipUnless(importlib.util.find_spec("authlib"), "requires optional oauth extra")
class AuthlibProtocolCompatibilityTests(unittest.TestCase):
    def test_protocol_imports_do_not_load_http_client_integrations(self):
        code = """
import sys
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri, prepare_token_request
from authlib.oauth2.rfc7636 import create_s256_code_challenge
assert not any(name.startswith('authlib.integrations') for name in sys.modules)
assert not any(name == 'httpx2' or name.startswith('httpcore2') for name in sys.modules)
"""
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pkce_s256_state_and_resource_are_explicit(self):
        from authlib.oauth2.rfc6749.parameters import (
            parse_authorization_code_response, prepare_grant_uri, prepare_token_request,
        )
        from authlib.oauth2.rfc7636 import create_s256_code_challenge

        verifier = "a" * 64
        challenge = urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(create_s256_code_challenge(verifier), challenge)
        url = prepare_grant_uri(
            "https://issuer.test/authorize", "client", "code",
            redirect_uri="https://host.test/callback", scope="read", state="host-state",
            code_challenge=challenge, code_challenge_method="S256", resource="https://resource.test/api",
        )
        params = parse_qs(urlsplit(url).query)
        self.assertEqual(params["code_challenge"], [challenge])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["resource"], ["https://resource.test/api"])
        callback = "https://host.test/callback?code=one-use-code&state=host-state"
        response = parse_authorization_code_response(callback, state="host-state")
        self.assertEqual(response["code"], "one-use-code")
        with self.assertRaises(Exception):
            parse_authorization_code_response(callback, state="wrong-state")
        form = parse_qs(prepare_token_request(
            "authorization_code", code=response["code"], code_verifier=verifier,
            redirect_uri="https://host.test/callback", resource="https://resource.test/api",
        ))
        self.assertEqual(form["code_verifier"], [verifier])
        self.assertEqual(form["resource"], ["https://resource.test/api"])

    def test_client_auth_methods_and_resource_binding(self):
        from authlib.oauth2.auth import ClientAuth
        from authlib.oauth2.rfc6749.parameters import prepare_token_request

        for method in ("none", "client_secret_basic", "client_secret_post"):
            for grant in ("client_credentials", "refresh_token"):
                with self.subTest(method=method, grant=grant):
                    body = prepare_token_request(
                        grant, scope="read", resource="https://resource.test/api",
                        **({"refresh_token": "rotating-refresh"} if grant == "refresh_token" else {}),
                    )
                    url, headers, body = ClientAuth("client", "secret", method).prepare(
                        "POST", "https://issuer.test/token", {}, body,
                    )
                    self.assertEqual(url, "https://issuer.test/token")
                    form = parse_qs(body)
                    self.assertEqual(form["resource"], ["https://resource.test/api"])
                    self.assertEqual(form["grant_type"], [grant])
                    if method == "client_secret_basic":
                        self.assertEqual(headers["Authorization"], "Basic Y2xpZW50OnNlY3JldA==")
                        self.assertNotIn("client_secret", form)
                    elif method == "client_secret_post":
                        self.assertEqual(form["client_secret"], ["secret"])
                    else:
                        self.assertEqual(form["client_id"], ["client"])
                        self.assertNotIn("client_secret", form)


if __name__ == "__main__":
    unittest.main()
