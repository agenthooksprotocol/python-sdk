"""Client ID Metadata Document checks and RFC 7591 request/response rules.

Pure helpers: no store, network or clock is owned here.
"""

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import ipaddress
from urllib.parse import urlsplit

from .auth import AuthErrorCode
from ._oauth_types import (
    OAuthDynamicRegistration,
    TokenEndpointAuthMethod,
)

SECRET_METHODS: tuple[TokenEndpointAuthMethod, ...] = (
    "client_secret_basic",
    "client_secret_post",
)


class RegistrationFailed(Exception):
    """A failed registration outcome; `retry_after` is in seconds."""

    def __init__(self, code: AuthErrorCode, retry_after: float | None = None) -> None:
        self.code, self.retry_after = code, retry_after


def valid_document_url(url: object) -> bool:
    """HTTPS with a path; no userinfo, fragment or dot segments."""
    if not isinstance(url, str) or "#" in url:
        return False
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(parts.hostname)
        and bool(parts.path)
        and parts.username is None
        and parts.password is None
        and not any(ord(c) <= 32 or ord(c) == 127 for c in url)
        and not any(segment in (".", "..") for segment in parts.path.split("/"))
    )


def loopback(redirect: str) -> bool:
    """An `http` redirect to a literal loopback IP without userinfo."""
    try:
        parts = urlsplit(redirect)
        return (
            parts.scheme == "http"
            and parts.username is None
            and parts.password is None
            and ipaddress.ip_address(parts.hostname or "").is_loopback
        )
    except ValueError:
        return False


def declared_redirect(redirect: str, declared: tuple[str, ...]) -> bool:
    """Whether a CIMD document declares `redirect`.

    A loopback redirect is compared without its port (RFC 8252 section 7.3);
    any other redirect must be listed exactly.
    """
    if redirect in declared:
        return True
    if not loopback(redirect):
        return False

    def portless(url: str) -> tuple[str, ...]:
        parts = urlsplit(url)
        return (parts.scheme, parts.hostname or "", parts.path, parts.query)

    return any(
        loopback(entry) and portless(entry) == portless(redirect) for entry in declared
    )


def registration_request(
    flow: str,
    redirect: str,
    method: TokenEndpointAuthMethod,
    policy: OAuthDynamicRegistration,
) -> dict[str, object]:
    body: dict[str, object] = {"client_name": policy.client_name}
    if flow == "authorization_code_pkce":
        body["redirect_uris"] = [redirect]
        if loopback(redirect):
            body["application_type"] = "native"
        body.update(
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
        )
    else:
        body["grant_types"] = ["client_credentials"]
    body["token_endpoint_auth_method"] = method
    if policy.software_id is not None:
        body["software_id"] = policy.software_id
    if policy.software_version is not None:
        body["software_version"] = policy.software_version
    if policy.scopes is not None:
        body["scope"] = " ".join(sorted(set(policy.scopes)))
    return body


@dataclass(frozen=True)
class Issued:
    client_id: str
    client_secret: str | None
    client_secret_expires_at: int | None


def accept_registration(
    flow: str,
    request: dict[str, object],
    status: int,
    body: object,
    now: float,
    retry_after: float | None = None,
) -> Issued:
    """Map a registration response by the outcome table, in order."""
    if 300 <= status < 400:
        raise RegistrationFailed("untrusted_destination")
    if 200 <= status < 300 and (status not in (200, 201) or not isinstance(body, dict)):
        raise RegistrationFailed("provider_failed", retry_after)
    if status in (401, 403):
        raise RegistrationFailed("credential_unavailable", retry_after)
    if status in (408, 429) or status >= 500 or status < 200:
        raise RegistrationFailed("provider_failed", retry_after)
    if 400 <= status < 500:
        raise RegistrationFailed("invalid_configuration", retry_after)
    assert isinstance(body, dict)
    pkce = flow == "authorization_code_pkce"
    client_id, secret = body.get("client_id"), body.get("client_secret")
    expires_at = body.get("client_secret_expires_at")
    echoed = body.get("redirect_uris")
    sent = request.get("redirect_uris")
    requested = sent if isinstance(sent, list) else []
    valid = (
        isinstance(client_id, str)
        and bool(client_id)
        # A JSON null is never an absent echo: each echoed field is checked
        # when present. redirect_uris must be a list (null is not);
        # a PKCE echo must contain the requested redirect. Client credentials
        # sent none, so any echoed list is harmless.
        and (
            "redirect_uris" not in body
            or (
                isinstance(echoed, list)
                and (not pkce or all(uri in echoed for uri in requested))
            )
        )
        and (
            "grant_types" not in body
            or (
                isinstance(body["grant_types"], list)
                and ("authorization_code" if pkce else "client_credentials")
                in body["grant_types"]
            )
        )
        and body.get(
            "token_endpoint_auth_method", request["token_endpoint_auth_method"]
        )
        == request["token_endpoint_auth_method"]
        # A public (PKCE) client ignores any issued secret and its expiry.
        and (
            pkce
            or (
                isinstance(secret, str)
                and bool(secret)
                # A JSON null is never an absent expiry.
                and (
                    "client_secret_expires_at" not in body
                    or (
                        type(expires_at) is int
                        and expires_at >= 0
                        and (expires_at == 0 or expires_at > now)
                    )
                )
            )
        )
    )
    if not valid:
        raise RegistrationFailed("invalid_configuration")
    assert isinstance(client_id, str)
    if pkce:
        return Issued(client_id, None, None)
    assert isinstance(secret, str)
    return Issued(client_id, secret, expires_at if type(expires_at) is int else None)


def parse_retry_after(value: str | None, now: float) -> float | None:
    """Delay-seconds or HTTP-date, as seconds from now."""
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():
        return float(min(int(value), 2**31))
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - now)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
