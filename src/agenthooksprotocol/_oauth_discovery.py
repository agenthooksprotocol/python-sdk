"""Bounded, host-authorized MCP 2025-11-25 OAuth discovery.

Metadata supplies candidates, never trust. DNS/TLS and egress enforcement remain
at the host's OAuthNetwork boundary; no client or browser is owned here.
"""

from dataclasses import replace
import json
import re
from urllib.parse import parse_qsl, urlsplit

import anyio
import httpx

from ._auth_challenge import ChallengeError, parse_challenge
from .auth import AuthChallenge, AuthenticationFailure, AuthTarget, OAuthBinding
from ._oauth_types import (
    EndpointPurpose,
    OAuthClientConfiguration,
    OAuthMetadata,
    OAuthNetwork,
    OAuthTrustPolicy,
    OperationBudget,
)
from .runtime import OperationCancelledError

MAX_RESPONSE_BYTES = 1024 * 1024


def _fail() -> AuthenticationFailure:
    return AuthenticationFailure(code="discovery_failed")


def validate_url(value: object, *, issuer: bool = False) -> str:
    """Validate syntax only; the host must independently authorize destinations."""
    if not isinstance(value, str):
        raise _fail()
    try:
        parts = urlsplit(value)
        valid = (
            parts.scheme == "https"
            and parts.hostname is not None
            and parts.username is None
            and parts.password is None
            and "#" not in value
            and "\\" not in value
            and not any(ord(c) <= 32 or ord(c) == 127 for c in value)
            and (not issuer or "?" not in value)
        )
        _ = parts.port
    except ValueError:
        valid = False
    if not valid:
        raise _fail()
    return value


def _validate_endpoint(value: object, *, authorization: bool = False) -> str:
    url = validate_url(value)
    reserved = {"client_id", "redirect_uri", "scope", "resource"}
    reserved.update(
        {
            "response_type",
            "state",
            "code_challenge",
            "code_challenge_method",
            "response_mode",
            "nonce",
        }
        if authorization
        else {"grant_type", "client_secret", "refresh_token", "code", "code_verifier"}
    )
    if any(
        key in reserved
        for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ):
        raise _fail()
    return url


class NotSent(AuthenticationFailure):
    """DNS, TCP connect or TLS handshake failure: the request provably never
    reached the server, so a renewal may safely refetch metadata and retry."""

    def __init__(self) -> None:
        super().__init__(code="discovery_failed")


def _public_error(error: BaseException) -> BaseException:
    """Construct sanitized failures outside the original exception handler."""
    if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout, NotSent)):
        return NotSent()
    if isinstance(error, httpx.TimeoutException):
        # A read/write timeout after connecting is an ambiguous network
        # failure, not the caller's deadline (which stays TimeoutError).
        return _fail()
    if isinstance(error, TimeoutError):
        return TimeoutError("Authentication operation timed out")
    if isinstance(error, AuthenticationFailure):
        return AuthenticationFailure(code=error.code, recovery=error.recovery)
    if isinstance(error, OperationCancelledError):
        return OperationCancelledError("Authentication operation cancelled")
    if isinstance(error, Exception):
        return _fail()
    # AnyIO native cancellation (and process-level exceptions) must propagate.
    return error


async def safe_request(
    network: OAuthNetwork,
    request: httpx.Request,
    purpose: EndpointPurpose,
    budget: OperationBudget,
) -> httpx.Response:
    """Authorize before sending; return bounded bytes and close only the response.

    Cleanup has its own shielded, one-second maximum so cancellation cannot skip
    releasing a borrowed response. Cleanup never replaces an operation failure.
    """
    response: httpx.Response | None = None
    result: httpx.Response | None = None
    error: BaseException | None = None
    try:
        await anyio.lowlevel.checkpoint_if_cancelled()
        with anyio.fail_after(budget.remaining()):
            validate_url(str(request.url))
            await network.authorize(str(request.url), purpose, budget)
            response = await network.send(request, purpose, budget)
            if response.history or 300 <= response.status_code < 400:
                if purpose == "registration":
                    raise AuthenticationFailure(code="untrusted_destination")
                raise _fail()
            length = response.headers.get("content-length")
            if length is not None and (
                not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES
            ):
                raise _fail()
            content = bytearray()
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise _fail()
                content.extend(chunk)
            headers = [
                (key, value)
                for key, value in response.headers.multi_items()
                if key.lower()
                not in ("content-encoding", "content-length", "transfer-encoding")
            ]
            result = httpx.Response(
                response.status_code,
                headers=headers,
                content=bytes(content),
                request=request,
            )
    except BaseException as caught:
        error = caught
    if response is not None:
        try:
            with anyio.CancelScope(shield=True):
                with anyio.fail_after(1):
                    await response.aclose()
        except BaseException as caught:
            if error is None:
                error = _fail() if isinstance(caught, Exception) else caught
    if error is not None:
        error = _public_error(error)
        if isinstance(error, Exception):
            error.__context__ = None
            error.__cause__ = None
        raise error
    await anyio.lowlevel.checkpoint_if_cancelled()
    assert result is not None
    return result


def challenge_requirements(
    challenge: AuthChallenge | None,
) -> tuple[str | None, tuple[str, ...]]:
    if challenge is None:
        return None, ()
    try:
        return parse_challenge(challenge.status, challenge.headers)
    except ChallengeError as error:
        code = error.code
    raise AuthenticationFailure(code=code)


def _well_known(identifier: str, name: str) -> list[tuple[str, str]]:
    parts = urlsplit(identifier)
    origin = f"{parts.scheme}://{parts.netloc}"
    path = parts.path if parts.path != "/" else ""
    query = "?" + parts.query if "?" in identifier else ""
    candidates = [(f"{origin}/.well-known/{name}{path}{query}", identifier)]
    if path or query:
        candidates.append((f"{origin}/.well-known/{name}", origin))
    return candidates


async def _metadata(
    urls: list[str],
    network: OAuthNetwork,
    budget: OperationBudget,
) -> tuple[dict[str, object], str]:
    for url in urls:
        response = await safe_request(
            network,
            httpx.Request(
                "GET", validate_url(url), headers={"accept": "application/json"}
            ),
            "metadata",
            budget,
        )
        # Only absence permits a fallback. A published but invalid document fails closed.
        if response.status_code in (404, 405):
            continue
        if response.status_code != 200:
            raise _fail()
        try:

            def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError()
                    result[key] = value
                return result

            document = json.loads(response.content, object_pairs_hook=unique)
        except (ValueError, UnicodeError):
            raise _fail() from None
        if not isinstance(document, dict):
            raise _fail()
        return document, url
    raise _fail()


def _strings(document: dict[str, object], key: str) -> tuple[str, ...]:
    value = document.get(key, [])
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise _fail()
    return tuple(value)


def _scope_set(scopes: tuple[str, ...]) -> set[str]:
    """Validate RFC 6749 scope tokens before comparing local policy sets."""
    if not isinstance(scopes, tuple) or any(
        not isinstance(scope, str)
        or re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]+", scope) is None
        for scope in scopes
    ):
        raise _fail()
    return set(scopes)


def check_redirect(redirect: object) -> None:
    """HTTPS, or HTTP to a literal loopback IP (RFC 8252); never localhost."""
    if not isinstance(redirect, str):
        raise AuthenticationFailure(code="invalid_configuration")
    try:
        parts = urlsplit(redirect)
        valid = (
            bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and "#" not in redirect
            and "\\" not in redirect
            and not any(ord(c) <= 32 or ord(c) == 127 for c in redirect)
        )
        _ = parts.port
        if parts.scheme == "http":
            import ipaddress

            valid = valid and ipaddress.ip_address(parts.hostname or "").is_loopback
        elif parts.scheme != "https":
            valid = False
        if any(
            key in ("code", "state", "iss", "error", "error_description")
            for key, _ in parse_qsl(parts.query, keep_blank_values=True)
        ):
            valid = False
    except ValueError:
        valid = False
    if not valid:
        raise AuthenticationFailure(code="invalid_configuration")


def validate_configuration(
    target: AuthTarget,
    resource: str,
    issuers: tuple[str, ...],
    required: tuple[str, ...],
    configuration: OAuthClientConfiguration,
) -> None:
    """Revalidate host policy without fetching metadata or holding a grant lock."""
    validate_url(resource)
    validate_url(configuration.issuer, issuer=True)
    requested = _scope_set(configuration.scopes)
    allowed = (
        requested
        if configuration.allowed_scopes is None
        else _scope_set(configuration.allowed_scopes)
    )
    mandatory = _scope_set(configuration.required_scopes) | _scope_set(required)
    if not requested.issubset(allowed) or not mandatory.issubset(allowed):
        raise AuthenticationFailure(code="access_denied")
    # An empty client_id asks client selection for CIMD or DCR.
    registered = not configuration.client_id
    if configuration.issuer not in issuers:
        raise _fail()
    binding = target.typed_binding
    if binding is not None and (
        not isinstance(binding, OAuthBinding)
        or binding.resource != resource
        or configuration.issuer != binding.issuer
        or configuration.client_id != binding.client_id
        or configuration.flow != binding.flow
        or requested != _scope_set(binding.scopes)
    ):
        raise AuthenticationFailure(code="invalid_configuration")
    if configuration.flow == "authorization_code_pkce":
        # A redirect is required only to create a login; a host may supply it
        # per login through prepare(redirect_uri=...). A configured one is
        # always checked, so localhost fails before client selection.
        redirect = configuration.redirect_uri
        if redirect is not None:
            check_redirect(redirect)
    elif configuration.flow != "client_credentials":
        raise AuthenticationFailure(code="unsupported_binding")
    if (
        not registered
        and configuration.token_endpoint_auth_method != "none"
        and not configuration.client_secret
    ):
        # This function only receives current runtime policy, never sanitized records.
        raise AuthenticationFailure(code="credential_unavailable")


async def discover(
    target: AuthTarget,
    challenge: AuthChallenge | None,
    network: OAuthNetwork,
    policy: OAuthTrustPolicy,
    budget: OperationBudget,
    *,
    redirect_uri: str | None = None,
) -> OAuthMetadata:
    """Resolve the locally selected binding. The result carries the current
    client secret; callers strip it before persisting metadata.
    `redirect_uri` overrides the configured redirect for one login."""
    resource = validate_url(await policy.resource(target, budget))
    binding = target.typed_binding
    metadata_url, required = challenge_requirements(challenge)
    issuers: tuple[str, ...]
    if binding is not None:
        if not isinstance(binding, OAuthBinding):
            raise AuthenticationFailure(code="unsupported_binding")
        if binding.resource != resource:
            raise _fail()
        issuers = (validate_url(binding.issuer, issuer=True),)
    else:
        destination = validate_url(target.destination)
        candidates = (
            [(validate_url(metadata_url), destination)]
            if metadata_url is not None
            else _well_known(destination, "oauth-protected-resource")
        )
        document, retrieved_url = await _metadata(
            [url for url, _ in candidates], network, budget
        )
        expected_resource = dict(candidates)[retrieved_url]
        # RFC 9728 section 3.3 binds metadata to its discovery source,
        # independently of the host's local resource authorization.
        if (
            document.get("resource") != expected_resource
            or expected_resource != resource
        ):
            raise _fail()
        issuers = _strings(document, "authorization_servers")
        if not issuers:
            raise _fail()
        for issuer in issuers:
            validate_url(issuer, issuer=True)
    configuration = await policy.select(target, resource, issuers, required, budget)
    if redirect_uri is not None:
        configuration = replace(configuration, redirect_uri=redirect_uri)
    validate_configuration(target, resource, issuers, required, configuration)
    return await issuer_metadata(resource, configuration, network, budget)


async def issuer_metadata(
    resource: str,
    configuration: OAuthClientConfiguration,
    network: OAuthNetwork,
    budget: OperationBudget,
) -> OAuthMetadata:
    """Fetch only the selected issuer's authorization-server metadata."""
    issuer = validate_url(configuration.issuer, issuer=True)
    parts = urlsplit(issuer)
    origin = f"{parts.scheme}://{parts.netloc}"
    path = parts.path.rstrip("/")
    urls = [
        f"{origin}/.well-known/oauth-authorization-server{path}",
        f"{origin}/.well-known/openid-configuration{path}",
    ]
    if path:
        urls.append(f"{origin}{path}/.well-known/openid-configuration")
    document, _ = await _metadata(urls, network, budget)
    if document.get("issuer") != issuer:
        raise _fail()
    token_endpoint = _validate_endpoint(document.get("token_endpoint"))
    await network.authorize(token_endpoint, "token", budget)
    authorization_endpoint = None
    if configuration.flow == "client_credentials":
        if "client_credentials" not in _strings(document, "grant_types_supported"):
            raise _fail()
    elif configuration.flow == "authorization_code_pkce":
        if "S256" not in _strings(document, "code_challenge_methods_supported"):
            raise _fail()
        if "code" not in _strings(document, "response_types_supported"):
            raise _fail()
        grants = _strings(document, "grant_types_supported")
        if grants and "authorization_code" not in grants:
            raise _fail()
        authorization_endpoint = _validate_endpoint(
            document.get("authorization_endpoint"), authorization=True
        )
        await network.authorize(authorization_endpoint, "authorization", budget)
    else:
        raise _fail()
    methods = _strings(document, "token_endpoint_auth_methods_supported") or (
        "client_secret_basic",
    )
    if (
        configuration.client_id
        and configuration.token_endpoint_auth_method not in methods
    ):
        raise _fail()
    response_issuer = document.get(
        "authorization_response_iss_parameter_supported", False
    )
    if not isinstance(response_issuer, bool):
        raise _fail()
    # Client registration inputs; selection validates the endpoint.
    registration = document.get("registration_endpoint")
    return OAuthMetadata(
        resource,
        configuration,
        token_endpoint,
        authorization_endpoint,
        response_issuer,
        registration if isinstance(registration, str) and registration else None,
        document.get("client_id_metadata_document_supported") is True,
        methods,
    )
