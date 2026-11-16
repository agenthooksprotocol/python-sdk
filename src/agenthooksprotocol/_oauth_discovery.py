"""Bounded, host-authorized MCP 2025-11-25 OAuth discovery.

Metadata supplies candidates, never trust. DNS/TLS and egress enforcement remain
at the host's OAuthNetwork boundary; no client or browser is owned here.
"""
import json
import re
from urllib.parse import parse_qsl, urlsplit

import anyio
import httpx

from .auth import AuthChallenge, AuthenticationFailure, AuthTarget, OAuthBinding
from ._oauth_types import (
    EndpointPurpose, OAuthMetadata, OAuthNetwork, OAuthTrustPolicy, OperationBudget,
)
from .runtime import OperationCancelledError

MAX_RESPONSE_BYTES = 1024 * 1024
_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"


def _fail() -> AuthenticationFailure:
    return AuthenticationFailure(code="discovery_failed")


def validate_url(value: object, *, issuer: bool = False) -> str:
    """Validate syntax only; the host must independently authorize destinations."""
    if not isinstance(value, str):
        raise _fail()
    try:
        parts = urlsplit(value)
        valid = (
            parts.scheme == "https" and parts.hostname is not None
            and parts.username is None and parts.password is None
            and "#" not in value and "\\" not in value
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
        {"response_type", "state", "code_challenge", "code_challenge_method",
         "response_mode", "nonce"} if authorization else
        {"grant_type", "client_secret", "refresh_token", "code", "code_verifier"}
    )
    if any(key in reserved for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)):
        raise _fail()
    return url


def _public_error(error: BaseException) -> BaseException:
    """Construct sanitized failures outside the original exception handler."""
    if isinstance(error, (httpx.TimeoutException, TimeoutError)):
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
    network: OAuthNetwork, request: httpx.Request, purpose: EndpointPurpose,
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
                raise _fail()
            length = response.headers.get("content-length")
            if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES):
                raise _fail()
            content = bytearray()
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise _fail()
                content.extend(chunk)
            headers = [(key, value) for key, value in response.headers.multi_items()
                       if key.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
            result = httpx.Response(response.status_code, headers=headers,
                                    content=bytes(content), request=request)
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


def _challenge(challenge: AuthChallenge | None) -> tuple[str | None, tuple[str, ...]]:
    if challenge is None or challenge.status != 401:
        return None, ()
    values = [v for k, v in challenge.headers.items() if k.lower() == "www-authenticate"]
    if len(values) > 1:
        raise _fail()
    if not values:
        return None, ()
    # Split only unquoted commas. Quoted-pairs may contain commas and quotes.
    pieces, start, quoted, escaped = [], 0, False, False
    for index, char in enumerate(values[0]):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            pieces.append(values[0][start:index].strip())
            start = index + 1
    if quoted or escaped:
        raise _fail()
    pieces.append(values[0][start:].strip())
    bearer, params, active = 0, {}, False
    for piece in pieces:
        scheme = re.match(rf"^({_TOKEN})\s+(?!\s*=)(.*)$", piece)
        if scheme:
            active = scheme[1].lower() == "bearer"
            if active:
                bearer += 1
                if bearer > 1:
                    raise _fail()
            piece = scheme[2].strip()
        elif re.fullmatch(_TOKEN, piece):
            active = piece.lower() == "bearer"
            if active:
                bearer += 1
                if bearer > 1:
                    raise _fail()
            continue
        if not active:
            continue
        match = re.fullmatch(rf'({_TOKEN})\s*=\s*({_TOKEN}|"(?:[^"\\\r\n]|\\[^\r\n])*")', piece)
        if match is None:
            raise _fail()
        key, value = match[1].lower(), match[2]
        if key in params:
            raise _fail()
        if value.startswith('"'):
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        params[key] = value
    scope = params.get("scope", "")
    if scope and not re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*", scope):
        raise _fail()
    return params.get("resource_metadata"), tuple(scope.split())


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
    urls: list[str], network: OAuthNetwork, budget: OperationBudget,
) -> tuple[dict[str, object], str]:
    for url in urls:
        response = await safe_request(network, httpx.Request("GET", validate_url(url),
                                      headers={"accept": "application/json"}), "metadata", budget)
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
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise _fail()
    return tuple(value)


async def discover(
    target: AuthTarget, challenge: AuthChallenge | None, network: OAuthNetwork,
    policy: OAuthTrustPolicy, budget: OperationBudget,
) -> OAuthMetadata:
    """Resolve locally bound resource and issuer without acquiring credentials."""
    error: BaseException | None = None
    result: OAuthMetadata | None = None
    try:
        await anyio.lowlevel.checkpoint_if_cancelled()
        with anyio.fail_after(budget.remaining()):
            result = await _discover(target, challenge, network, policy, budget)
    except BaseException as caught:
        error = caught
    if error is not None:
        error = _public_error(error)
        if isinstance(error, Exception):
            error.__context__ = None
            error.__cause__ = None
        raise error
    assert result is not None
    return result


async def _discover(
    target: AuthTarget, challenge: AuthChallenge | None, network: OAuthNetwork,
    policy: OAuthTrustPolicy, budget: OperationBudget,
) -> OAuthMetadata:
    resource = validate_url(await policy.resource(target, budget))
    binding = target.typed_binding
    metadata_url, required = _challenge(challenge)
    issuers: tuple[str, ...]
    if binding is not None:
        if not isinstance(binding, OAuthBinding):
            raise AuthenticationFailure(code="unsupported_binding")
        if binding.resource != resource:
            raise _fail()
        issuers = (validate_url(binding.issuer, issuer=True),)
    else:
        destination = validate_url(target.destination)
        candidates = ([(validate_url(metadata_url), destination)] if metadata_url is not None else
                      _well_known(destination, "oauth-protected-resource"))
        document, retrieved_url = await _metadata([url for url, _ in candidates], network, budget)
        expected_resource = dict(candidates)[retrieved_url]
        # RFC 9728 section 3.3 binds metadata to its discovery source,
        # independently of the host's local resource authorization.
        if document.get("resource") != expected_resource or expected_resource != resource:
            raise _fail()
        issuers = _strings(document, "authorization_servers")
        if not issuers:
            raise _fail()
        for issuer in issuers:
            validate_url(issuer, issuer=True)
    configuration = await policy.select(target, resource, issuers, required, budget)
    if (configuration.issuer not in issuers or not configuration.client_id
            or not set(required).issubset(configuration.scopes)):
        raise _fail()
    if binding is not None and (
        configuration.issuer != binding.issuer or configuration.client_id != binding.client_id
        or configuration.flow != binding.flow or set(configuration.scopes) != set(binding.scopes)
    ):
        raise _fail()
    issuer = validate_url(configuration.issuer, issuer=True)
    parts = urlsplit(issuer)
    origin = f"{parts.scheme}://{parts.netloc}"
    path = parts.path.rstrip("/")
    urls = [f"{origin}/.well-known/oauth-authorization-server{path}",
            f"{origin}/.well-known/openid-configuration{path}"]
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
        authorization_endpoint = _validate_endpoint(document.get("authorization_endpoint"), authorization=True)
        await network.authorize(authorization_endpoint, "authorization", budget)
    else:
        raise _fail()
    methods = _strings(document, "token_endpoint_auth_methods_supported") or ("client_secret_basic",)
    if configuration.token_endpoint_auth_method not in methods:
        raise _fail()
    response_issuer = document.get("authorization_response_iss_parameter_supported", False)
    if not isinstance(response_issuer, bool):
        raise _fail()
    return OAuthMetadata(resource, configuration, token_endpoint, authorization_endpoint, response_issuer)
