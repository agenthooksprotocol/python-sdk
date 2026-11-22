"""Registration-aware bearer delivery with harness-owned provider resources."""

from copy import deepcopy
from dataclasses import dataclass, field
import inspect
import json
import os
import re
from typing import Any, Literal, Protocol, TYPE_CHECKING, TypeAlias
from collections.abc import Awaitable, Callable

if TYPE_CHECKING:
    from .generated import ContentUploadReceipt
from uuid import uuid4

import anyio

from .runtime import (
    OperationCancelledError,
    ProtocolError,
    _validate_intercept_response,
)
from .transports.http import HTTPTransport, _raise_rpc_error
from .headers import validate_headers, resolve_headers


# Challenged replay (HTTP binding): request/response methods only, at most once.
_REPLAYABLE = ("hooks/intercept", "hooks/configuration", "hooks/capabilities")


class TransportFailure(ProtocolError):
    """Sanitized delivery failure, distinct from invalid protocol data."""


AuthErrorCode: TypeAlias = Literal[
    "invalid_configuration",
    "unsupported_binding",
    "credential_unavailable",
    "interaction_required",
    "access_denied",
    "refresh_rejected",
    "discovery_failed",
    "untrusted_destination",
    "provider_failed",
]

_ERROR_MESSAGES = {
    "invalid_configuration": "Invalid authentication configuration",
    "unsupported_binding": "Unsupported authentication binding",
    "credential_unavailable": "Configured credential is unavailable",
    "interaction_required": "Authentication requires host interaction",
    "access_denied": "Authentication access denied",
    "refresh_rejected": "Credential refresh rejected",
    "discovery_failed": "Authentication discovery failed",
    "untrusted_destination": "Authentication destination is not trusted",
    "provider_failed": "Authentication provider failed",
}


AuthRecovery: TypeAlias = Literal["configure", "login", "retry", "none"]


_DEFAULT_RECOVERY: dict[str, AuthRecovery] = {
    "invalid_configuration": "configure",
    "unsupported_binding": "configure",
    "credential_unavailable": "configure",
    "interaction_required": "login",
    "access_denied": "none",
    "refresh_rejected": "login",
    "discovery_failed": "retry",
    "untrusted_destination": "configure",
    "provider_failed": "retry",
}


class AuthenticationFailure(ProtocolError):
    """Safe auth classification; remains a ProtocolError for existing callers."""

    def __init__(
        self,
        message: str = "Authentication provider failed",
        *,
        code: AuthErrorCode = "provider_failed",
        recovery: AuthRecovery | None = None,
        required_scopes: tuple[str, ...] = (),
    ) -> None:
        # Accept the legacy positional argument, but never expose provider text.
        if code not in _ERROR_MESSAGES:
            code = "provider_failed"
        super().__init__(_ERROR_MESSAGES[code])
        self.code = code
        self.recovery = (
            recovery
            if recovery in ("configure", "login", "retry", "none")
            else _DEFAULT_RECOVERY[code]
        )
        # Validated, non-secret scope tokens a host can pass back to `prepare`
        # (step-up). Only interaction_required/access_denied carry them.
        self.required_scopes: tuple[str, ...] = (
            tuple(sorted(set(required_scopes)))
            if code in ("interaction_required", "access_denied")
            and isinstance(required_scopes, tuple)
            and all(
                isinstance(scope, str)
                and re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]+", scope)
                for scope in required_scopes
            )
            else ()
        )
        # Set by ManagedOAuthProvider.complete on every error it raises: True
        # when the login named by the callback's state no longer exists.
        self.login_ended: bool | None = None


SecretResolver: TypeAlias = Callable[[str], str | None | Awaitable[str | None]]


@dataclass(frozen=True)
class BearerCredential:
    token: str = field(repr=False)
    identity: object = field(default_factory=lambda: uuid4().hex, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.token, str) or not re.fullmatch(
            r"[A-Za-z0-9\-._~+/]+=*", self.token
        ):
            raise AuthenticationFailure("Invalid bearer credential")


@dataclass(frozen=True)
class AuthContext:
    backend: dict[str, object] = field(repr=False)
    binding: dict[str, object] | None = field(repr=False)
    destination: str
    purpose: Literal["event", "upload"]
    cancellation: anyio.CancelScope = field(repr=False)


@dataclass(frozen=True)
class AuthChallenge:
    status: int
    headers: dict[str, str] = field(repr=False)
    destination: str
    attempted_identity: object = field(repr=False)
    retry_allowed: bool


class AuthProvider(Protocol):
    async def credential(self, context: AuthContext) -> BearerCredential | None: ...

    async def challenge(
        self, context: AuthContext, challenge: AuthChallenge
    ) -> BearerCredential | None: ...


async def _resolve_secret(binding, env_key, ref_key, resolver=None):
    if env_key in binding:
        return os.environ.get(binding[env_key])
    if ref_key in binding and resolver is not None:
        value = resolver(binding[ref_key])
        return await value if inspect.isawaitable(value) else value
    return None


class EnvironmentAuthProvider:
    """Optional bearer adapter; no discovery, refresh worker, or owned resources."""

    def __init__(self, resolve_credential: SecretResolver | None = None) -> None:
        self.resolve_credential = resolve_credential

    async def credential(self, context: AuthContext) -> BearerCredential | None:
        binding = context.binding
        if binding is None:
            return None
        if binding.get("type") != "bearer":
            raise AuthenticationFailure(code="unsupported_binding")
        token = None
        try:
            token = await _resolve_secret(
                binding, "tokenEnv", "tokenRef", self.resolve_credential
            )
        except OperationCancelledError:
            raise
        except Exception:
            token = None
        if token is None:
            raise AuthenticationFailure(code="credential_unavailable")
        return BearerCredential(token)

    async def challenge(
        self, context: AuthContext, challenge: AuthChallenge
    ) -> BearerCredential | None:
        return None


def _validate_binding(binding: dict[str, Any] | None) -> None:
    if binding is None:
        return
    if binding.get("type") == "bearer":
        if ("tokenEnv" in binding) != ("tokenRef" in binding):
            return
    elif binding.get("type") == "oauth" and binding.get("flow") in (
        "authorization_code_pkce",
        "client_credentials",
    ):
        # Registration validation checks OAuth details. The harness exchanges
        # secrets; clientSecretRef is never an AHP endpoint credential.
        return
    raise AuthenticationFailure(code="unsupported_binding")


class AuthenticatedHTTPTransport(HTTPTransport):
    """One provider, independent endpoint bindings, no hidden auth workers.

    Provider and injected client lifecycle belong to the harness. Client default
    headers, cookies, auth and redirects are not inherited. A challenged
    intercept, configuration or capabilities request replays at most once, with
    the same id and body. Notifications and uploads never replay.
    """

    def __init__(
        self,
        url: str,
        *,
        backend: dict[str, Any],
        auth_provider: AuthProvider | None = None,
        client: Any = None,
        headers: dict[str, str] | None = None,
        validator: Any = None,
        header_resolver: Any = None,
        resolve_credential: SecretResolver | None = None,
    ) -> None:
        super().__init__(url, client=client, headers=headers, validator=validator)
        self.backend = deepcopy(backend)
        self.header_resolver = header_resolver
        self.resolve_credential = resolve_credential
        self.headers = validate_headers(self.headers, sources=False)
        self._registration_headers = validate_headers(
            self.backend.get("transport", {}).get("headers", {})
        )
        self.auth_provider = (
            auth_provider if auth_provider is not None else EnvironmentAuthProvider()
        )
        if (
            "authorization" not in self._registration_headers
            and "authorization" not in self.headers
        ):
            _validate_binding(self.backend.get("authentication"))

    async def _credential(self, context, challenge=None):
        failure: AuthErrorCode | None = None
        recovery: AuthRecovery | None = None
        scopes: tuple[str, ...] = ()
        try:
            credential = (
                await self.auth_provider.credential(context)
                if challenge is None
                else await self.auth_provider.challenge(context, challenge)
            )
            # Observe cancellation even when a provider returns synchronously,
            # including the final non-retryable challenge handoff.
            await anyio.lowlevel.checkpoint()
        except OperationCancelledError:
            raise
        except AuthenticationFailure as exc:
            failure, recovery, scopes = exc.code, exc.recovery, exc.required_scopes
        except Exception:
            # Native cancellation is a BaseException and propagates. Raise only
            # after leaving the handler so even __context__ cannot retain secrets.
            failure = "provider_failed"
        if failure is not None:
            raise AuthenticationFailure(
                code=failure, recovery=recovery, required_scopes=scopes
            )
        if credential is not None and not isinstance(credential, BearerCredential):
            raise AuthenticationFailure("Unsupported delivery credential")
        if challenge is None and context.binding is not None and credential is None:
            raise AuthenticationFailure(code="credential_unavailable")
        return credential

    async def _send(self, request, *, purpose, binding, retry_allowed=False):
        import httpx

        resolved = await resolve_headers(
            self._registration_headers,
            backend=self.backend,
            destination=str(request.url),
            resolver=self.header_resolver,
            resolve_credential=self.resolve_credential
            or getattr(self.auth_provider, "resolve_credential", None),
            purpose=purpose,
        )
        explicit_auth = (
            "authorization" in resolved or "authorization" in request.headers
        )
        if not explicit_auth:
            _validate_binding(binding)
        with anyio.CancelScope() as cancellation:
            context = AuthContext(
                deepcopy(self.backend),
                deepcopy(binding),
                str(request.url),
                purpose,
                cancellation,
            )
            credential = None if explicit_auth else await self._credential(context)
            if not explicit_auth:
                request.headers.pop("Authorization", None)
            if credential is not None:
                request.headers["Authorization"] = "Bearer " + credential.token
            request.headers.update(httpx.Headers(resolved, encoding="latin-1"))
            request.headers.encoding = "latin-1"
            try:
                response = await self._ready().send(
                    request, auth=None, follow_redirects=False
                )
            except httpx.TimeoutException:
                raise TimeoutError("HTTP delivery timed out") from None
            except ProtocolError:
                raise
            except OperationCancelledError:
                raise
            except Exception:
                raise TransportFailure("HTTP delivery failed") from None
            if explicit_auth or response.status_code not in (401, 403):
                return response
            challenges = response.headers.get("www-authenticate", "")
            if response.status_code == 403 and not insufficient_scope(response.headers):
                # Only one Bearer insufficient_scope challenge makes a 403 an
                # auth challenge (the provider validates its scope); any
                # other 403 is an operational failure for the caller.
                return response
            safe = (
                retry_allowed
                and re.search(r"(?:^|,)\s*Bearer(?:\s|$)", challenges, re.I) is not None
            )
            challenge = AuthChallenge(
                response.status_code,
                dict(response.headers),
                str(response.url),
                credential.identity if credential is not None else None,
                safe,
            )
            replacement = await self._credential(context, challenge)
            if not safe or replacement is None:
                return response
            await response.aclose()
            # Event bytes were serialized once; do not rebuild a mutable message.
            replay = httpx.Request(
                request.method,
                request.url,
                content=request.content,
                headers=request.headers,
            )
            replay.headers["Authorization"] = "Bearer " + replacement.token
            try:
                final = await self._ready().send(
                    replay, auth=None, follow_redirects=False
                )
            except httpx.TimeoutException:
                raise TimeoutError("HTTP delivery timed out") from None
            except ProtocolError:
                raise
            except OperationCancelledError:
                raise
            except Exception:
                raise TransportFailure("HTTP delivery failed") from None
            if final.status_code == 401 or (
                final.status_code == 403 and insufficient_scope(final.headers)
            ):
                # A second rejection is an operational failure; the provider
                # still handles it (no replay). A plain 403 is classified by
                # the caller like any other non-2xx response.
                await self._credential(
                    context,
                    AuthChallenge(
                        final.status_code,
                        dict(final.headers),
                        str(final.url),
                        replacement.identity,
                        False,
                    ),
                )
            return final
        raise OperationCancelledError("Authentication operation cancelled")

    async def _event(self, message, *, retry_allowed, intercept_response=False):
        import httpx

        ident = message.get("id")
        request = httpx.Request(
            "POST",
            self.url,
            content=json.dumps(message, allow_nan=False).encode(),
            headers=httpx.Headers(
                {
                    **self.headers,
                    "content-type": "application/json",
                    "accept": "application/json",
                },
                encoding="latin-1",
            ),
        )
        response = await self._send(
            request,
            purpose="event",
            binding=self.backend.get("authentication"),
            retry_allowed=retry_allowed,
        )
        if not 200 <= response.status_code < 300:
            # A correlated canonical JSON-RPC rejection retains its protocol
            # classification. Never surface arbitrary HTTP error response text.
            if intercept_response:
                try:
                    rejected = response.json()
                except (ValueError, UnicodeError):
                    rejected = None
                if isinstance(rejected, dict) and "error" in rejected:
                    _validate_intercept_response(
                        self._validator, {"id": ident}, rejected
                    )
            raise TransportFailure(
                "HTTP delivery rejected: " + str(response.status_code)
            )
        return response

    async def request(self, message: dict[str, Any]) -> dict[str, Any]:
        ident = message["id"]
        correlation = deepcopy(message)
        response = await self._event(
            message,
            retry_allowed=message.get("method") in _REPLAYABLE,
            intercept_response=message.get("method") == "hooks/intercept",
        )
        if (
            message.get("method") == "hooks/configuration"
            and response.status_code != 200
        ):
            # Discovery succeeds only with 200; any other status is unavailable.
            raise TransportFailure(
                "HTTP delivery rejected: " + str(response.status_code)
            )
        try:
            result = response.json()
        except (ValueError, UnicodeError):
            raise ProtocolError("Malformed HTTP protocol response") from None
        if not isinstance(result, dict) or result.get("id") != ident:
            raise ProtocolError("HTTP response correlation mismatch")
        if message.get("method") == "hooks/configuration":
            _raise_rpc_error(self._validator, correlation, result)
        if message.get("method") in ("hooks/configuration", "hooks/capabilities"):
            if response.status_code != 200:
                raise ProtocolError("Unexpected HTTP response status")
            self._validator.validate(
                message["method"].removeprefix("hooks/") + "-response", result
            )
        else:
            _validate_intercept_response(self._validator, correlation, result)
        return result

    async def notify(self, message: dict[str, Any]) -> None:
        response = await self._event(message, retry_allowed=False)
        if response.content:
            raise ProtocolError("Unexpected observation response body")

    async def upload(
        self,
        url,
        body,
        *,
        headers=None,
        selection="body",
        size=None,
        sha256=None,
        authentication=None,
    ) -> "ContentUploadReceipt | None":
        # Reuse EOF/hash/receipt validation, routing its single send through
        # the upload binding. No stream is read twice or buffered.
        owner = self

        class UploadClient:
            async def send(self, request, **kwargs):
                response = await owner._send(
                    request,
                    purpose="upload",
                    binding=authentication,
                )
                if not 200 <= response.status_code < 300:
                    raise TransportFailure(
                        "HTTP upload rejected: " + str(response.status_code)
                    )
                return response

        transport = HTTPTransport(url, client=UploadClient(), validator=self._validator)
        try:
            return await transport.upload(
                url,
                body,
                headers=headers,
                selection=selection,
                size=size,
                sha256=sha256,
            )
        except ProtocolError:
            raise
        except (ValueError, UnicodeError):
            raise ProtocolError("Malformed HTTP upload response") from None


# Kept separate from the transport implementation; all public providers above
# retain their existing entry points and lifecycle ownership.
from ._auth_challenge import insufficient_scope  # noqa: E402
from ._auth_routing import (  # noqa: E402
    AuthTarget as AuthTarget,
    BearerBinding as BearerBinding,
    OAuthBinding as OAuthBinding,
    NormalizedBinding as NormalizedBinding,
    BearerAuthProvider as BearerAuthProvider,
    RoutingAuthProvider as RoutingAuthProvider,
    normalize_auth_target as normalize_auth_target,
)
