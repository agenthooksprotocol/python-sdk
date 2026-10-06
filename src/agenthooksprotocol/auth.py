"""Registration-aware bearer delivery with harness-owned provider resources."""

from copy import deepcopy
from dataclasses import dataclass, field
import inspect
import json
import os
import re
from typing import Any, Literal, Protocol
from uuid import uuid4

import anyio

from .runtime import OperationCancelledError, ProtocolError, validate_intercept_response
from .transports.http import HTTPTransport


class TransportFailure(ProtocolError):
    """Sanitized delivery failure, distinct from invalid protocol data."""


class AuthenticationFailure(ProtocolError):
    """Sanitized provider, binding, or credential failure."""


@dataclass(frozen=True)
class BearerCredential:
    token: str = field(repr=False)
    identity: Any = field(default_factory=lambda: uuid4().hex, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.token, str) or not re.fullmatch(
            r"[A-Za-z0-9\-._~+/]+=*", self.token
        ):
            raise AuthenticationFailure("Invalid bearer credential")


@dataclass(frozen=True)
class AuthContext:
    backend: dict[str, Any] = field(repr=False)
    binding: dict[str, Any] | None = field(repr=False)
    destination: str
    purpose: Literal["event", "upload"]
    cancellation: anyio.CancelScope = field(repr=False)


@dataclass(frozen=True)
class AuthChallenge:
    status: int
    headers: dict[str, str] = field(repr=False)
    destination: str
    attempted_identity: Any = field(repr=False)
    retry_allowed: bool


class AuthProvider(Protocol):
    async def credential(self, context: AuthContext) -> BearerCredential | None: ...

    async def challenge(
        self, context: AuthContext, challenge: AuthChallenge
    ) -> BearerCredential | None: ...


class EnvironmentAuthProvider:
    """Optional bearer adapter; no discovery, refresh worker, or owned resources."""

    def __init__(self, resolve_credential: Any = None) -> None:
        self.resolve_credential = resolve_credential

    async def credential(self, context: AuthContext) -> BearerCredential | None:
        binding = context.binding
        if binding is None:
            return None
        if binding.get("type") != "bearer":
            raise AuthenticationFailure(
                "Configured authentication requires a host provider"
            )
        token = None
        try:
            if "tokenEnv" in binding:
                token = os.environ.get(binding["tokenEnv"])
            elif "tokenRef" in binding and self.resolve_credential is not None:
                token = self.resolve_credential(binding["tokenRef"])
                if inspect.isawaitable(token):
                    token = await token
        except OperationCancelledError:
            raise
        except Exception:
            raise AuthenticationFailure(
                "Cannot resolve configured credential"
            ) from None
        if token is None:
            raise AuthenticationFailure("Cannot resolve configured credential")
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
    raise AuthenticationFailure("Unsupported authentication binding")


class AuthenticatedHTTPTransport(HTTPTransport):
    """One provider, independent endpoint bindings, no hidden auth workers.

    Provider and injected client lifecycle belong to the harness. Client default
    headers, cookies, auth and redirects are not inherited. Only a rejected
    interception can retry, once. Notifications and uploads never replay.
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
    ) -> None:
        super().__init__(url, client=client, headers=headers, validator=validator)
        self.backend = deepcopy(backend)
        self.auth_provider = (
            auth_provider if auth_provider is not None else EnvironmentAuthProvider()
        )
        _validate_binding(self.backend.get("authentication"))

    async def _credential(self, context, challenge=None):
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
        except Exception:
            # Cancellation is a BaseException and deliberately propagates.
            # Provider exceptions may contain secrets.
            raise AuthenticationFailure("Authentication provider failed") from None
        if credential is not None and not isinstance(credential, BearerCredential):
            raise AuthenticationFailure("Unsupported delivery credential")
        if challenge is None and context.binding is not None and credential is None:
            raise AuthenticationFailure(
                "Configured authentication returned no credential"
            )
        return credential

    async def _send(self, request, *, purpose, binding, retry_allowed=False):
        import httpx

        _validate_binding(binding)
        with anyio.CancelScope() as cancellation:
            context = AuthContext(
                deepcopy(self.backend),
                deepcopy(binding),
                str(request.url),
                purpose,
                cancellation,
            )
            credential = await self._credential(context)
            request.headers.pop("Authorization", None)
            if credential is not None:
                request.headers["Authorization"] = "Bearer " + credential.token
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
            if response.status_code not in (401, 403):
                return response
            challenges = response.headers.get("www-authenticate", "")
            safe = (
                retry_allowed
                and response.status_code == 401
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
            if final.status_code in (401, 403):
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
            headers={**self.headers, "Content-Type": "application/json"},
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
                    validate_intercept_response(
                        self._validator, {"id": ident}, rejected
                    )
            raise TransportFailure(
                "HTTP delivery rejected: " + str(response.status_code)
            )
        return response

    async def request(self, message: dict[str, Any]) -> dict[str, Any]:
        ident = message["id"]
        response = await self._event(
            message,
            retry_allowed=message.get("method") == "hooks/intercept",
            intercept_response=True,
        )
        try:
            result = response.json()
        except (ValueError, UnicodeError):
            raise ProtocolError("Malformed HTTP protocol response") from None
        if not isinstance(result, dict) or result.get("id") != ident:
            raise ProtocolError("HTTP response correlation mismatch")
        validate_intercept_response(self._validator, {"id": ident}, result)
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
    ):
        # Reuse EOF/hash/descriptor validation, routing its single send through
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
