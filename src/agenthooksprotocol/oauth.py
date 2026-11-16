"""Optional, host-controlled managed OAuth. Importing is dependency-light.

Install agenthooksprotocol[oauth] to perform exchanges. No browsers, listeners,
workers, HTTP clients, or token stores are created outside a bounded operation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
import math
import importlib
import secrets
import time
from typing import Protocol, TypeVar, cast
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import anyio

from .auth import (
    AuthenticationFailure,
    AuthChallenge,
    AuthContext,
    AuthErrorCode,
    AuthRecovery,
    AuthTarget,
    BearerCredential,
    normalize_auth_target,
)
from .runtime import OperationCancelledError
from ._oauth_types import (
    OAuthClientConfiguration as OAuthClientConfiguration,
    OAuthNetwork as OAuthNetwork,
    OAuthTrustPolicy as OAuthTrustPolicy,
    OAuthTokenStore as OAuthTokenStore,
    OAuthStoreGuard as OAuthStoreGuard,
    OAuthMetadata as OAuthMetadata,
    OAuthRecord as OAuthRecord,
    StoredToken as StoredToken,
    PendingState as PendingState,
    StoreKey as StoreKey,
    EndpointPurpose as EndpointPurpose,
    OperationBudget as OperationBudget,
    PendingLogin as PendingLogin,
    Ready as Ready,
)

T = TypeVar("T")


class _OAuthOperations(Protocol):
    def create_authorization_url(
        self, url: str, **kwargs: object
    ) -> tuple[str, str]: ...
    async def fetch_token(self, url: str, **kwargs: object) -> Mapping[str, object]: ...
    async def refresh_token(
        self, url: str, **kwargs: object
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class _Attempt:
    key: StoreKey = field(repr=False)
    generation: str = field(repr=False)
    target_identity: tuple[object, ...] = field(repr=False)


class ManagedOAuthProvider:
    """Library-backed OAuth with mandatory host trust/network/store boundaries.

    The store owns coordination across all providers/processes sharing a key.
    Only guarded CAS transitions write state. Network awaits occur under that
    key's guard to coalesce refresh/login; host callbacks MUST NOT reenter it.
    Refresh/code exchanges first reserve a generation. Cancellation/ambiguous
    network failure leaves that reservation unusable rather than restoring a
    potentially rotated refresh token. reset() is an explicit host repair action.
    """

    def __init__(
        self,
        *,
        network: OAuthNetwork,
        policy: OAuthTrustPolicy,
        store: OAuthTokenStore,
        namespace: str,
        operation_timeout: float = 30,
        expiry_skew: float = 30,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            not namespace
            or not math.isfinite(operation_timeout)
            or operation_timeout <= 0
            or not math.isfinite(expiry_skew)
            or expiry_skew < 0
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        self.network, self.policy, self.store = network, policy, store
        self.namespace, self.operation_timeout = namespace, operation_timeout
        self.expiry_skew, self.clock = expiry_skew, clock

    async def _run(
        self, operation: Callable[[], Awaitable[T]], budget: OperationBudget
    ) -> T:
        failure: AuthErrorCode = "provider_failed"
        recovery: AuthRecovery | None = None
        timed_out = cancelled = False
        try:
            await anyio.lowlevel.checkpoint_if_cancelled()
            with anyio.fail_after(budget.remaining()):
                return await operation()
        except TimeoutError:
            timed_out = True
        except OperationCancelledError:
            cancelled = True
        except AuthenticationFailure as error:
            failure, recovery = error.code, error.recovery
        except Exception:
            pass
        # Outside the handler: no secret-bearing __cause__ or __context__.
        if timed_out:
            raise TimeoutError("Authentication operation timed out")
        if cancelled:
            raise OperationCancelledError("Authentication operation cancelled")
        raise AuthenticationFailure(code=failure, recovery=recovery)

    @staticmethod
    def _dependencies() -> None:
        try:
            importlib.import_module("httpx")
            importlib.import_module("httpx2")
            importlib.import_module("authlib.integrations.httpx_client")
        except ImportError:
            raise AuthenticationFailure(
                code="unsupported_binding", recovery="configure"
            ) from None

    def _check_target(self, target: AuthTarget) -> None:
        if target.namespace != self.namespace or target.kind == "bearer":
            raise AuthenticationFailure(code="invalid_configuration")

    @staticmethod
    def _key(target: AuthTarget, metadata: OAuthMetadata) -> StoreKey:
        config = metadata.configuration
        return target.identity + (
            config.issuer,
            metadata.resource,
            config.client_id,
            config.flow,
            config.scopes,
            config.redirect_uri,
            config.token_endpoint_auth_method,
        )

    def _ready(self, target: AuthTarget, key: StoreKey, record: OAuthRecord) -> Ready:
        if record.token is None:
            raise AuthenticationFailure(code="credential_unavailable")
        return Ready(
            BearerCredential(
                record.token.access_token,
                _Attempt(key, record.generation, target.identity),
            )
        )

    @staticmethod
    async def _cas(
        guard: OAuthStoreGuard, previous: OAuthRecord | None, record: OAuthRecord | None
    ) -> None:
        if not await guard.compare_and_swap(
            previous.generation if previous else None, record
        ):
            raise AuthenticationFailure(code="provider_failed", recovery="retry")

    async def _commit_token(
        self, guard: OAuthStoreGuard, reserved: OAuthRecord, token: StoredToken
    ) -> OAuthRecord:
        active = OAuthRecord(uuid4().hex, "active", reserved.metadata, token)
        # Rotation may already have occurred externally. Finish one bounded
        # atomic store commit before honoring cancellation; never restore stale
        # credentials from a broad exception/finally cleanup path.
        with anyio.CancelScope(shield=True):
            with anyio.fail_after(1):
                await self._cas(guard, reserved, active)
        await anyio.lowlevel.checkpoint()
        return active

    def _client(
        self, metadata: OAuthMetadata, budget: OperationBudget
    ) -> AbstractAsyncContextManager[_OAuthOperations]:
        try:
            import httpx
            import httpx2
            from authlib.integrations.httpx_client import AsyncOAuth2Client  # type: ignore[import-untyped]
        except ImportError:
            raise AuthenticationFailure(
                code="unsupported_binding", recovery="configure"
            ) from None
        from ._oauth_discovery import safe_request

        network = self.network

        class HostTransport(httpx2.AsyncBaseTransport):
            async def handle_async_request(
                self, request: httpx2.Request
            ) -> httpx2.Response:
                # Authlib uses HTTPX2, whose request/response/stream classes are
                # distinct from HTTPX. Keep the established host network boundary
                # on HTTPX and explicitly bridge fully buffered OAuth messages.
                host_request = httpx.Request(
                    request.method, str(request.url),
                    headers=request.headers.multi_items(),
                    content=await request.aread(),
                    extensions=dict(request.extensions),
                )
                response = await safe_request(network, host_request, "token", budget)
                return httpx2.Response(
                    response.status_code, headers=response.headers.multi_items(),
                    content=response.content,
                )

            async def aclose(self) -> None:
                # The host network and its injected client remain borrowed.
                pass

        config = metadata.configuration
        return cast(
            AbstractAsyncContextManager[_OAuthOperations],
            AsyncOAuth2Client(
                config.client_id,
                config.client_secret,
                scope=" ".join(config.scopes),
                redirect_uri=config.redirect_uri,
                token_endpoint_auth_method=config.token_endpoint_auth_method,
                code_challenge_method="S256",
                transport=HostTransport(),
                follow_redirects=False,
                timeout=budget.remaining(),
                trust_env=False,
            ),
        )

    def _token(
        self,
        response: Mapping[str, object],
        metadata: OAuthMetadata,
        previous: StoredToken | None,
    ) -> StoredToken:
        value, kind, lifetime = (
            response.get("access_token"),
            response.get("token_type"),
            response.get("expires_in"),
        )
        if (
            not isinstance(value, str)
            or not isinstance(kind, str)
            or kind.lower() != "bearer"
            or isinstance(lifetime, bool)
            or not isinstance(lifetime, (int, float))
            or not math.isfinite(lifetime)
            or lifetime <= 0
        ):
            raise AuthenticationFailure(code="credential_unavailable")
        BearerCredential(value)
        scopes = metadata.configuration.scopes
        granted = response.get("scope")
        if granted is not None and (
            not isinstance(granted, str) or set(granted.split()) != set(scopes)
        ):
            raise AuthenticationFailure(code="access_denied")
        refresh = response.get(
            "refresh_token", previous.refresh_token if previous else None
        )
        if refresh is not None and (not isinstance(refresh, str) or not refresh):
            raise AuthenticationFailure(code="credential_unavailable")
        return StoredToken(value, self.clock() + lifetime, refresh, scopes)

    async def _exchange(
        self,
        guard: OAuthStoreGuard,
        previous: OAuthRecord | None,
        metadata: OAuthMetadata,
        budget: OperationBudget,
        *,
        pending: PendingState | None = None,
        callback: str | None = None,
    ) -> OAuthRecord:
        old_token = previous.token if previous else None
        reserved = OAuthRecord(uuid4().hex, "refreshing", metadata, old_token)
        await self._cas(guard, previous, reserved)
        oauth_error: str | None = None
        response = None
        try:
            async with self._client(metadata, budget) as client:
                if pending is not None:
                    response = await client.fetch_token(
                        metadata.token_endpoint,
                        authorization_response=callback,
                        state=pending.state,
                        code_verifier=pending.verifier,
                        resource=metadata.resource,
                    )
                elif old_token is not None and old_token.refresh_token:
                    response = await client.refresh_token(
                        metadata.token_endpoint,
                        refresh_token=old_token.refresh_token,
                        resource=metadata.resource,
                    )
                else:
                    response = await client.fetch_token(
                        metadata.token_endpoint,
                        grant_type="client_credentials",
                        resource=metadata.resource,
                    )
        except (TimeoutError, OperationCancelledError, AuthenticationFailure):
            raise
        except Exception as error:
            # Only explicit OAuth protocol rejections are known not to have
            # rotated a token. Network/parse/store uncertainty stays reserved.
            from authlib.integrations.base_client.errors import OAuthError  # type: ignore[import-untyped]

            if isinstance(error, OAuthError):
                oauth_error = error.error
            else:
                oauth_error = "unknown"
        if oauth_error is not None:
            if (
                oauth_error in ("temporarily_unavailable", "server_error")
                and old_token is not None
                and pending is None
            ):
                retained = OAuthRecord(uuid4().hex, "active", metadata, old_token)
                await self._cas(guard, reserved, retained)
                raise AuthenticationFailure(code="provider_failed", recovery="retry")
            if oauth_error == "invalid_grant":
                await self._cas(
                    guard, reserved, OAuthRecord(uuid4().hex, "rejected", metadata)
                )
                raise AuthenticationFailure(
                    code="refresh_rejected" if old_token else "access_denied",
                    recovery="login",
                )
            if oauth_error == "access_denied":
                await self._cas(
                    guard, reserved, OAuthRecord(uuid4().hex, "rejected", metadata)
                )
                raise AuthenticationFailure(code="access_denied", recovery="login")
            raise AuthenticationFailure(code="provider_failed", recovery="login")
        if response is None:
            raise AuthenticationFailure(code="provider_failed")
        token = self._token(response, metadata, old_token)
        return await self._commit_token(guard, reserved, token)

    async def _pending(
        self,
        guard: OAuthStoreGuard,
        previous: OAuthRecord | None,
        metadata: OAuthMetadata,
        key: StoreKey,
        budget: OperationBudget,
    ) -> PendingLogin:
        pending = (
            previous.pending if previous and previous.status == "pending" else None
        )
        if pending is None or pending.expires_at <= self.clock():
            config = metadata.configuration
            if (
                config.flow != "authorization_code_pkce"
                or not metadata.authorization_endpoint
                or not config.redirect_uri
            ):
                raise AuthenticationFailure(code="unsupported_binding")
            async with self._client(metadata, budget) as client:
                verifier = secrets.token_urlsafe(64)
                state = secrets.token_urlsafe(32)
                url, state = client.create_authorization_url(
                    metadata.authorization_endpoint,
                    state=state,
                    code_verifier=verifier,
                    resource=metadata.resource,
                )
            pending = PendingState(
                metadata, state, verifier, url, self.clock() + config.login_lifetime
            )
            previous_record = OAuthRecord(
                uuid4().hex, "pending", metadata, pending=pending
            )
            await self._cas(guard, previous, previous_record)
            previous = previous_record
        await self.network.authorize(pending.authorization_url, "authorization", budget)
        if previous is None:
            raise AuthenticationFailure(code="provider_failed")
        return PendingLogin(
            key, previous.generation, pending.authorization_url, pending.expires_at
        )

    async def _prepare(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        challenge: AuthChallenge | None,
        rejected_generation: str | None = None,
        expected_key: StoreKey | None = None,
    ) -> Ready | PendingLogin:
        self._dependencies()
        from ._oauth_discovery import discover

        self._check_target(target)
        metadata = await discover(target, challenge, self.network, self.policy, budget)
        key = self._key(target, metadata)
        if expected_key is not None and key != expected_key:
            raise AuthenticationFailure(code="invalid_configuration")
        async with self.store.coordinate(key, budget) as guard:
            record = await guard.load()
            if record is not None:
                if record.metadata != metadata:
                    # Endpoint/config policy changed under the same identity.
                    raise AuthenticationFailure(code="invalid_configuration")
                if (
                    record.status == "refreshing"
                    and metadata.configuration.flow == "client_credentials"
                    and (record.token is None or not record.token.refresh_token)
                ):
                    active = await self._exchange(guard, record, metadata, budget)
                    return self._ready(target, key, active)
                if record.status == "refreshing":
                    raise AuthenticationFailure(
                        code="interaction_required", recovery="login"
                    )
                if record.status == "active" and record.token is not None:
                    rejected = rejected_generation == record.generation
                    if (
                        not rejected
                        and record.token.expires_at > self.clock() + self.expiry_skew
                    ):
                        return self._ready(target, key, record)
                    if (
                        record.token.refresh_token
                        or metadata.configuration.flow == "client_credentials"
                    ):
                        active = await self._exchange(guard, record, metadata, budget)
                        return self._ready(target, key, active)
            if metadata.configuration.flow == "client_credentials":
                active = await self._exchange(guard, record, metadata, budget)
                return self._ready(target, key, active)
            return await self._pending(guard, record, metadata, key, budget)

    async def prepare(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        *,
        challenge: AuthChallenge | None = None,
    ) -> Ready | PendingLogin:
        return await self._run(lambda: self._prepare(target, budget, challenge), budget)

    async def _complete(
        self,
        target: AuthTarget,
        login: PendingLogin,
        callback_url: str,
        budget: OperationBudget,
    ) -> Ready:
        self._check_target(target)
        async with self.store.coordinate(login.key, budget) as guard:
            record = await guard.load()
            if (
                record is None
                or record.status != "pending"
                or record.generation != login.generation
                or record.pending is None
                or self._key(target, record.metadata) != login.key
            ):
                raise AuthenticationFailure(code="invalid_configuration")
            pending, config = record.pending, record.metadata.configuration
            resource = await self.policy.resource(target, budget)
            selected = await self.policy.select(
                target, resource, (config.issuer,), config.scopes, budget
            )
            if resource != record.metadata.resource or selected != config:
                raise AuthenticationFailure(code="access_denied")
            if pending.expires_at <= self.clock():
                raise AuthenticationFailure(
                    code="interaction_required", recovery="login"
                )
            if config.redirect_uri is None:
                raise AuthenticationFailure(code="invalid_configuration")
            callback, redirect = urlsplit(callback_url), urlsplit(config.redirect_uri)
            if (
                callback.fragment
                or callback.username is not None
                or callback.password is not None
                or (callback.scheme, callback.netloc, callback.path)
                != (redirect.scheme, redirect.netloc, redirect.path)
            ):
                raise AuthenticationFailure(code="access_denied")
            values = parse_qs(callback.query, keep_blank_values=True)
            fixed = parse_qs(redirect.query, keep_blank_values=True)
            if any(values.get(key) != value for key, value in fixed.items()):
                raise AuthenticationFailure(code="access_denied")
            if (
                values.get("state") != [pending.state]
                or ("iss" in values and values["iss"] != [config.issuer])
                or (
                    record.metadata.require_response_issuer
                    and values.get("iss") != [config.issuer]
                )
            ):
                raise AuthenticationFailure(code="access_denied")
            if "error" in values:
                await self._cas(
                    guard, record, OAuthRecord(uuid4().hex, "rejected", record.metadata)
                )
                raise AuthenticationFailure(code="access_denied", recovery="login")
            if len(values.get("code", [])) != 1 or not values["code"][0]:
                raise AuthenticationFailure(code="access_denied")
            # Revalidate local endpoint policy at completion, not only login prep.
            await self.network.authorize(callback_url, "authorization", budget)
            active = await self._exchange(
                guard,
                record,
                record.metadata,
                budget,
                pending=pending,
                callback=callback_url,
            )
            return self._ready(target, login.key, active)

    async def complete(
        self,
        target: AuthTarget,
        login: PendingLogin,
        callback_url: str,
        budget: OperationBudget,
    ) -> Ready:
        return await self._run(
            lambda: self._complete(target, login, callback_url, budget), budget
        )

    async def reset(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        *,
        handle: PendingLogin | BearerCredential | None = None,
        challenge: AuthChallenge | None = None,
    ) -> None:
        """Explicitly invalidate the current grant. A retained handle avoids I/O.

        This deliberate host action clears the current generation, not merely
        the handle's old generation. Do not call reset automatically on stale 401.
        """

        async def reset_record() -> None:
            self._check_target(target)
            if isinstance(handle, PendingLogin):
                key = handle.key
            elif isinstance(handle, BearerCredential) and isinstance(
                handle.identity, _Attempt
            ):
                if handle.identity.target_identity != target.identity:
                    raise AuthenticationFailure(code="invalid_configuration")
                key = handle.identity.key
            elif handle is not None:
                raise AuthenticationFailure(code="invalid_configuration")
            else:
                from ._oauth_discovery import discover

                metadata = await discover(
                    target, challenge, self.network, self.policy, budget
                )
                key = self._key(target, metadata)
            if key[: len(target.identity)] != target.identity:
                raise AuthenticationFailure(code="invalid_configuration")
            async with self.store.coordinate(key, budget) as guard:
                record = await guard.load()
                if record is not None and self._key(target, record.metadata) != key:
                    raise AuthenticationFailure(code="invalid_configuration")
                await self._cas(guard, record, None)

        await self._run(reset_record, budget)

    def _budget(self) -> OperationBudget:
        return OperationBudget.after(self.operation_timeout)

    async def credential(self, context: AuthContext) -> BearerCredential | None:
        if context.binding is None:
            return None
        result = await self.prepare(
            normalize_auth_target(context, namespace=self.namespace), self._budget()
        )
        if isinstance(result, PendingLogin):
            raise AuthenticationFailure(code="interaction_required", recovery="login")
        return result.credential

    async def challenge(
        self, context: AuthContext, challenge: AuthChallenge
    ) -> BearerCredential | None:
        target = normalize_auth_target(context, namespace=self.namespace)
        attempt = challenge.attempted_identity
        if challenge.status == 403:
            raise AuthenticationFailure(code="access_denied")
        if challenge.status != 401 or not challenge.retry_allowed:
            return None
        if attempt is not None and (
            not isinstance(attempt, _Attempt)
            or attempt.target_identity != target.identity
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        budget = self._budget()
        result = await self._run(
            lambda: self._prepare(
                target,
                budget,
                challenge,
                attempt.generation if isinstance(attempt, _Attempt) else None,
                attempt.key if isinstance(attempt, _Attempt) else None,
            ),
            budget,
        )
        if isinstance(result, PendingLogin):
            raise AuthenticationFailure(code="interaction_required", recovery="login")
        return result.credential
