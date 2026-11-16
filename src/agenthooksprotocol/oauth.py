"""Optional, host-controlled managed OAuth. Importing is dependency-light.

Install agenthooksprotocol[oauth] to perform exchanges. No browsers, listeners,
workers, HTTP clients, or token stores are created outside a bounded operation.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
import math
import importlib
import secrets
import time
from typing import Protocol, TypeVar
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
    OAuthBinding,
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


class _ExchangeError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


class _ProtocolOAuth:
    """Pure OAuth message primitives; the host owns every HTTP operation."""

    def __init__(
        self,
        network: OAuthNetwork,
        config: OAuthClientConfiguration,
        budget: OperationBudget,
    ) -> None:
        self.network, self.config, self.budget = network, config, budget

    def create_authorization_url(self, url: str, **kwargs: object) -> tuple[str, str]:
        from authlib.oauth2.rfc6749.parameters import prepare_grant_uri  # type: ignore[import-untyped]
        from authlib.oauth2.rfc7636 import create_s256_code_challenge  # type: ignore[import-untyped]

        state = str(kwargs.pop("state"))
        verifier = str(kwargs.pop("code_verifier"))
        result = prepare_grant_uri(
            url,
            self.config.client_id,
            "code",
            redirect_uri=self.config.redirect_uri,
            scope=" ".join(self.config.scopes),
            state=state,
            code_challenge=create_s256_code_challenge(verifier),
            code_challenge_method="S256",
            **kwargs,
        )
        return str(result), state

    async def fetch_token(self, url: str, **kwargs: object) -> Mapping[str, object]:
        callback = kwargs.pop("authorization_response", None)
        kwargs.pop("state", None)
        if callback is not None:
            kwargs["code"] = parse_qs(urlsplit(str(callback)).query)["code"][0]
            kwargs["redirect_uri"] = self.config.redirect_uri
            grant_type = "authorization_code"
        else:
            grant_type = str(kwargs.pop("grant_type", "client_credentials"))
            kwargs["scope"] = " ".join(self.config.scopes)
        return await self._request(url, grant_type, kwargs)

    async def refresh_token(self, url: str, **kwargs: object) -> Mapping[str, object]:
        # Omitting scope preserves the actual (possibly narrowed) grant.
        return await self._request(url, "refresh_token", kwargs)

    async def _request(
        self, url: str, grant_type: str, parameters: dict[str, object]
    ) -> Mapping[str, object]:
        import httpx
        from authlib.oauth2.auth import ClientAuth  # type: ignore[import-untyped]
        from authlib.oauth2.rfc6749.parameters import prepare_token_request
        from ._oauth_discovery import safe_request

        body = prepare_token_request(grant_type, **parameters)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        url, headers, body = ClientAuth(
            self.config.client_id,
            self.config.client_secret,
            self.config.token_endpoint_auth_method,
        ).prepare("POST", url, headers, body)
        response = await safe_request(
            self.network,
            httpx.Request(
                "POST",
                url,
                headers=headers,
                content=body,
            ),
            "token",
            self.budget,
        )
        if response.status_code >= 500:
            raise _ExchangeError("server_error")
        try:
            data = response.json()
        except ValueError:
            raise _ExchangeError("unknown") from None
        if not isinstance(data, dict):
            raise _ExchangeError("unknown")
        if "error" in data:
            code = data["error"]
            raise _ExchangeError(
                code
                if code
                in (
                    "invalid_grant",
                    "invalid_client",
                    "unauthorized_client",
                    "access_denied",
                    "temporarily_unavailable",
                    "server_error",
                    "invalid_scope",
                )
                else "unknown"
            )
        if not 200 <= response.status_code < 300:
            raise _ExchangeError("unknown")
        return data


@dataclass(frozen=True)
class _Attempt:
    key: StoreKey = field(repr=False)
    generation: str = field(repr=False)
    target_identity: tuple[object, ...] = field(repr=False)


class ManagedOAuthProvider:
    """Library-backed OAuth with mandatory host trust/network/store boundaries.

    The store owns coordination across all providers/processes sharing a key.
    Guarded CAS transitions serialize grants; binding metadata and local policy
    are resolved outside the grant lock. Refresh ambiguity retains credentials
    for host-budgeted retry; a rotating server can still reject their reuse.
    Host store/network callbacks must not reenter the same grant lock.
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
        # Each entry is mutated only while the host store holds that grant lock.
        # Native cancellation ownership is deliberately process-local, not a
        # serialized credential-store field. A new provider prepares a new login.
        self._pending_owners: dict[StoreKey, tuple[str, OperationBudget]] = {}

    async def _run(
        self, operation: Callable[[], Awaitable[T]], budget: OperationBudget
    ) -> T:
        failure: AuthErrorCode = "provider_failed"
        recovery: AuthRecovery | None = None
        timed_out = cancelled = False
        try:
            await anyio.lowlevel.checkpoint_if_cancelled()
            with anyio.fail_after(budget.remaining()):
                result = await operation()
                await anyio.lowlevel.checkpoint_if_cancelled()
                budget.remaining()
                return result
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
            importlib.import_module("authlib.oauth2.rfc6749.parameters")
        except ImportError:
            raise AuthenticationFailure(
                code="unsupported_binding", recovery="configure"
            ) from None

    def _check_target(self, target: AuthTarget) -> None:
        if (
            target.namespace != self.namespace
            or target.kind == "bearer"
            or not isinstance(target.backend_id, str)
            or not target.backend_id
            or target.purpose not in ("event", "upload")
        ):
            raise AuthenticationFailure(code="invalid_configuration")

    @staticmethod
    def _key(target: AuthTarget, metadata: OAuthMetadata) -> StoreKey:
        from ._oauth_types import grant_key

        return grant_key(target, metadata)

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

    @asynccontextmanager
    async def _client(
        self,
        metadata: OAuthMetadata,
        budget: OperationBudget,
        config: OAuthClientConfiguration | None = None,
    ) -> AsyncIterator[_OAuthOperations]:
        # Secrets are operation-local and never enter persisted metadata.
        yield _ProtocolOAuth(self.network, config or metadata.configuration, budget)

    def _token(
        self,
        response: Mapping[str, object],
        metadata: OAuthMetadata,
        previous: StoredToken | None,
        *,
        enforce_allowed: bool = True,
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
            or ("expires_in" in response and lifetime is None)
            or (
                lifetime is not None
                and (
                    isinstance(lifetime, bool)
                    or not isinstance(lifetime, (int, float))
                    or not math.isfinite(lifetime)
                    or lifetime <= 0
                )
            )
        ):
            raise AuthenticationFailure(code="credential_unavailable")
        BearerCredential(value)
        config = metadata.configuration
        scopes = previous.scopes if previous is not None else config.scopes
        granted = response.get("scope")
        if "scope" in response and granted is None:
            raise AuthenticationFailure(code="access_denied")
        if granted is not None:
            if not isinstance(granted, str):
                raise AuthenticationFailure(code="access_denied")
            scopes = tuple(granted.split(" ")) if granted else ()
        allowed = (
            config.allowed_scopes
            if config.allowed_scopes is not None
            else config.scopes
        )
        if any(
            not scope
            or any(ord(c) < 0x21 or ord(c) > 0x7E or c in '"\\' for c in scope)
            for scope in scopes
        ):
            raise AuthenticationFailure(code="access_denied")
        if enforce_allowed and not set(scopes).issubset(allowed):
            raise AuthenticationFailure(code="access_denied")
        refresh = response.get(
            "refresh_token", previous.refresh_token if previous else None
        )
        if refresh is not None and (not isinstance(refresh, str) or not refresh):
            raise AuthenticationFailure(code="credential_unavailable")
        return StoredToken(
            value,
            self.clock() + lifetime if lifetime is not None else None,
            refresh,
            scopes,
        )

    async def _exchange(
        self,
        guard: OAuthStoreGuard,
        previous: OAuthRecord | None,
        metadata: OAuthMetadata,
        budget: OperationBudget,
        *,
        pending: PendingState | None = None,
        callback: str | None = None,
        config: OAuthClientConfiguration | None = None,
    ) -> OAuthRecord:
        config = config or metadata.configuration
        old_token = previous.token if previous else None
        if (
            config.flow == "client_credentials"
            and old_token is not None
            and not set(config.required_scopes).issubset(old_token.scopes)
        ):
            old_token = None
        retained_token = previous.token if previous else None
        reserved = OAuthRecord(uuid4().hex, "refreshing", metadata, retained_token)
        await self._cas(guard, previous, reserved)
        try:
            async with self._client(metadata, budget, config) as client:
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
            token = self._token(
                response,
                metadata,
                old_token if pending is None else None,
                enforce_allowed=False,
            )
        except BaseException as error:
            definitive = isinstance(error, _ExchangeError) and error.code in (
                "invalid_grant",
                "invalid_client",
                "unauthorized_client",
                "access_denied",
                "invalid_scope",
            )
            # Ambiguity retains the refreshing record for host-budgeted retry;
            # it is not proof of lost authorization or safe external rollback.
            if definitive:
                with anyio.CancelScope(shield=True):
                    with anyio.fail_after(1):
                        retained = (
                            retained_token
                            if pending is not None or old_token is None
                            else None
                        )
                        await self._cas(
                            guard,
                            reserved,
                            OAuthRecord(
                                uuid4().hex,
                                "active" if retained else "rejected",
                                metadata,
                                retained,
                            ),
                        )
            if not isinstance(error, _ExchangeError):
                raise
            if config.flow == "client_credentials" and definitive:
                raise AuthenticationFailure(code="credential_unavailable") from None
            if error.code == "invalid_grant":
                raise AuthenticationFailure(
                    code="interaction_required" if pending else "refresh_rejected"
                ) from None
            if error.code in ("access_denied", "invalid_scope"):
                raise AuthenticationFailure(code="access_denied") from None
            if error.code in ("invalid_client", "unauthorized_client"):
                raise AuthenticationFailure(code="credential_unavailable") from None
            raise AuthenticationFailure(code="provider_failed") from None
        active = await self._commit_token(guard, reserved, token)
        allowed = (
            config.scopes if config.allowed_scopes is None else config.allowed_scopes
        )
        if not set(token.scopes).issubset(allowed):
            raise AuthenticationFailure(code="access_denied")
        return active

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
        owner = self._pending_owners.get(key)
        if (
            pending is None
            or owner is None
            or previous is None
            or owner[0] != previous.generation
            or owner[1].cancelled
            or pending.expires_at <= self.clock()
            or pending.metadata.configuration.redirect_uri
            != metadata.configuration.redirect_uri
            or pending.deadline < budget.deadline
            or pending.deadline <= anyio.current_time()
            or set(metadata.configuration.scopes)
            != set(pending.metadata.configuration.scopes)
            or set(metadata.configuration.required_scopes)
            != set(pending.metadata.configuration.required_scopes)
        ):
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
                metadata,
                state,
                verifier,
                url,
                self.clock() + min(config.login_lifetime, budget.remaining()),
                budget.deadline,
            )
            previous_record = OAuthRecord(
                uuid4().hex,
                "pending",
                metadata,
                token=previous.token if previous else None,
                pending=pending,
            )
            # Validate fallible host/browser policy before publishing the handle.
            await self.network.authorize(
                pending.authorization_url, "authorization", budget
            )
            try:
                await self._cas(guard, previous, previous_record)
            except BaseException:
                # A backend can commit then observe cancellation. Invalidate only
                # our unpublished generation, never resurrect an obsolete login.
                try:
                    with anyio.CancelScope(shield=True):
                        with anyio.fail_after(1):
                            current = await guard.load()
                            if (
                                current is not None
                                and current.generation == previous_record.generation
                            ):
                                retained = (
                                    OAuthRecord(
                                        uuid4().hex,
                                        "active",
                                        current.metadata,
                                        current.token,
                                    )
                                    if current.token
                                    else None
                                )
                                await self._cas(guard, current, retained)
                except BaseException:
                    pass
                raise
            self._pending_owners[key] = (previous_record.generation, budget)
            previous = previous_record
        else:
            await self.network.authorize(
                pending.authorization_url, "authorization", budget
            )
        if previous is None:
            raise AuthenticationFailure(code="provider_failed")
        return PendingLogin(
            key, previous.generation, pending.authorization_url, pending.expires_at
        )

    async def _prepare(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        challenge: AuthChallenge | None = None,
        rejected_generation: str | None = None,
        expected_key: StoreKey | None = None,
        *,
        interactive: bool = True,
        renew_metadata: bool = False,
    ) -> Ready | PendingLogin:
        from ._oauth_discovery import discover, validate_configuration, _challenge
        from ._oauth_types import binding_key

        self._check_target(target)
        binding = binding_key(target)
        cached = await self.store.load_binding(binding, budget)
        metadata = None if renew_metadata else cached
        loaded_from_cache = metadata is not None
        config = None
        retained_required = cached.configuration.required_scopes if cached else ()
        if metadata is not None:
            resource = await self.policy.resource(target, budget)
            _, required = _challenge(challenge)
            required = tuple(
                sorted(set(required) | set(metadata.configuration.required_scopes))
            )
            retained_required = required
            issuers = (
                (target.typed_binding.issuer,)
                if isinstance(target.typed_binding, OAuthBinding)
                else (metadata.configuration.issuer,)
            )
            config = await self.policy.select(
                target, resource, issuers, required, budget
            )
            validate_configuration(target, resource, (config.issuer,), required, config)
            candidate = replace(
                metadata,
                resource=resource,
                configuration=replace(config, client_secret=None),
            )
            if self._key(target, candidate) != self._key(target, metadata):
                metadata = None
                loaded_from_cache = False
            else:
                metadata = candidate
        if metadata is None:
            # An unbound first delivery stays anonymous; explicit prepare or a
            # validated challenge owns discovery/acquisition, never dispatch UI.
            metadata = await discover(
                target, challenge, self.network, self.policy, budget
            )
            config = await self.policy.select(
                target,
                metadata.resource,
                (metadata.configuration.issuer,),
                metadata.configuration.required_scopes,
                budget,
            )
            validate_configuration(
                target,
                metadata.resource,
                (metadata.configuration.issuer,),
                metadata.configuration.required_scopes,
                config,
            )
        assert config is not None
        _, required = _challenge(challenge)
        required = tuple(
            sorted(
                set(required)
                | set(retained_required)
                | set(config.required_scopes)
                | set(metadata.configuration.required_scopes)
            )
        )
        allowed = (
            config.scopes if config.allowed_scopes is None else config.allowed_scopes
        )
        if not set(required).issubset(allowed) or (
            challenge is not None and challenge.status == 403 and not required
        ):
            raise AuthenticationFailure(code="access_denied")
        # Scope step-up is binding-local. It never changes the grant key ceiling.
        config = replace(
            config,
            scopes=tuple(sorted(set(config.scopes) | set(required))),
            required_scopes=required,
        )
        metadata = replace(metadata, configuration=replace(config, client_secret=None))
        await self.store.save_binding(binding, metadata, budget)
        key = self._key(target, metadata)
        # Policy rotation can legitimately rebind; never reuse the old principal.
        if expected_key is not None and key != expected_key:
            rejected_generation = None
        if loaded_from_cache:
            # Discover refreshed endpoint/capability metadata only when renewal is
            # needed. Release exclusion first, then reload after discovery so
            # another provider's completed refresh wins over duplicate exchanges.
            async with self.store.coordinate(key, budget) as guard:
                existing = await guard.load()
                token = existing.token if existing else None
                adequate = (
                    token is not None
                    and set(required).issubset(token.scopes)
                    and set(token.scopes).issubset(allowed)
                )
                usable = (
                    existing is not None
                    and existing.status in ("active", "pending")
                    and token is not None
                    and adequate
                    and rejected_generation != existing.generation
                    and (
                        token.expires_at is None
                        or token.expires_at > self.clock() + self.expiry_skew
                    )
                )
                if usable:
                    assert existing is not None
                    return self._ready(target, key, existing)
                needs_exchange = config.flow == "client_credentials" or (
                    token is not None and bool(token.refresh_token) and adequate
                )
            if needs_exchange:
                return await self._prepare(
                    target,
                    budget,
                    challenge,
                    rejected_generation,
                    expected_key,
                    interactive=interactive,
                    renew_metadata=True,
                )
        async with self.store.coordinate(key, budget) as guard:
            record = await guard.load()
            if (
                record is not None
                and record.token is not None
                and record.status in ("active", "refreshing", "pending")
            ):
                token = record.token
                adequate = set(required).issubset(token.scopes) and set(
                    token.scopes
                ).issubset(allowed)
                valid = (
                    token.expires_at is None
                    or token.expires_at > self.clock() + self.expiry_skew
                )
                if (
                    record.status in ("active", "pending")
                    and rejected_generation != record.generation
                    and valid
                    and adequate
                ):
                    return self._ready(target, key, record)
                if (
                    token.refresh_token and adequate
                ) or config.flow == "client_credentials":
                    active = await self._exchange(
                        guard, record, metadata, budget, config=config
                    )
                    assert active.token is not None
                    if not set(required).issubset(active.token.scopes):
                        raise AuthenticationFailure(
                            code="interaction_required"
                            if config.flow == "authorization_code_pkce"
                            else "access_denied"
                        )
                    return self._ready(target, key, active)
            if config.flow == "client_credentials":
                active = await self._exchange(
                    guard, record, metadata, budget, config=config
                )
                assert active.token is not None
                if not set(required).issubset(active.token.scopes):
                    raise AuthenticationFailure(code="access_denied")
                return self._ready(target, key, active)
            if not interactive:
                raise AuthenticationFailure(code="interaction_required")
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
        from ._oauth_types import binding_key
        from ._oauth_discovery import validate_configuration

        self._check_target(target)
        metadata = await self.store.load_binding(binding_key(target), budget)
        if metadata is None:
            raise AuthenticationFailure(code="invalid_configuration")
        resource = await self.policy.resource(target, budget)
        selected = await self.policy.select(
            target,
            resource,
            (metadata.configuration.issuer,),
            metadata.configuration.required_scopes,
            budget,
        )
        validate_configuration(
            target,
            resource,
            (metadata.configuration.issuer,),
            metadata.configuration.required_scopes,
            selected,
        )
        requirements = tuple(
            sorted(
                set(metadata.configuration.required_scopes)
                | set(selected.required_scopes)
            )
        )
        selected = replace(selected, required_scopes=requirements)
        current = replace(
            metadata,
            resource=resource,
            configuration=replace(selected, client_secret=None),
        )
        if self._key(target, current) != login.key:
            raise AuthenticationFailure(code="access_denied")
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
            owner = self._pending_owners.get(login.key)
            if owner is None or owner[0] != login.generation or owner[1].cancelled:
                raise AuthenticationFailure(code="interaction_required")
            budget = OperationBudget(
                min(budget.deadline, owner[1].deadline),
                owner[1].cancel_scope or budget.cancel_scope,
            )
            with anyio.fail_after(budget.remaining()):
                pending, config = record.pending, record.metadata.configuration
                if selected.redirect_uri != config.redirect_uri:
                    raise AuthenticationFailure(code="interaction_required")
                # An omitted token-response scope inherits the actual consent request,
                # not a later mutable host request preference.
                exchange_metadata = replace(
                    current,
                    configuration=replace(
                        selected,
                        client_secret=None,
                        scopes=config.scopes,
                    ),
                )

                if (
                    pending.expires_at <= self.clock()
                    or pending.deadline <= anyio.current_time()
                ):
                    raise AuthenticationFailure(
                        code="interaction_required", recovery="login"
                    )
                if config.redirect_uri is None:
                    raise AuthenticationFailure(code="invalid_configuration")
                callback, redirect = (
                    urlsplit(callback_url),
                    urlsplit(config.redirect_uri),
                )
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
                        guard,
                        record,
                        OAuthRecord(
                            uuid4().hex,
                            "active" if record.token else "rejected",
                            record.metadata,
                            record.token,
                        ),
                    )
                    raise AuthenticationFailure(code="access_denied")
                if len(values.get("code", [])) != 1 or not values["code"][0]:
                    raise AuthenticationFailure(code="access_denied")
                # Revalidate local endpoint policy at completion, not only login prep.
                await self.network.authorize(callback_url, "authorization", budget)
                self._pending_owners.pop(login.key, None)
                active = await self._exchange(
                    guard,
                    record,
                    exchange_metadata,
                    budget,
                    pending=pending,
                    callback=callback_url,
                    config=selected,
                )
                assert active.token is not None
                if not set(current.configuration.required_scopes).issubset(
                    active.token.scopes
                ):
                    raise AuthenticationFailure(code="interaction_required")
                return self._ready(target, login.key, active)

    async def complete(
        self,
        target: AuthTarget,
        login: PendingLogin,
        callback_url: str,
        budget: OperationBudget,
    ) -> Ready:
        await anyio.lowlevel.checkpoint_if_cancelled()
        # This immutable snapshot can only shorten the budget or reject; the
        # generation and owner are rechecked under the store guard before use.
        owner = self._pending_owners.get(login.key)
        if owner is None or owner[0] != login.generation:
            raise AuthenticationFailure(code="interaction_required")
        if owner[1].cancelled:
            raise OperationCancelledError("Authentication operation cancelled")
        budget = OperationBudget(
            min(budget.deadline, owner[1].deadline),
            owner[1].cancel_scope or budget.cancel_scope,
        )
        # Bound local policy/coordination too, before the guarded pending reload.
        budget = OperationBudget(
            min(
                budget.deadline,
                anyio.current_time() + max(0, login.expires_at - self.clock()),
            ),
            budget.cancel_scope,
        )
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
                from ._oauth_types import binding_key

                metadata = await self.store.load_binding(binding_key(target), budget)
                if metadata is None:
                    return
                key = self._key(target, metadata)
            async with self.store.coordinate(key, budget) as guard:
                record = await guard.load()
                if record is not None and self._key(target, record.metadata) != key:
                    raise AuthenticationFailure(code="invalid_configuration")
                await self._cas(guard, record, None)
                self._pending_owners.pop(key, None)

        await self._run(reset_record, budget)

    async def cancel(
        self,
        target: AuthTarget,
        login: PendingLogin,
        budget: OperationBudget,
    ) -> None:
        """Cancel only this pending generation; never erase an active grant."""

        async def cancel_pending() -> None:
            self._check_target(target)
            async with self.store.coordinate(login.key, budget) as guard:
                record = await guard.load()
                if record is None or record.generation != login.generation:
                    return
                if self._key(target, record.metadata) != login.key:
                    raise AuthenticationFailure(code="invalid_configuration")
                if record.status == "pending":
                    retained = (
                        OAuthRecord(
                            uuid4().hex, "active", record.metadata, record.token
                        )
                        if record.token
                        else None
                    )
                    await self._cas(guard, record, retained)
                    self._pending_owners.pop(login.key, None)

        await self._run(cancel_pending, budget)

    def _budget(self) -> OperationBudget:
        return OperationBudget.after(self.operation_timeout)

    async def credential(self, context: AuthContext) -> BearerCredential | None:
        from ._oauth_types import binding_key

        target = normalize_auth_target(context, namespace=self.namespace)
        budget = self._budget()
        if context.binding is None:
            cached = await self._run(
                lambda: self.store.load_binding(binding_key(target), budget), budget
            )
            if cached is None:
                return None
        result = await self._run(
            lambda: self._prepare(target, budget, interactive=False),
            budget,
        )
        assert isinstance(result, Ready)
        return result.credential

    async def challenge(
        self,
        context: AuthContext,
        challenge: AuthChallenge,
    ) -> BearerCredential | None:
        from ._oauth_discovery import _challenge

        target = normalize_auth_target(context, namespace=self.namespace)
        attempt = challenge.attempted_identity
        if attempt is not None and (
            not isinstance(attempt, _Attempt)
            or attempt.target_identity != target.identity
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        if challenge.status == 403:
            _challenge(challenge)
        elif challenge.status != 401:
            return None
        budget = self._budget()
        result = await self._run(
            lambda: self._prepare(
                target,
                budget,
                challenge,
                attempt.generation if isinstance(attempt, _Attempt) else None,
                attempt.key if isinstance(attempt, _Attempt) else None,
                interactive=False,
            ),
            budget,
        )
        assert isinstance(result, Ready)
        return result.credential if challenge.retry_allowed else None
