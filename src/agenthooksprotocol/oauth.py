"""Optional, host-controlled managed OAuth. Importing is dependency-light.

Install agenthooksprotocol[oauth] (HTTPX) to perform exchanges. No browsers,
listeners, workers, HTTP clients, or token stores are created outside a bounded
operation.
"""

from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
import hashlib
import json
import math
import re
import secrets
import time
from typing import TypeVar
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit
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
    binding_key,
    grant_key,
)

T = TypeVar("T")

_DEFINITIVE = (
    "invalid_grant",
    "invalid_client",
    "unauthorized_client",
    "access_denied",
    "invalid_scope",
)
_SCOPE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")


_MAX_LIFETIME = 2**31  # About 68 years; longer lifetimes are clamped.


def _clamped_int(digits: str) -> int:
    """Parse an integer string, clamping magnitudes beyond the lifetime cap."""
    magnitude = digits.lstrip("+-").lstrip("0")
    if len(magnitude) > 12:
        return -_MAX_LIFETIME if digits.startswith("-") else _MAX_LIFETIME
    return int(digits)


class _StaleMetadata(AuthenticationFailure):
    """The token endpoint provably did not process the request (DNS/connect/
    TLS failure or 404/410); persisted metadata may be stale."""

    def __init__(self) -> None:
        super().__init__(code="discovery_failed")


class _ExchangeError(Exception):
    """A definitive OAuth error code, "transient" or "invalid" (bad response).

    `refresh_token` keeps a valid rotated refresh token from an invalid response.
    """

    def __init__(self, code: str, refresh_token: str | None = None) -> None:
        self.code, self.refresh_token = code, refresh_token


def _authorization_url(
    metadata: OAuthMetadata,
    config: OAuthClientConfiguration,
    scopes: tuple[str, ...],
    state: str,
    verifier: str,
) -> str:
    assert metadata.authorization_endpoint is not None
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri or "",
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge.rstrip(b"=").decode(),
        "code_challenge_method": "S256",
        "resource": metadata.resource,
    }
    if not scopes:
        del params["scope"]
    parts = urlsplit(metadata.authorization_endpoint)
    query = "&".join(filter(None, (parts.query, urlencode(params))))
    return urlunsplit(parts._replace(query=query))


async def _token_endpoint(
    network: OAuthNetwork,
    metadata: OAuthMetadata,
    config: OAuthClientConfiguration,
    form: dict[str, str],
    budget: OperationBudget,
) -> Mapping[str, object]:
    """One RFC 6749 token request with RFC 8707 resource and client auth."""
    import httpx
    from ._oauth_discovery import safe_request

    form = {**form, "resource": metadata.resource}
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    if config.token_endpoint_auth_method == "client_secret_basic":
        # RFC 6749 section 2.3.1: form-encode each part before Basic encoding.
        pair = ":".join(
            quote(v, safe="") for v in (config.client_id, config.client_secret or "")
        )
        headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
    else:
        form["client_id"] = config.client_id
        if config.token_endpoint_auth_method == "client_secret_post":
            form["client_secret"] = config.client_secret or ""
    request = httpx.Request(
        "POST", metadata.token_endpoint, headers=headers, content=urlencode(form)
    )
    response = await safe_request(network, request, "token", budget)
    try:
        # Clamp long integers so a huge expires_in cannot hit the int limit.
        data = json.loads(response.content, parse_int=_clamped_int)
    except ValueError:
        data = None
    if response.status_code >= 500:
        raise _ExchangeError("transient")
    if response.status_code in (404, 410) and not (
        isinstance(data, dict) and "error" in data
    ):
        # The endpoint did not process the request: it may have moved.
        raise _ExchangeError("stale")
    if not isinstance(data, dict):
        kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if 200 <= response.status_code < 300 and kind in (
            "application/x-www-form-urlencoded",
            "text/plain",
        ):
            # A form-encoded success body is invalid, but a valid rotated
            # refresh token in it must still be kept.
            try:
                values = parse_qs(response.content.decode("ascii"), strict_parsing=True)
            except (UnicodeDecodeError, ValueError):
                values = {}
            rotated = values.get("refresh_token", [])
            valid = len(rotated) == 1 and re.fullmatch(r"[\x20-\x7e]+", rotated[0])
            raise _ExchangeError("invalid", rotated[0] if valid else None)
        raise _ExchangeError("transient")
    error = data.get("error")
    if error is not None or not 200 <= response.status_code < 300:
        raise _ExchangeError(error if error in _DEFINITIVE else "transient")
    if response.status_code != 200:
        # RFC 6749 section 5.1 success is 200: any other 2xx is an invalid
        # response that still keeps a valid rotated refresh token.
        refresh = data.get("refresh_token")
        raise _ExchangeError(
            "invalid", refresh if isinstance(refresh, str) and refresh else None
        )
    return data


@dataclass(frozen=True)
class _Attempt:
    key: StoreKey = field(repr=False)
    generation: str = field(repr=False)
    target_identity: tuple[object, ...] = field(repr=False)


class ManagedOAuthProvider:
    """OAuth with mandatory host trust/network/store boundaries.

    The store owns coordination across all providers/processes sharing a key,
    including pending logins: any process sharing the store can complete one.
    Binding metadata and local policy are resolved outside the grant lock.
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
        commit_timeout: float = 30,
    ) -> None:
        if (
            not namespace
            or not math.isfinite(operation_timeout)
            or operation_timeout <= 0
            or not math.isfinite(expiry_skew)
            or expiry_skew < 0
            or not math.isfinite(commit_timeout)
            or commit_timeout <= 0
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        self.network, self.policy, self.store = network, policy, store
        self.namespace, self.operation_timeout = namespace, operation_timeout
        self.expiry_skew, self.clock = expiry_skew, clock
        # Bounds the post-exchange store commit, shielded from cancellation.
        self.commit_timeout = commit_timeout

    async def _run(
        self, operation: Callable[[], Awaitable[T]], budget: OperationBudget
    ) -> T:
        """The single error boundary: only safe codes, never exception chains."""
        failure: AuthErrorCode = "provider_failed"
        recovery: AuthRecovery | None = None
        scopes: tuple[str, ...] = ()
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
            scopes = error.required_scopes
        except ImportError:
            failure = "unsupported_binding"
        except Exception:
            pass
        # Outside the handler: no secret-bearing __cause__ or __context__.
        if timed_out:
            raise TimeoutError("Authentication operation timed out")
        if cancelled:
            raise OperationCancelledError("Authentication operation cancelled")
        raise AuthenticationFailure(
            code=failure, recovery=recovery, required_scopes=scopes
        )

    def _check_target(self, target: AuthTarget) -> None:
        if (
            target.namespace != self.namespace
            or target.kind == "bearer"
            or not isinstance(target.backend_id, str)
            or not target.backend_id
            or target.purpose not in ("event", "upload")
        ):
            raise AuthenticationFailure(code="invalid_configuration")

    def _ready(self, target: AuthTarget, key: StoreKey, record: OAuthRecord) -> Ready:
        if record.token is None or record.token.access_token is None:
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

    @staticmethod
    def _settled(
        metadata: OAuthMetadata,
        token: StoredToken | None,
        pending: PendingState | None,
    ) -> OAuthRecord | None:
        """A settled (never in-flight) record, or None when nothing remains."""
        if token is None and pending is None:
            return None
        if pending is not None:
            return OAuthRecord(uuid4().hex, "pending", metadata, token, pending)
        return OAuthRecord(uuid4().hex, "active", metadata, token)

    def _token(
        self,
        response: Mapping[str, object],
        requested: tuple[str, ...],
        ceiling: tuple[str, ...],
        previous: StoredToken | None,
    ) -> StoredToken:
        """Validate a token response; `previous` is set only for a refresh.

        Initial: granted = response scopes ∩ acquisition ceiling. Refresh:
        granted = response scopes ∩ previous grant (never the current ceiling,
        which only filters at use).
        Extra scopes are ignored. An invalid response is never dispatched.
        """
        value, kind = response.get("access_token"), response.get("token_type")
        lifetime, scope = response.get("expires_in"), response.get("scope")
        refresh = response.get("refresh_token")
        # A positive JSON integer or ASCII-digit string; never fractional.
        # Huge values are clamped rather than overflowing.
        seconds = (
            lifetime
            if isinstance(lifetime, int) and not isinstance(lifetime, bool)
            else _clamped_int(lifetime)
            if isinstance(lifetime, str) and lifetime.isascii() and lifetime.isdigit()
            else None
        )
        if seconds is not None:
            seconds = min(seconds, _MAX_LIFETIME) if seconds > 0 else None
        valid_refresh = refresh if isinstance(refresh, str) and refresh else None
        valid = (
            isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9\-._~+/]+=*", value) is not None
            and isinstance(kind, str)
            and kind.lower() == "bearer"
            and (refresh is None or valid_refresh is not None)
            and ("expires_in" not in response or seconds is not None)
            and (
                "scope" not in response
                or (
                    isinstance(scope, str)
                    and all(_SCOPE.fullmatch(item) for item in scope.split(" "))
                )
            )
        )
        if not valid:
            raise _ExchangeError("invalid", valid_refresh)
        assert isinstance(value, str)
        if isinstance(scope, str):
            granted = set(scope.split(" "))
        else:
            granted = set(previous.scopes if previous is not None else requested)
        granted &= set(previous.scopes if previous is not None else ceiling)
        return StoredToken(
            value,
            self.clock() + seconds if seconds is not None else None,
            valid_refresh or (previous.refresh_token if previous else None),
            tuple(sorted(granted)),
        )

    async def _exchange(
        self,
        guard: OAuthStoreGuard,
        record: OAuthRecord | None,
        metadata: OAuthMetadata,
        config: OAuthClientConfiguration,
        budget: OperationBudget,
        form: dict[str, str],
        requested: tuple[str, ...],
        *,
        previous: StoredToken | None = None,
        retained: StoredToken | None = None,
        code: bool = False,
        ceiling: tuple[str, ...] | None = None,
    ) -> OAuthRecord:
        """Spend one code, refresh token or client credential under the guard.

        The in-flight reservation is always replaced: by the new token, by
        `retained` plus any valid rotated refresh token, or (refresh
        `invalid_grant`) by dropping both tokens. A pending login survives
        unless this exchange consumes it.
        """
        pending = None if code or record is None else record.pending
        reserved = OAuthRecord(uuid4().hex, "refreshing", metadata, retained, pending)
        await self._cas(guard, record, reserved)
        token: StoredToken | None = None
        outcome: BaseException | None = None
        try:
            response = await _token_endpoint(
                self.network, metadata, config, form, budget
            )
            token = self._token(
                response,
                requested,
                config.ceiling if ceiling is None else ceiling,
                previous,
            )
        except BaseException as error:
            outcome = error
        final = token if token is not None else retained
        if isinstance(outcome, _ExchangeError):
            if outcome.code == "invalid_grant" and previous is not None:
                final = None
            elif outcome.refresh_token is not None and previous is not None:
                final = StoredToken(None, None, outcome.refresh_token, previous.scopes)
        settled = self._settled(metadata, final, pending)
        committed = False
        try:
            # Rotation may already have occurred externally: finish one bounded
            # commit before honoring cancellation.
            with anyio.CancelScope(shield=True), anyio.fail_after(self.commit_timeout):
                committed = await guard.compare_and_swap(reserved.generation, settled)
        except Exception:
            if outcome is None:
                raise
        await anyio.lowlevel.checkpoint()
        from ._oauth_discovery import NotSent

        if isinstance(outcome, NotSent) or (
            isinstance(outcome, _ExchangeError) and outcome.code == "stale"
        ):
            raise _StaleMetadata()
        if (
            isinstance(outcome, AuthenticationFailure)
            and outcome.code == "discovery_failed"
        ):
            # Ambiguous post-send failure (read timeout/reset, redirect): the
            # refresh token may be spent, so never retry or refetch here.
            raise AuthenticationFailure(code="provider_failed")
        if outcome is not None and not isinstance(outcome, _ExchangeError):
            raise outcome
        if isinstance(outcome, _ExchangeError):
            if not committed:
                # A newer record replaced ours: it is kept, never wiped.
                raise AuthenticationFailure(code="provider_failed")
            if outcome.code == "invalid_grant":
                raise AuthenticationFailure(
                    code="interaction_required"
                    if code
                    else "credential_unavailable"
                    if previous is None
                    else "refresh_rejected"
                    if config.flow == "authorization_code_pkce"
                    else "provider_failed"
                )
            if outcome.code in ("access_denied", "invalid_scope"):
                raise AuthenticationFailure(code="access_denied")
            if outcome.code in ("invalid_client", "unauthorized_client"):
                raise AuthenticationFailure(code="credential_unavailable")
            raise AuthenticationFailure(code="provider_failed")
        if not committed or settled is None:
            raise AuthenticationFailure(code="provider_failed")
        return settled

    async def _pending(
        self,
        guard: OAuthStoreGuard,
        record: OAuthRecord | None,
        metadata: OAuthMetadata,
        config: OAuthClientConfiguration,
        required: tuple[str, ...],
        key: StoreKey,
        budget: OperationBudget,
    ) -> PendingLogin:
        """Reuse a covering unexpired pending login, or atomically supersede it.

        Reuse needs only requested ∪ required ⊆ pending scopes (effective
        scopes are filtered by each caller's ceiling at use). A superseding
        login requests old pending ∪ previous grant ∪ ((requested ∪ required)
        ∩ ceiling) and stores the union of the old and new ceilings; with a
        different redirect it uses only the new caller's scopes and ceiling.
        """
        wanted = set(config.scopes) | set(required)
        pending = record.pending if record is not None else None
        if (
            pending is not None
            and pending.metadata.configuration.redirect_uri != config.redirect_uri
        ):
            pending = None  # Merge only for the same grant key and redirect.
        previous = set(pending.metadata.configuration.scopes) if pending else set()
        granted = set(record.token.scopes) if record and record.token else set()
        if (
            pending is not None
            and pending.expires_at > self.clock()
            and pending.metadata.configuration.redirect_uri == config.redirect_uri
            and wanted <= previous
        ):
            return PendingLogin(
                key, pending.state, pending.authorization_url, pending.expires_at
            )
        # Step-up keeps the previous grant; old pending scopes and ceilings
        # only grow, so alternating callers converge.
        scopes = tuple(sorted(previous | granted | (wanted & set(config.ceiling))))
        ceiling = set(config.ceiling) | set(scopes)
        if pending is not None:
            ceiling |= set(pending.metadata.configuration.ceiling)
        if (
            config.flow != "authorization_code_pkce"
            or not metadata.authorization_endpoint
            or not config.redirect_uri
        ):
            raise AuthenticationFailure(code="unsupported_binding")
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        url = _authorization_url(metadata, config, scopes, state, verifier)
        # Validate fallible host/browser policy before publishing the handle.
        await self.network.authorize(url, "authorization", budget)
        pending = PendingState(
            replace(
                metadata,
                configuration=replace(
                    metadata.configuration,
                    scopes=scopes,
                    # The acquisition ceiling bounds the completed grant.
                    allowed_scopes=tuple(sorted(ceiling)),
                ),
            ),
            state,
            verifier,
            url,
            self.clock() + config.login_lifetime,
        )
        token = record.token if record is not None else None
        await self._cas(guard, record, self._settled(metadata, token, pending))
        return PendingLogin(key, state, url, pending.expires_at)

    async def _acquire(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        challenge: AuthChallenge | None = None,
        rejected: str | None = None,
        *,
        interactive: bool,
        lookup: bool = False,
        explicit: tuple[str, ...] = (),
    ) -> Ready | PendingLogin | None:
        """Serve, refresh, reissue or (interactive only) start a login.

        Full discovery runs only on a cache miss, a rebind, a host `prepare`
        or challenge handling. `lookup` (unbound up-front lookup) never runs
        protected-resource discovery or starts a login: it serves, refreshes
        or re-acquires with persisted metadata, fails like any operation when
        the binding is known, and returns None (anonymous) only on a store
        miss or host policy refusal.
        `explicit` holds host-supplied required scopes (step-up round trip).
        """
        from ._oauth_discovery import (
            challenge_requirements,
            discover,
            issuer_metadata,
            validate_configuration,
        )

        self._check_target(target)
        binding = binding_key(target)
        _, challenged = challenge_requirements(challenge)
        challenged = tuple(sorted(set(challenged) | set(explicit)))
        cached = await self.store.load_binding(binding, budget)
        renew, refetched = False, False
        while True:
            metadata = None if renew else cached
            if metadata is not None:
                issuers = (
                    (target.typed_binding.issuer,)
                    if isinstance(target.typed_binding, OAuthBinding)
                    else (metadata.configuration.issuer,)
                )
                candidate: OAuthMetadata | None = None
                try:
                    resource = await self.policy.resource(target, budget)
                    config = await self.policy.select(
                        target, resource, issuers, challenged, budget
                    )
                except AuthenticationFailure:
                    if lookup:
                        return None  # Host policy refusal: anonymous attempt.
                else:
                    try:
                        validate_configuration(
                            target, resource, issuers, challenged, config
                        )
                        candidate = replace(
                            metadata, resource=resource, configuration=config
                        )
                    except AuthenticationFailure:
                        if lookup:
                            raise
                # A failed cached check or a changed principal (issuer, client,
                # flow or partition) rediscovers and repairs the binding; the
                # lookup cannot discover, so it fails instead of going
                # anonymous. Never reuse the old principal.
                if candidate is not None and grant_key(target, candidate) != grant_key(
                    target, metadata
                ):
                    if lookup:
                        raise AuthenticationFailure(code="discovery_failed")
                    candidate = None
                metadata = candidate
                if metadata is not None and not metadata.token_endpoint:
                    # Missing persisted authorization-server metadata: fetch
                    # the stored issuer's only, never protected-resource data.
                    try:
                        metadata = await issuer_metadata(
                            resource, config, self.network, budget
                        )
                    except AuthenticationFailure:
                        if lookup:
                            raise
                        metadata = None  # Issuer gone: full discovery repairs.
            discovered = metadata is None
            if metadata is None:
                if lookup:
                    return None
                metadata = await discover(
                    target, challenge, self.network, self.policy, budget
                )
            config = metadata.configuration
            # Secrets are operation-local and never enter persisted metadata.
            stored = replace(
                metadata, configuration=replace(config, client_secret=None)
            )
            if stored != cached:
                await self.store.save_binding(binding, stored, budget)
                cached = stored
            # A challenge requirement applies to this operation only.
            required = tuple(sorted(set(challenged) | set(config.required_scopes)))
            if not set(required) <= set(config.ceiling) or (
                challenge is not None and challenge.status == 403 and not required
            ):
                raise AuthenticationFailure(
                    code="access_denied", required_scopes=required
                )
            key = grant_key(target, stored)
            try:
                async with self.store.coordinate(key, budget) as guard:
                    record = await guard.load()
                    token = record.token if record is not None else None
                    adequate = token is not None and set(required) <= (
                        set(token.scopes) & set(config.ceiling)
                    )
                    stale = record is not None and record.generation == rejected
                    if (
                        stale
                        and record is not None
                        and token is not None
                        and token.access_token is not None
                        and challenge is not None
                        and challenge.status == 401
                    ):
                        # Persist the rejection before any renewal that can
                        # fail, so a revoked token is never resent.
                        token = replace(token, access_token=None)
                        marked = replace(record, generation=uuid4().hex, token=token)
                        await self._cas(guard, record, marked)
                        record = marked
                    if (
                        token is not None
                        and adequate
                        and not stale
                        and token.access_token is not None
                        and (
                            token.expires_at is None
                            or token.expires_at > self.clock() + self.expiry_skew
                        )
                    ):
                        assert record is not None
                        return self._ready(target, key, record)
                    refresh = (
                        token.refresh_token if token is not None and adequate else None
                    )
                    if config.flow == "client_credentials" or refresh:
                        if not discovered and (interactive or challenge is not None):
                            # Renew endpoint metadata outside the lock, then reload.
                            renew = True
                            continue
                        # Re-acquisition keeps the previous grant (step-up).
                        granted = set(token.scopes) if token is not None else set()
                        requested = tuple(
                            sorted(granted | set(config.scopes) | set(required))
                        )
                        form = (
                            {"grant_type": "refresh_token", "refresh_token": refresh}
                            if refresh
                            else {
                                "grant_type": "client_credentials",
                                "scope": " ".join(requested),
                            }
                        )
                        if not requested:
                            form.pop("scope", None)
                        active = await self._exchange(
                            guard,
                            record,
                            stored,
                            config,
                            budget,
                            form,
                            requested,
                            previous=token if refresh else None,
                            retained=token,
                            ceiling=tuple(sorted(granted | set(config.ceiling))),
                        )
                        assert active.token is not None
                        if not set(required) <= set(active.token.scopes) & set(
                            config.ceiling
                        ):
                            raise AuthenticationFailure(
                                code="access_denied", required_scopes=required
                            )
                        return self._ready(target, key, active)
                    if not interactive:
                        raise AuthenticationFailure(
                            code="interaction_required", required_scopes=required
                        )
                    if not discovered:
                        # A login rebuilds binding metadata first.
                        renew = True
                        continue
                    return await self._pending(
                        guard, record, stored, config, required, key, budget
                    )
            except _StaleMetadata:
                if discovered or refetched:
                    raise
            # Persisted issuer metadata looks stale: refetch the stored
            # issuer's metadata once (never protected-resource discovery),
            # persist it when the issuer is unchanged, and retry once.
            refetched = True
            cached = await issuer_metadata(
                stored.resource, config, self.network, budget
            )

    async def prepare(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        *,
        challenge: AuthChallenge | None = None,
        required_scopes: tuple[str, ...] = (),
    ) -> Ready | PendingLogin:
        """Host-driven acquisition; the only path that creates pending logins.

        Pass a failure's `required_scopes` back here to request step-up consent.
        """

        async def run() -> Ready | PendingLogin:
            result = await self._acquire(
                target,
                budget,
                challenge,
                interactive=True,
                explicit=tuple(required_scopes),
            )
            assert result is not None
            return result

        return await self._run(run, budget)

    async def _complete(
        self,
        target: AuthTarget,
        login: PendingLogin,
        callback_url: str,
        budget: OperationBudget,
    ) -> Ready:
        from ._oauth_discovery import validate_configuration

        self._check_target(target)
        metadata = await self.store.load_binding(binding_key(target), budget)
        if metadata is None:
            raise AuthenticationFailure(code="interaction_required")
        resource = await self.policy.resource(target, budget)
        issuers = (metadata.configuration.issuer,)
        config = await self.policy.select(target, resource, issuers, (), budget)
        validate_configuration(target, resource, issuers, (), config)
        stored = replace(
            metadata,
            resource=resource,
            configuration=replace(config, client_secret=None),
        )
        if grant_key(target, stored) != login.key:
            raise AuthenticationFailure(code="access_denied")
        async with self.store.coordinate(login.key, budget) as guard:
            record = await guard.load()
            pending = record.pending if record is not None else None
            if (
                record is None
                or pending is None
                or pending.state != login.generation
                or pending.expires_at <= self.clock()
            ):
                raise AuthenticationFailure(code="interaction_required")
            requested = pending.metadata.configuration
            if (
                config.redirect_uri != requested.redirect_uri
                or not requested.redirect_uri
            ):
                raise AuthenticationFailure(code="interaction_required")
            # Validate redirect, state and issuer before consuming the login.
            callback, redirect = (
                urlsplit(callback_url),
                urlsplit(requested.redirect_uri),
            )
            values = parse_qs(callback.query, keep_blank_values=True)
            fixed = parse_qs(redirect.query, keep_blank_values=True)
            issuer = values.get("iss")
            if (
                callback.fragment
                or callback.username is not None
                or callback.password is not None
                or (callback.scheme, callback.netloc, callback.path)
                != (redirect.scheme, redirect.netloc, redirect.path)
                or any(values.get(name) != value for name, value in fixed.items())
                or values.get("state") != [pending.state]
                or (issuer is not None and issuer != [requested.issuer])
                or (pending.metadata.require_response_issuer and issuer is None)
            ):
                raise AuthenticationFailure(code="access_denied")
            if "error" in values:
                # Valid consent denial consumes the login, never the stored grant.
                await self._cas(
                    guard,
                    record,
                    self._settled(record.metadata, record.token, None),
                )
                raise AuthenticationFailure(code="access_denied")
            codes = values.get("code", [])
            if len(codes) != 1 or not codes[0]:
                raise AuthenticationFailure(code="access_denied")
            await self.network.authorize(callback_url, "authorization", budget)
            form = {
                "grant_type": "authorization_code",
                "code": codes[0],
                "redirect_uri": requested.redirect_uri,
                "code_verifier": pending.verifier,
            }
            active = await self._exchange(
                guard,
                record,
                stored,
                config,
                budget,
                form,
                requested.scopes,
                # granted = response ∩ (previous grant ∪ acquisition ceiling).
                ceiling=tuple(
                    sorted(
                        set(requested.ceiling)
                        | set(record.token.scopes if record.token else ())
                    )
                ),
                retained=record.token,
                code=True,
            )
            assert active.token is not None
            effective = set(active.token.scopes) & set(config.ceiling)
            if not set(config.required_scopes) <= effective:
                raise AuthenticationFailure(
                    code="access_denied", required_scopes=config.required_scopes
                )
            return self._ready(target, login.key, active)

    async def complete(
        self,
        target: AuthTarget,
        login: PendingLogin,
        callback_url: str,
        budget: OperationBudget,
    ) -> Ready:
        """Complete a stored pending login from any process sharing the store."""
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
                metadata = await self.store.load_binding(binding_key(target), budget)
                if metadata is None:
                    return
                key = grant_key(target, metadata)
            async with self.store.coordinate(key, budget) as guard:
                record = await guard.load()
                if record is not None and grant_key(target, record.metadata) != key:
                    raise AuthenticationFailure(code="invalid_configuration")
                await self._cas(guard, record, None)

        await self._run(reset_record, budget)

    async def cancel(
        self,
        target: AuthTarget,
        login: PendingLogin,
        budget: OperationBudget,
    ) -> None:
        """Cancel only this pending login; never erase a stored grant."""

        async def cancel_pending() -> None:
            self._check_target(target)
            async with self.store.coordinate(login.key, budget) as guard:
                record = await guard.load()
                if (
                    record is None
                    or record.pending is None
                    or record.pending.state != login.generation
                ):
                    return
                if grant_key(target, record.metadata) != login.key:
                    raise AuthenticationFailure(code="invalid_configuration")
                await self._cas(
                    guard,
                    record,
                    self._settled(record.metadata, record.token, None),
                )

        await self._run(cancel_pending, budget)

    def _budget(self) -> OperationBudget:
        return OperationBudget.after(self.operation_timeout)

    async def credential(self, context: AuthContext) -> BearerCredential | None:
        target = normalize_auth_target(context, namespace=self.namespace)
        budget = self._budget()
        if context.binding is None:
            # Up-front lookup for an unbound destination: never discovery or login.
            found = await self._run(
                lambda: self._acquire(target, budget, interactive=False, lookup=True),
                budget,
            )
            return found.credential if isinstance(found, Ready) else None
        result = await self._run(
            lambda: self._acquire(target, budget, interactive=False), budget
        )
        assert isinstance(result, Ready)
        return result.credential

    async def challenge(
        self,
        context: AuthContext,
        challenge: AuthChallenge,
    ) -> BearerCredential | None:
        target = normalize_auth_target(context, namespace=self.namespace)
        attempt = challenge.attempted_identity
        if attempt is not None and (
            not isinstance(attempt, _Attempt)
            or attempt.target_identity != target.identity
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        if challenge.status not in (401, 403):
            return None
        budget = self._budget()
        result = await self._run(
            lambda: self._acquire(
                target,
                budget,
                challenge,
                attempt.generation if isinstance(attempt, _Attempt) else None,
                interactive=False,
            ),
            budget,
        )
        assert isinstance(result, Ready)
        return result.credential if challenge.retry_allowed else None
