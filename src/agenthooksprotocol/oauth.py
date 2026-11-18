"""Optional, host-controlled managed OAuth. Importing is dependency-light.

Install agenthooksprotocol[oauth] (HTTPX) to perform exchanges. No browsers,
listeners, workers, HTTP clients, or token stores are created outside a bounded
operation; only a proactive client-credentials re-registration runs detached,
bounded by `commit_timeout`.
"""

from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
import hashlib
import json
import logging
import math
import re
import secrets
import time
from typing import Literal, TypeVar
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
    OAuthClientMetadataDocument as OAuthClientMetadataDocument,
    OAuthDynamicRegistration as OAuthDynamicRegistration,
    OAuthRegistration as OAuthRegistration,
    OAuthSecretStore as OAuthSecretStore,
    StoredRecord as StoredRecord,
    TokenEndpointAuthMethod,
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
    registration_key,
)
from ._oauth_registration import (
    SECRET_METHODS,
    Issued,
    RegistrationFailed,
    accept_registration,
    parse_retry_after,
    registration_request,
    request_digest,
    valid_document_url,
)

T = TypeVar("T")
_log = logging.getLogger(__name__)

_DEFINITIVE = (
    "invalid_grant",
    "invalid_client",
    "unauthorized_client",
    "access_denied",
    "invalid_scope",
)
_SCOPE = r"[\x21\x23-\x5b\x5d-\x7e]+"
_SCOPE_LIST = re.compile(rf"{_SCOPE}(?: {_SCOPE})*")


def _endpoint(url: str) -> str:
    """Compare event endpoints as HTTP requests address them."""
    import httpx

    try:
        return str(httpx.URL(url))
    except (httpx.InvalidURL, TypeError):
        return url


def _response_scopes(scope: object) -> tuple[str, ...] | None | Literal[False]:
    """A token-response `scope`: its tokens, None when omitted, False if malformed.

    Absent, JSON null and blank strings (only SP/HTAB/CR/LF) are treated as
    omitted. Any other string must be an RFC 6749 scope list with single-SP
    separators; any other JSON type is malformed.
    """
    if scope is None or (isinstance(scope, str) and not scope.strip(" \t\r\n")):
        return None
    if not isinstance(scope, str) or _SCOPE_LIST.fullmatch(scope) is None:
        return False
    return tuple(scope.split(" "))


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


class _InvalidClient(AuthenticationFailure):
    """The token endpoint rejected the client itself (`invalid_client`)."""

    def __init__(self) -> None:
        super().__init__(code="credential_unavailable")


@dataclass(frozen=True)
class _Client:
    """The selected client for one operation.

    `blocked` is set when no usable registration exists and none may be made
    now: a stored token still works, but no token request is sent.
    """

    blocked: AuthErrorCode | None = None
    generation: str | None = None
    # Proactive client-credentials renewal, run detached after the operation.
    renewal: Callable[[], Awaitable[object]] | None = field(
        default=None, compare=False, repr=False
    )


def _persisted(config: OAuthClientConfiguration) -> OAuthClientConfiguration:
    """Binding metadata never holds secrets or host registration policy."""
    return replace(
        config,
        client_secret=None,
        client_metadata_document=None,
        dynamic_registration=None,
    )


def _keep_selection(fresh: OAuthMetadata, recorded: OAuthMetadata) -> OAuthMetadata:
    """Refetched issuer metadata keeps the recorded client selection."""
    return replace(
        fresh,
        client_source=recorded.client_source,
        registration_key=recorded.registration_key,
    )


def _grant_record(record: StoredRecord | None) -> OAuthRecord | None:
    if record is not None and not isinstance(record, OAuthRecord):
        raise AuthenticationFailure(code="provider_failed")
    return record


def _registration_record(record: StoredRecord | None) -> OAuthRegistration | None:
    if record is not None and not isinstance(record, OAuthRegistration):
        raise AuthenticationFailure(code="provider_failed")
    return record


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
    trace: Callable[[str, object], Awaitable[None]] | None = None,
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
        "POST",
        metadata.token_endpoint,
        headers=headers,
        content=urlencode(form),
        # HTTPX reports when the request bytes are written (httpcore trace).
        extensions={"trace": trace} if trace is not None else None,
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
        secret_store: OAuthSecretStore | None = None,
        registration_backoff: float = 60,
        registration_backoff_max: float = 3600,
        retry_after_max: float = 3600,
        renewal_margin_max: float = 3600,
    ) -> None:
        if (
            not namespace
            or not math.isfinite(operation_timeout)
            or operation_timeout <= 0
            or not math.isfinite(expiry_skew)
            or expiry_skew < 0
            or not math.isfinite(commit_timeout)
            or commit_timeout <= 0
            or not all(
                math.isfinite(value) and value >= 0
                for value in (
                    registration_backoff,
                    registration_backoff_max,
                    retry_after_max,
                    renewal_margin_max,
                )
            )
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        self.network, self.policy, self.store = network, policy, store
        self.namespace, self.operation_timeout = namespace, operation_timeout
        self.expiry_skew, self.clock = expiry_skew, clock
        # Bounds the post-exchange store commit, shielded from cancellation.
        self.commit_timeout = commit_timeout
        # Host hook for DCR client secrets; there is no implicit secret store.
        self.secret_store = secret_store
        # Failed-registration backoff: `registration_backoff` doubling per
        # attempt up to `registration_backoff_max`; Retry-After is honoured up
        # to `retry_after_max`. Proactive client-credentials re-registration
        # starts min(10% of the secret lifetime, `renewal_margin_max`) early.
        self.registration_backoff = registration_backoff
        self.registration_backoff_max = registration_backoff_max
        self.retry_after_max = retry_after_max
        self.renewal_margin_max = renewal_margin_max
        self._detached: set[anyio.Event] = set()
        self._tasks: set[object] = set()
        # Successful host prepares per (backend ID, event endpoint).
        self._prepared: dict[tuple[str, str], int] = {}

    def prepared_generation(self, backend_id: str, destination: str) -> int:
        """Count of successful host prepares for a backend's event endpoint.

        A `prepare` or `complete` returning `Ready` advances it. Hooks compares
        it to re-attempt configuration discovery skipped as unavailable. Only
        calls on this provider in this process count: a login completed by
        another process sharing the store needs a local `prepare` (which then
        returns `Ready`) or a new `Hooks` to re-attempt discovery.
        """
        return self._prepared.get((backend_id, _endpoint(destination)), 0)

    def _record_prepared(self, target: AuthTarget, result: object) -> None:
        if isinstance(result, Ready) and target.purpose == "event":
            key = (target.backend_id, _endpoint(target.destination))
            self._prepared[key] = self._prepared.get(key, 0) + 1

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
        lifetime = response.get("expires_in")
        scopes = _response_scopes(response.get("scope"))
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
            and scopes is not False
        )
        if not valid:
            raise _ExchangeError("invalid", valid_refresh)
        assert isinstance(value, str)
        if isinstance(scopes, tuple):
            granted = set(scopes)
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
        cancel: BaseException | None = None
        box: dict[str, object] = {}
        try:
            budget.remaining()
            await anyio.lowlevel.checkpoint_if_cancelled()
            await self._send_detached(
                box,
                lambda budget, trace: _token_endpoint(
                    self.network, metadata, config, form, budget, trace
                ),
            )
        except anyio.get_cancelled_exc_class() as error:
            cancel = error  # The response may still have arrived (shielded).
        except BaseException as error:
            outcome = error
        if outcome is None:
            try:
                failure, response = box.get("error"), box.get("response")
                if isinstance(failure, BaseException):
                    raise failure
                if isinstance(response, Mapping):
                    token = self._token(
                        response,
                        requested,
                        config.ceiling if ceiling is None else ceiling,
                        previous,
                    )
                else:
                    outcome = cancel
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
        if cancel is not None:
            raise cancel  # The caller sees its cancellation after the commit.
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
            if outcome.code == "invalid_client":
                raise _InvalidClient()
            if outcome.code == "unauthorized_client":
                raise AuthenticationFailure(code="credential_unavailable")
            raise AuthenticationFailure(code="provider_failed")
        if not committed or settled is None:
            raise AuthenticationFailure(code="provider_failed")
        return settled

    async def _send_detached(
        self,
        box: dict[str, object],
        send: Callable[
            [OperationBudget, Callable[[str, object], Awaitable[None]]],
            Awaitable[object],
        ],
    ) -> None:
        """Send one token or registration request; once written, finish it.

        Before the request is written (policy check, DNS, connect, TLS) the
        caller's cancellation stops it promptly. After that the grant may be
        spent or the client issued, so receiving the response is shielded and
        bounded by `commit_timeout`; the caller's cancellation is re-raised
        afterwards, with the result in `box`.
        """
        written = False
        done = anyio.Event()
        send_scope = anyio.CancelScope()

        async def trace(event: str, info: object) -> None:
            nonlocal written
            if event.endswith("send_request_body.complete"):
                written = True

        async def exchange() -> None:
            with anyio.CancelScope(shield=True):
                with send_scope:
                    try:
                        box["response"] = await send(
                            OperationBudget(anyio.current_time() + self.commit_timeout),
                            trace,
                        )
                    except Exception as error:
                        box["error"] = error
                done.set()

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(exchange)
            try:
                await done.wait()
            except anyio.get_cancelled_exc_class():
                if not written:
                    send_scope.cancel()
                raise

    async def _pending(
        self,
        guard: OAuthStoreGuard,
        record: OAuthRecord | None,
        metadata: OAuthMetadata,
        config: OAuthClientConfiguration,
        required: tuple[str, ...],
        key: StoreKey,
        budget: OperationBudget,
        registration_generation: str | None = None,
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
            and pending.registration_generation == registration_generation
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
            registration_generation,
        )
        token = record.token if record is not None else None
        await self._cas(guard, record, self._settled(metadata, token, pending))
        return PendingLogin(key, state, url, pending.expires_at)

    async def _select(
        self,
        metadata: OAuthMetadata,
        chosen: OAuthClientConfiguration,
        recorded: OAuthMetadata | None,
        budget: OperationBudget,
        *,
        interactive: bool,
        force: bool = False,
        coordinated: bool = False,
    ) -> tuple[OAuthMetadata, _Client]:
        """Select a pre-registered client, else CIMD (PKCE), else permitted DCR.

        A recorded CIMD/DCR selection survives authorization-server metadata
        changes while current host policy still permits it.
        """
        if chosen.client_id:
            return (
                replace(
                    metadata,
                    configuration=chosen,
                    client_source="preregistered",
                    registration_key=None,
                ),
                _Client(),
            )
        pkce = chosen.flow == "authorization_code_pkce"
        redirect = (chosen.redirect_uri or "") if pkce else ""
        kept = (
            recorded.client_source
            if recorded is not None
            and recorded.configuration.issuer == chosen.issuer
            and recorded.configuration.flow == chosen.flow
            else None
        )
        document = chosen.client_metadata_document if pkce else None
        if document is not None and (
            (
                kept == "cimd"
                and recorded is not None
                and recorded.configuration.client_id == document.url
            )
            or (
                metadata.client_id_metadata_document_supported
                and not (kept == "dcr" and chosen.dynamic_registration is not None)
            )
        ):
            if (
                not valid_document_url(document.url)
                or redirect not in document.redirect_uris
            ):
                raise AuthenticationFailure(code="invalid_configuration")
            config = replace(
                chosen,
                client_id=document.url,
                token_endpoint_auth_method="none",
                client_secret=None,
            )
            return (
                replace(
                    metadata,
                    configuration=config,
                    client_source="cimd",
                    registration_key=None,
                ),
                _Client(),
            )
        policy, endpoint = chosen.dynamic_registration, metadata.registration_endpoint
        if policy is None or not (endpoint or kept == "dcr"):
            raise AuthenticationFailure(code="credential_unavailable")
        method: TokenEndpointAuthMethod | None = "none"
        if not pkce:
            supported = metadata.token_endpoint_auth_methods or ("client_secret_basic",)
            method = next((m for m in SECRET_METHODS if m in supported), None)
            # A recorded registration is re-checked when it must re-register.
            if (method is None or self.secret_store is None) and kept != "dcr":
                raise AuthenticationFailure(code="credential_unavailable")
        if endpoint is not None and urlsplit(endpoint).scheme != "https":
            raise AuthenticationFailure(code="untrusted_destination")
        key = registration_key(self.namespace, chosen.issuer, chosen.flow, redirect)
        record, secret, blocked = await self._registration(
            key,
            chosen,
            policy,
            method,
            endpoint,
            redirect,
            budget,
            # PKCE registers only in host prepare; client credentials anywhere.
            register=interactive or not pkce,
            prepare=interactive,
            force=force,
            coordinated=coordinated,
        )
        if record is not None and record.client_id is not None:
            client_id = record.client_id
            renewal = None
            now = self.clock()
            if (
                not pkce
                and self._renewal_due(record, now)
                and not (record.next_attempt_at and record.next_attempt_at > now)
            ):

                async def renewal() -> object:
                    # Own budget, the registration lock (reload and re-check)
                    # and the failed marker; the operation never waits on it.
                    return await self._registration(
                        key,
                        chosen,
                        policy,
                        method,
                        endpoint,
                        redirect,
                        OperationBudget.after(self.commit_timeout),
                        register=True,
                        prepare=False,
                        force=False,
                        renew=True,
                    )

            method = record.token_endpoint_auth_method
            client = _Client(generation=record.client_generation, renewal=renewal)
        elif (
            kept == "dcr" and recorded is not None and recorded.registration_key == key
        ):
            # Keep presenting a still-valid stored token for the recorded client.
            client_id = recorded.configuration.client_id
            method = recorded.configuration.token_endpoint_auth_method
            client = _Client(blocked=blocked)
        else:
            raise AuthenticationFailure(code=blocked)
        config = replace(
            chosen,
            client_id=client_id,
            token_endpoint_auth_method=method,
            client_secret=secret,
        )
        return (
            replace(
                metadata,
                configuration=config,
                client_source="dcr",
                registration_key=key,
            ),
            client,
        )

    def _detach(self, work: Callable[[], Awaitable[object]] | None) -> None:
        """Run best-effort work outside the caller's operation and deadline.

        Failures are recorded by the work itself (failed marker) and never
        reach the caller. `renewals_settled` waits for outstanding work.
        """
        if work is None:
            return
        done = anyio.Event()
        self._detached.add(done)

        async def run() -> None:
            try:
                with anyio.fail_after(2 * self.commit_timeout):
                    await work()
            except anyio.get_cancelled_exc_class():
                raise
            except Exception as error:
                # Failures that never reach the failed marker (store, lock or
                # CAS errors, timeouts) stay observable; never secret-bearing.
                _log.warning(
                    "Detached client registration renewal failed: %s",
                    type(error).__name__,
                )
            finally:
                self._detached.discard(done)
                done.set()

        import sniffio

        if sniffio.current_async_library() == "trio":
            import trio

            trio.lowlevel.spawn_system_task(run)
        else:
            import asyncio

            task = asyncio.get_running_loop().create_task(run())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def renewals_settled(self) -> None:
        """Wait for detached proactive renewals started by this provider.

        Await this before shutting down the event loop: on asyncio, a loop
        shut down after a renewal request was written loses the issued client.
        """
        while self._detached:
            await next(iter(self._detached)).wait()

    async def _secret(
        self, record: OAuthRegistration | None, budget: OperationBudget
    ) -> str | None:
        if record is None or record.secret_ref is None or self.secret_store is None:
            return None
        return await self.secret_store.resolve(record.secret_ref, budget)

    async def _delete_secret(self, reference: str | None) -> None:
        if reference is None or self.secret_store is None:
            return
        try:
            with anyio.CancelScope(shield=True), anyio.fail_after(self.commit_timeout):
                await self.secret_store.delete(
                    reference, OperationBudget.after(self.commit_timeout)
                )
        except Exception:
            pass  # Best effort: the reference is no longer recorded anywhere.

    async def _swap_registration(
        self,
        guard: OAuthStoreGuard,
        old: OAuthRegistration | None,
        new: OAuthRegistration | None,
    ) -> None:
        """CAS a registration; delete whichever secret reference it orphans."""
        old_ref = old.secret_ref if old is not None else None
        new_ref = new.secret_ref if new is not None else None
        if not await guard.compare_and_swap(old.generation if old else None, new):
            if new_ref != old_ref:
                await self._delete_secret(new_ref)
            raise AuthenticationFailure(code="provider_failed", recovery="retry")
        if old_ref != new_ref:
            await self._delete_secret(old_ref)

    def _marked(
        self,
        record: OAuthRegistration | None,
        digest: str,
        retry_after: float | None,
        *,
        reset: bool = False,
    ) -> OAuthRegistration:
        """The failed marker after one more failed attempt."""
        now = self.clock()
        attempts = (0 if record is None or reset else record.attempts) + 1
        delay = min(
            self.registration_backoff * 2 ** min(attempts - 1, 32),
            self.registration_backoff_max,
        )
        if retry_after is not None:
            delay = max(delay, min(retry_after, self.retry_after_max))
        base = record if record is not None else OAuthRegistration("", digest)
        return replace(
            base,
            generation=uuid4().hex,
            failed_at=now,
            attempts=attempts,
            next_attempt_at=now + delay,
        )

    @staticmethod
    def _usable(
        record: OAuthRegistration, secret: str | None, pkce: bool, now: float
    ) -> bool:
        expires = record.client_secret_expires_at
        return (
            record.client_id is not None
            and not (expires and expires <= now)
            and (pkce or bool(secret))
        )

    def _renewal_due(self, record: OAuthRegistration, now: float) -> bool:
        expires = record.client_secret_expires_at
        if not expires:
            return False
        margin = min(0.1 * (expires - record.registered_at), self.renewal_margin_max)
        return now >= expires - margin

    async def _registration(
        self,
        key: str,
        chosen: OAuthClientConfiguration,
        policy: OAuthDynamicRegistration,
        method: TokenEndpointAuthMethod | None,
        endpoint: str | None,
        redirect: str,
        budget: OperationBudget,
        *,
        register: bool,
        prepare: bool,
        force: bool,
        renew: bool = False,
        coordinated: bool = False,
    ) -> tuple[OAuthRegistration | None, str | None, AuthErrorCode]:
        """Load, and when needed and permitted (re-)register, under the key lock.

        Returns the usable record (or None), its secret, and the error to
        report where a missing registration blocks a token request.
        """
        pkce = chosen.flow == "authorization_code_pkce"
        digest = request_digest(policy)
        blocked: AuthErrorCode = (
            "interaction_required" if pkce else "credential_unavailable"
        )
        if not force and not coordinated:
            # Serve an existing usable record without the registration lock,
            # so no caller ever waits on another's registration or renewal.
            seen = _registration_record(await self.store.load(key, budget))
            if (
                seen is not None
                and seen.request_digest == digest
                and not (prepare and seen.next_attempt_at is not None)
            ):
                now = self.clock()
                secret = await self._secret(seen, budget) if not pkce else None
                if self._usable(seen, secret, pkce, now) and (
                    pkce or not renew or not self._renewal_due(seen, now)
                ):
                    return seen, secret, blocked
        async with self.store.coordinate(key, budget) as guard:
            record = _registration_record(await guard.load())
            if record is not None and (record.request_digest != digest or force):
                # Host policy changed (or a forced repair): drop the record,
                # its secret and any failed marker.
                await self._swap_registration(guard, record, None)
                record = None
            now = self.clock()
            secret = await self._secret(record, budget) if not pkce else None
            usable = record is not None and self._usable(record, secret, pkce, now)
            current = record if usable else None
            if (
                record is not None
                and usable
                and (pkce or not renew or not self._renewal_due(record, now))
            ):
                if prepare and record.next_attempt_at is not None:
                    cleared = replace(
                        record,
                        generation=uuid4().hex,
                        failed_at=None,
                        attempts=0,
                        next_attempt_at=None,
                    )
                    await self._swap_registration(guard, record, cleared)
                    record = cleared
                return record, secret, blocked
            if not register:
                return current, secret, blocked
            backoff = (
                record is not None
                and record.next_attempt_at is not None
                and record.next_attempt_at > now
            )
            if (
                (backoff and not prepare)
                or endpoint is None
                or method is None
                or (not pkce and self.secret_store is None)
            ):
                # Not eligible to register now (DCR checks re-run here).
                return current, secret, "credential_unavailable"
            outcome, cancel = await self._register(
                endpoint, chosen, policy, method, redirect, budget
            )
            # Once written, always commit the outcome shielded from the
            # caller's cancellation or deadline, so an issued client (and its
            # secret) is never lost; then honour any pending cancellation.
            with anyio.CancelScope(shield=True), anyio.fail_after(self.commit_timeout):
                result = await self._commit_registration(
                    guard,
                    record,
                    current,
                    secret,
                    digest,
                    method,
                    outcome,
                    blocked,
                    prepare,
                    OperationBudget(anyio.current_time() + self.commit_timeout),
                )
            if cancel is not None:
                raise cancel
            await anyio.lowlevel.checkpoint_if_cancelled()
            return result

    async def _commit_registration(
        self,
        guard: OAuthStoreGuard,
        record: OAuthRegistration | None,
        current: OAuthRegistration | None,
        secret: str | None,
        digest: str,
        method: TokenEndpointAuthMethod,
        outcome: Issued | RegistrationFailed,
        blocked: AuthErrorCode,
        prepare: bool,
        budget: OperationBudget,
    ) -> tuple[OAuthRegistration | None, str | None, AuthErrorCode]:
        """Persist a registration outcome under the registration-key lock."""
        if isinstance(outcome, RegistrationFailed):
            await self._swap_registration(
                guard,
                record,
                self._marked(record, digest, outcome.retry_after, reset=prepare),
            )
            # A failed proactive renewal keeps the current registration;
            # otherwise only a stored token for the recorded client works.
            return current, secret, blocked if current else outcome.code
        issued = outcome
        reference = None
        if issued.client_secret is not None:
            assert self.secret_store is not None
            reference = await self.secret_store.store(issued.client_secret, budget)
        fresh = OAuthRegistration(
            uuid4().hex,
            digest,
            issued.client_id,
            uuid4().hex,
            method,
            self.clock(),
            issued.client_secret_expires_at,
            reference,
            issued.metadata,
        )
        try:
            await self._swap_registration(guard, record, fresh)
        except AuthenticationFailure:
            # Lost to a writer outside this lock: use its record instead.
            winner = _registration_record(await guard.load())
            if (
                winner is None
                or winner.client_id is None
                or winner.request_digest != digest
            ):
                raise
            return winner, await self._secret(winner, budget), blocked
        return fresh, issued.client_secret, blocked

    async def _register(
        self,
        endpoint: str,
        chosen: OAuthClientConfiguration,
        policy: OAuthDynamicRegistration,
        method: TokenEndpointAuthMethod,
        redirect: str,
        budget: OperationBudget,
    ) -> tuple[Issued | RegistrationFailed, BaseException | None]:
        """One RFC 7591 registration request; never retried here.

        Returns the outcome and any caller cancellation that arrived after the
        request was written (the caller must still commit the outcome).
        """
        import httpx
        from ._oauth_discovery import safe_request

        body = registration_request(chosen.flow, redirect, method, policy)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if policy.initial_access_token_ref is not None:
            token = (
                await self.secret_store.resolve(policy.initial_access_token_ref, budget)
                if self.secret_store is not None
                else None
            )
            if not token:
                return RegistrationFailed("credential_unavailable"), None
            # Sent only to this issuer's registration endpoint; never stored.
            headers["Authorization"] = "Bearer " + token
        box: dict[str, object] = {}
        cancel: BaseException | None = None
        try:
            await anyio.lowlevel.checkpoint_if_cancelled()
            await self._send_detached(
                box,
                lambda commit, trace: safe_request(
                    self.network,
                    httpx.Request(
                        "POST",
                        endpoint,
                        headers=headers,
                        content=json.dumps(body).encode(),
                        extensions={"trace": trace},
                    ),
                    "registration",
                    commit,
                ),
            )
        except anyio.get_cancelled_exc_class() as error:
            if not box:
                raise  # Cancelled before the request was written.
            cancel = error
        return self._registration_outcome(chosen.flow, body, box), cancel

    def _registration_outcome(
        self, flow: str, body: dict[str, object], box: dict[str, object]
    ) -> Issued | RegistrationFailed:
        import httpx

        response = box.get("response")
        if not isinstance(response, httpx.Response):
            error = box.get("error")
            return RegistrationFailed(
                "untrusted_destination"
                if isinstance(error, AuthenticationFailure)
                and error.code == "untrusted_destination"
                else "provider_failed"
            )
        try:
            data: object = json.loads(response.content)
        except ValueError:
            data = None
        now = self.clock()
        try:
            return accept_registration(
                flow,
                body,
                response.status_code,
                data,
                now,
                parse_retry_after(response.headers.get("retry-after"), now),
            )
        except RegistrationFailed as failure:
            return failure

    async def _drop_grant(
        self, target: AuthTarget, metadata: OAuthMetadata, budget: OperationBudget
    ) -> None:
        """Compare-and-delete a replaced client's grant when binding-scoped.

        A shared partition may still serve other bindings, so it is kept.
        """
        if metadata.configuration.grant_partition is not None:
            return
        async with self.store.coordinate(grant_key(target, metadata), budget) as guard:
            record = _grant_record(await guard.load())
            if record is not None:
                await self._cas(guard, record, None)

    async def _drop_registration(
        self,
        key: str,
        generation: str | None,
        policy: OAuthDynamicRegistration | None,
        budget: OperationBudget,
        *,
        mark: bool,
    ) -> None:
        """Compare-and-delete one client generation (after invalid_client).

        `mark` records a failed marker (a repeated invalid_client).
        """
        async with self.store.coordinate(key, budget) as guard:
            record = _registration_record(await guard.load())
            if record is None or record.client_generation != generation:
                return  # A newer registration is never deleted.
            cleared = replace(
                record,
                generation=uuid4().hex,
                client_id=None,
                client_generation=None,
                secret_ref=None,
                client_secret_expires_at=None,
                issued={},
            )
            if mark and policy is not None:
                cleared = self._marked(cleared, request_digest(policy), None)
            await self._swap_registration(
                guard,
                record,
                cleared if cleared.next_attempt_at is not None else None,
            )

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
        force_registration: bool = False,
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
        renew, refetched, replaced, fresh = False, False, False, False
        force = force_registration
        while True:
            metadata = None if renew else cached
            chosen: OAuthClientConfiguration | None = None
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
                        chosen = config
                        if not config.client_id and metadata.client_source != (
                            "preregistered"
                        ):
                            # Compare principals by the recorded client; the
                            # selection below may still move it.
                            config = replace(
                                config,
                                client_id=metadata.configuration.client_id,
                                token_endpoint_auth_method=(
                                    metadata.configuration.token_endpoint_auth_method
                                ),
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
                        metadata = _keep_selection(
                            await issuer_metadata(
                                resource, config, self.network, budget
                            ),
                            metadata,
                        )
                    except AuthenticationFailure:
                        if lookup:
                            raise
                        metadata = None  # Issuer gone: full discovery repairs.
            # Metadata discovered earlier in this operation counts as fresh.
            discovered = metadata is None or fresh
            if metadata is None:
                if lookup:
                    return None
                metadata = await discover(
                    target, challenge, self.network, self.policy, budget
                )
                chosen = metadata.configuration
            assert chosen is not None
            metadata, client = await self._select(
                metadata,
                chosen,
                cached,
                budget,
                interactive=interactive,
                force=force,
                # After invalid_client, read under the lock: an eventually
                # consistent store must not serve the rejected record again.
                coordinated=replaced,
            )
            if (
                force
                and cached is not None
                and cached.client_source == "dcr"
                and grant_key(target, cached) != grant_key(target, metadata)
            ):
                # A forced re-registration replaced the client.
                await self._drop_grant(target, cached, budget)
            force = False  # A forced re-registration happens once per prepare.
            config = metadata.configuration
            # Secrets are operation-local and never enter persisted metadata.
            stored = replace(metadata, configuration=_persisted(config))
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
                    record = _grant_record(await guard.load())
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
                        self._detach(client.renewal)
                        return self._ready(target, key, record)
                    if client.blocked is not None:
                        # No usable registration: only a stored token works.
                        raise AuthenticationFailure(
                            code=client.blocked, required_scopes=required
                        )
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
                        self._detach(client.renewal)
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
                        guard,
                        record,
                        stored,
                        config,
                        required,
                        key,
                        budget,
                        client.generation,
                    )
            except _InvalidClient:
                if stored.client_source == "cimd":
                    raise AuthenticationFailure(code="invalid_configuration") from None
                if stored.client_source != "dcr":
                    raise
                assert stored.registration_key is not None
                await self._drop_registration(
                    stored.registration_key,
                    client.generation,
                    chosen.dynamic_registration,
                    budget,
                    mark=replaced,
                )
                await self._drop_grant(target, stored, budget)
                if replaced or config.flow != "client_credentials":
                    # A PKCE code or refresh token bound to the old client is
                    # never reused; a repeated invalid_client stops here.
                    raise AuthenticationFailure(
                        code="interaction_required"
                        if config.flow == "authorization_code_pkce"
                        else "credential_unavailable"
                    ) from None
                # Re-register at most once per operation, without refetching
                # metadata.
                replaced, renew, fresh = True, False, discovered
                continue
            except _StaleMetadata:
                if discovered or refetched:
                    raise
            # Persisted issuer metadata looks stale: refetch the stored
            # issuer's metadata once (never protected-resource discovery),
            # persist it when the issuer is unchanged, and retry once.
            refetched = True
            cached = _keep_selection(
                await issuer_metadata(stored.resource, config, self.network, budget),
                stored,
            )

    async def prepare(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        *,
        challenge: AuthChallenge | None = None,
        required_scopes: tuple[str, ...] = (),
        force_registration: bool = False,
    ) -> Ready | PendingLogin:
        """Host-driven acquisition; the only path that creates pending logins.

        Pass a failure's `required_scopes` back here to request step-up consent.
        `force_registration` discards the current DCR registration (and its
        secret and failed marker) and registers anew, e.g. after the
        authorization server deleted the client.
        """

        async def run() -> Ready | PendingLogin:
            result = await self._acquire(
                target,
                budget,
                challenge,
                interactive=True,
                explicit=tuple(required_scopes),
                force_registration=force_registration,
            )
            assert result is not None
            return result

        prepared = await self._run(run, budget)
        self._record_prepared(target, prepared)
        return prepared

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
        registered = not config.client_id
        stored = replace(metadata, resource=resource, configuration=_persisted(config))
        if not registered and grant_key(target, stored) != login.key:
            raise AuthenticationFailure(code="access_denied")
        async with self.store.coordinate(login.key, budget) as guard:
            record = _grant_record(await guard.load())
            pending = record.pending if record is not None else None
            if (
                record is None
                or pending is None
                or pending.state != login.generation
                or pending.expires_at <= self.clock()
            ):
                raise AuthenticationFailure(code="interaction_required")
            source = pending.metadata.client_source
            if registered:
                # Complete with the client the login was created under, while
                # current host policy still permits its source.
                client_id = pending.metadata.configuration.client_id
                document = config.client_metadata_document
                if not (
                    (source == "cimd" and document and document.url == client_id)
                    or (source == "dcr" and config.dynamic_registration is not None)
                ):
                    raise AuthenticationFailure(code="interaction_required")
                config = replace(
                    config,
                    client_id=client_id,
                    token_endpoint_auth_method="none",
                    client_secret=None,
                )
                stored = replace(
                    stored,
                    configuration=_persisted(config),
                    client_source=source,
                    registration_key=pending.metadata.registration_key,
                )
                if grant_key(target, stored) != login.key:
                    raise AuthenticationFailure(code="access_denied")
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
                if source == "cimd" and values["error"] == ["invalid_client"]:
                    raise AuthenticationFailure(code="invalid_configuration")
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
            try:
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
            except _InvalidClient:
                if source == "preregistered":
                    raise
                rejected = True
            else:
                rejected = False
            if not rejected:
                assert active.token is not None
                effective = set(active.token.scopes) & set(config.ceiling)
                if not set(config.required_scopes) <= effective:
                    raise AuthenticationFailure(
                        code="access_denied", required_scopes=config.required_scopes
                    )
                return self._ready(target, login.key, active)
        # invalid_client for a registered client, handled outside the grant lock.
        if source == "cimd":
            raise AuthenticationFailure(code="invalid_configuration")
        assert pending.metadata.registration_key is not None
        # Only the generation this login was created under: a stale callback
        # never deletes a newer registration.
        await self._drop_registration(
            pending.metadata.registration_key,
            pending.registration_generation,
            None,
            budget,
            mark=False,
        )
        await self._drop_grant(target, stored, budget)  # Binding-scoped only.
        raise AuthenticationFailure(code="interaction_required")

    async def complete(
        self,
        target: AuthTarget,
        login: PendingLogin,
        callback_url: str,
        budget: OperationBudget,
    ) -> Ready:
        """Complete a stored pending login from any process sharing the store."""
        ready = await self._run(
            lambda: self._complete(target, login, callback_url, budget), budget
        )
        self._record_prepared(target, ready)
        return ready

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
                record = _grant_record(await guard.load())
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
                record = _grant_record(await guard.load())
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
