"""Optional, host-controlled managed OAuth. Importing is dependency-light.

Install agenthooksprotocol[oauth] (HTTPX) to perform exchanges. No browsers,
listeners, workers, HTTP clients, or token stores are created outside a bounded
operation.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
import hashlib
import json
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
    OAuthPendingLogins as OAuthPendingLogins,
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
    pending_key,
    registration_key,
)
from ._oauth_registration import (
    SECRET_METHODS,
    Issued,
    RegistrationFailed,
    accept_registration,
    declared_redirect,
    parse_retry_after,
    registration_request,
    valid_document_url,
)

T = TypeVar("T")

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


def _persisted(metadata: OAuthMetadata) -> OAuthMetadata:
    """Binding metadata never holds secrets, host registration policy, an
    issued DCR client or a redirect (a per-login property, kept by the login)."""
    config = metadata.configuration
    return replace(
        metadata,
        configuration=replace(
            config,
            client_id="" if metadata.client_source == "dcr" else config.client_id,
            redirect_uri=None,
            client_secret=None,
            client_metadata_document=None,
            dynamic_registration=None,
        ),
    )


def _with_client(metadata: OAuthMetadata, client_id: str) -> OAuthMetadata:
    """Grant-record metadata: the client its tokens were issued to."""
    return replace(
        metadata, configuration=replace(metadata.configuration, client_id=client_id)
    )


def _candidate(
    metadata: OAuthMetadata, resource: str, config: OAuthClientConfiguration
) -> OAuthMetadata:
    """Current host policy over a recorded selection, for grant-key comparison.

    A host client_id is a pre-registered client; otherwise the recorded CIMD or
    DCR selection stands until client selection moves it.
    """
    if config.client_id:
        return replace(
            metadata,
            resource=resource,
            configuration=config,
            client_source="preregistered",
        )
    if metadata.client_source == "cimd":
        config = replace(
            config,
            client_id=metadata.configuration.client_id,
            token_endpoint_auth_method="none",
            client_secret=None,
        )
    return replace(metadata, resource=resource, configuration=config)


def _keep_selection(fresh: OAuthMetadata, recorded: OAuthMetadata) -> OAuthMetadata:
    """Refetched issuer metadata keeps the recorded client selection."""
    return replace(fresh, client_source=recorded.client_source)


def _grant_record(record: StoredRecord | None) -> OAuthRecord | None:
    if record is not None and not isinstance(record, OAuthRecord):
        raise AuthenticationFailure(code="provider_failed")
    return record


def _registration_record(record: StoredRecord | None) -> OAuthRegistration | None:
    if record is not None and not isinstance(record, OAuthRegistration):
        raise AuthenticationFailure(code="provider_failed")
    return record


def _pending_record(record: StoredRecord | None) -> OAuthPendingLogins | None:
    if record is not None and not isinstance(record, OAuthPendingLogins):
        raise AuthenticationFailure(code="provider_failed")
    return record


class _ProcessGuard:
    def __init__(self, records: dict[StoreKey, StoredRecord], key: StoreKey) -> None:
        self.records, self.key = records, key

    async def load(self) -> StoredRecord | None:
        return self.records.get(self.key)

    async def compare_and_swap(
        self, expected_generation: str | None, record: StoredRecord | None
    ) -> bool:
        old = self.records.get(self.key)
        if (old.generation if old is not None else None) != expected_generation:
            return False
        if record is None:
            self.records.pop(self.key, None)
        else:
            self.records[self.key] = record
        return True


class _ProcessLogins:
    """Process-owned pending logins (the default), with per-key locks."""

    def __init__(self) -> None:
        self.records: dict[StoreKey, StoredRecord] = {}
        self.locks: dict[StoreKey, anyio.Lock] = {}

    @asynccontextmanager
    async def coordinate(
        self, key: StoreKey, budget: OperationBudget
    ) -> AsyncIterator[OAuthStoreGuard]:
        lock = self.locks.setdefault(key, anyio.Lock())
        async with lock:
            try:
                yield _ProcessGuard(self.records, key)
            finally:
                if key not in self.records and not lock.statistics().tasks_waiting:
                    self.locks.pop(key, None)

    def sweep(self, now: float) -> None:
        """Delete expired logins of every grant key not being written now."""
        for key, record in list(self.records.items()):
            lock = self.locks.get(key)
            if not isinstance(record, OAuthPendingLogins) or (lock and lock.locked()):
                continue
            logins = tuple(item for item in record.logins if item.expires_at > now)
            if not logins:
                self.records.pop(key)
                self.locks.pop(key, None)
            elif logins != record.logins:
                self.records[key] = OAuthPendingLogins(uuid4().hex, logins)


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

    The store owns grant and registration coordination across all providers
    and processes sharing a key. As in MCP clients, a pending login belongs to
    the provider that created it unless `persist_pending_logins` stores it so
    that any process sharing the store can complete it by `state`.
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
        max_pending_logins: int = 5,
        persist_pending_logins: bool = False,
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
                for value in (registration_backoff, registration_backoff_max)
            )
            or isinstance(max_pending_logins, bool)
            or not isinstance(max_pending_logins, int)
            or max_pending_logins < 1
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        self.network, self.policy, self.store = network, policy, store
        self.namespace, self.operation_timeout = namespace, operation_timeout
        self.expiry_skew, self.clock = expiry_skew, clock
        # Bounds the post-exchange store commit, shielded from cancellation.
        self.commit_timeout = commit_timeout
        # Host hook for client-credentials DCR secrets; there is no implicit
        # secret store.
        self.secret_store = secret_store
        # Client-credentials registration backoff: `registration_backoff`
        # doubling per failure up to `registration_backoff_max`, or a later
        # Retry-After up to the same cap.
        self.registration_backoff = registration_backoff
        self.registration_backoff_max = registration_backoff_max
        # Pending logins per grant key; a new one beyond the cap cancels the
        # oldest. Process-owned unless persisted through `store`.
        self.max_pending_logins = max_pending_logins
        self._logins: OAuthTokenStore | _ProcessLogins = (
            store if persist_pending_logins else _ProcessLogins()
        )
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
        forget_client: bool = False,
    ) -> OAuthRecord:
        """Spend one code, refresh token or client credential under the guard.

        Success commits the new token with `metadata` (its client) together.
        Otherwise the in-flight reservation is replaced by the previous record
        with `retained` plus any valid rotated refresh token, or dropped: by a
        refresh `invalid_grant`, or (`forget_client`) by a refresh
        `invalid_client` while the record still holds the presented client and
        refresh token.
        """
        kept = record.metadata if record is not None else metadata
        reserved = OAuthRecord(uuid4().hex, "refreshing", kept, retained)
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
        final = retained
        forget = False
        if isinstance(outcome, _ExchangeError) and previous is not None:
            if outcome.code == "invalid_grant":
                final = None
            elif outcome.code == "invalid_client" and forget_client:
                forget = True
            elif outcome.refresh_token is not None:
                final = StoredToken(None, None, outcome.refresh_token, previous.scopes)
        settled = (
            OAuthRecord(uuid4().hex, "active", metadata, token)
            if token is not None
            else OAuthRecord(uuid4().hex, "active", kept, final)
            if final is not None
            else None
        )
        committed = False
        try:
            # Rotation may already have occurred externally: finish one bounded
            # commit before honoring cancellation.
            with anyio.CancelScope(shield=True), anyio.fail_after(self.commit_timeout):
                if forget:
                    committed = await self._forget_client(
                        guard, config.client_id, previous
                    )
                else:
                    committed = await guard.compare_and_swap(
                        reserved.generation, settled
                    )
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
            if not committed and not forget:
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

    @staticmethod
    async def _forget_client(
        guard: OAuthStoreGuard, client_id: str, presented: StoredToken | None
    ) -> bool:
        """Compare-and-delete a grant whose client was rejected at refresh.

        Only while it still holds the presented client and refresh token: a
        newer login's client and tokens are never deleted.
        """
        current = _grant_record(await guard.load())
        if (
            current is None
            or presented is None
            or current.token is None
            or current.metadata.configuration.client_id != client_id
            or current.token.refresh_token != presented.refresh_token
        ):
            return False
        return await guard.compare_and_swap(current.generation, None)

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

    async def _login(
        self,
        key: StoreKey,
        metadata: OAuthMetadata,
        config: OAuthClientConfiguration,
        required: tuple[str, ...],
        granted: tuple[str, ...],
        budget: OperationBudget,
    ) -> PendingLogin:
        """Create one process-owned (or persisted) pending login.

        It requests previous grant ∪ ((requested ∪ required) ∩ ceiling) and
        records that ceiling. A DCR client is registered for this login, with
        its exact redirect.
        """
        from ._oauth_discovery import check_redirect

        if (
            config.flow != "authorization_code_pkce"
            or not metadata.authorization_endpoint
        ):
            raise AuthenticationFailure(code="unsupported_binding")
        # Only a login needs a redirect: configured, or this prepare's own.
        if not config.redirect_uri:
            raise AuthenticationFailure(code="invalid_configuration")
        check_redirect(config.redirect_uri)
        document = config.client_metadata_document
        if metadata.client_source == "cimd" and (
            document is None
            or not declared_redirect(config.redirect_uri, document.redirect_uris)
        ):
            raise AuthenticationFailure(code="invalid_configuration")
        wanted = set(config.scopes) | set(required)
        scopes = tuple(sorted(set(granted) | (wanted & set(config.ceiling))))
        ceiling = tuple(sorted(set(config.ceiling) | set(scopes)))
        if metadata.client_source == "dcr":
            config = replace(
                config,
                client_id=await self._register_login(metadata, config, budget),
                token_endpoint_auth_method="none",
                client_secret=None,
            )
        if isinstance(self._logins, _ProcessLogins):
            self._logins.sweep(self.clock())
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        url = _authorization_url(metadata, config, scopes, state, verifier)
        # Validate fallible host/browser policy before publishing the handle.
        await self.network.authorize(url, "authorization", budget)
        login = replace(
            config,
            scopes=scopes,
            # The acquisition ceiling bounds the completed grant.
            allowed_scopes=ceiling,
            client_secret=None,
            client_metadata_document=None,
            dynamic_registration=None,
        )
        pending = PendingState(
            replace(metadata, configuration=login),
            state,
            verifier,
            url,
            self.clock() + config.login_lifetime,
        )
        async with self._logins.coordinate(pending_key(key), budget) as guard:
            record = _pending_record(await guard.load())
            now = self.clock()
            logins = [
                item
                for item in (record.logins if record is not None else ())
                if item.expires_at > now
            ]
            # Beyond the cap the oldest logins are cancelled, in the same write.
            logins = [*logins, pending][-self.max_pending_logins :]
            if not await guard.compare_and_swap(
                record.generation if record is not None else None,
                OAuthPendingLogins(uuid4().hex, tuple(logins)),
            ):
                raise AuthenticationFailure(code="provider_failed", recovery="retry")
        return PendingLogin(key, state, url, pending.expires_at)

    async def _end_logins(
        self,
        key: StoreKey,
        budget: OperationBudget,
        keep: Callable[[PendingState], bool],
    ) -> None:
        """Delete pending logins of one grant key that `keep` rejects, and any
        expired ones."""
        async with self._logins.coordinate(pending_key(key), budget) as guard:
            record = _pending_record(await guard.load())
            if record is None:
                return
            now = self.clock()
            logins = tuple(
                item for item in record.logins if item.expires_at > now and keep(item)
            )
            if logins != record.logins and not await guard.compare_and_swap(
                record.generation,
                OAuthPendingLogins(uuid4().hex, logins) if logins else None,
            ):
                raise AuthenticationFailure(code="provider_failed", recovery="retry")

    async def _select(
        self,
        metadata: OAuthMetadata,
        chosen: OAuthClientConfiguration,
        recorded: OAuthMetadata | None,
        budget: OperationBudget,
        *,
        prepare: bool,
        force: bool = False,
        coordinated: bool = False,
    ) -> tuple[OAuthMetadata, AuthErrorCode | None]:
        """Select a pre-registered client, else CIMD (PKCE), else permitted DCR.

        A recorded CIMD/DCR selection survives authorization-server metadata
        changes while current host policy still permits it. A PKCE DCR client
        comes from the grant record or the login; a client-credentials one from
        its registration record. The returned code is set when no
        client-credentials registration is usable and none may be made now:
        only a still-valid stored token works.
        """
        if chosen.client_id:
            return replace(
                metadata, configuration=chosen, client_source="preregistered"
            ), None
        pkce = chosen.flow == "authorization_code_pkce"
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
            # A configured redirect is checked here, before any login; one
            # supplied only to a later prepare is checked when that login is
            # created.
            if not valid_document_url(document.url) or (
                chosen.redirect_uri is not None
                and not declared_redirect(chosen.redirect_uri, document.redirect_uris)
            ):
                raise AuthenticationFailure(code="invalid_configuration")
            config = replace(
                chosen,
                client_id=document.url,
                token_endpoint_auth_method="none",
                client_secret=None,
            )
            return replace(metadata, configuration=config, client_source="cimd"), None
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
        if pkce:
            config = replace(
                chosen, token_endpoint_auth_method="none", client_secret=None
            )
            return replace(metadata, configuration=config, client_source="dcr"), None
        record, secret, blocked = await self._registration(
            registration_key(self.namespace, chosen.issuer),
            policy,
            method,
            endpoint,
            budget,
            prepare=prepare,
            force=force,
            coordinated=coordinated,
        )
        if record is not None and record.client_id is not None:
            config = replace(
                chosen,
                client_id=record.client_id,
                token_endpoint_auth_method=record.token_endpoint_auth_method,
                client_secret=secret,
            )
            return replace(metadata, configuration=config, client_source="dcr"), None
        if kept != "dcr":
            raise AuthenticationFailure(code=blocked)
        # Keep presenting a still-valid stored token; no token request is sent.
        return replace(metadata, configuration=chosen, client_source="dcr"), blocked

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
        code: AuthErrorCode,
        retry_after: float | None,
    ) -> OAuthRegistration:
        """The backoff record after one more failed registration."""
        now = self.clock()
        # Failures count until a token request with a registered client
        # succeeds, whether the client expired or was rejected.
        attempts = (record.attempts if record is not None else 0) + 1
        delay = min(
            self.registration_backoff * 2 ** min(attempts - 1, 32),
            self.registration_backoff_max,
        )
        if retry_after is not None:
            delay = max(delay, min(retry_after, self.registration_backoff_max))
        return OAuthRegistration(
            uuid4().hex, failure=code, attempts=attempts, next_attempt_at=now + delay
        )

    @staticmethod
    def _usable(record: OAuthRegistration, secret: str | None, now: float) -> bool:
        expires = record.client_secret_expires_at
        return (
            record.client_id is not None
            and not (expires and expires <= now)
            and bool(secret)
        )

    async def _registration(
        self,
        key: str,
        policy: OAuthDynamicRegistration,
        method: TokenEndpointAuthMethod | None,
        endpoint: str | None,
        budget: OperationBudget,
        *,
        prepare: bool,
        force: bool,
        coordinated: bool,
    ) -> tuple[OAuthRegistration | None, str | None, AuthErrorCode]:
        """Load, and when needed and permitted register, a client-credentials
        client under the registration-key lock.

        Returns the usable record (or None), its secret, and the error to
        report where a missing registration blocks a token request: the last
        failure's code during the backoff. Host `prepare` bypasses the backoff;
        `force` replaces a usable record.
        """
        if not force and not coordinated:
            # Serve an existing usable record without the registration lock.
            seen = _registration_record(await self.store.load(key, budget))
            if seen is not None:
                secret = await self._secret(seen, budget)
                if self._usable(seen, secret, self.clock()):
                    return seen, secret, "credential_unavailable"
        async with self.store.coordinate(key, budget) as guard:
            record = _registration_record(await guard.load())
            secret = await self._secret(record, budget)
            now = self.clock()
            usable = record is not None and self._usable(record, secret, now)
            if usable and not force:
                return record, secret, "credential_unavailable"
            if (
                not prepare
                and record is not None
                and record.next_attempt_at is not None
                and record.next_attempt_at > now
            ):
                return None, None, record.failure or "credential_unavailable"
            if endpoint is None or method is None or self.secret_store is None:
                # Not eligible to register now (DCR checks re-run here).
                return None, None, "credential_unavailable"
            outcome, cancel = await self._register(
                endpoint, "client_credentials", policy, method, "", budget
            )
            # Once written, always commit the outcome shielded from the
            # caller's cancellation or deadline, so an issued client (and its
            # secret) is never lost; then honour any pending cancellation.
            with anyio.CancelScope(shield=True), anyio.fail_after(self.commit_timeout):
                result = await self._commit_registration(
                    guard,
                    record,
                    record if usable else None,
                    secret,
                    method,
                    outcome,
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
        method: TokenEndpointAuthMethod,
        outcome: Issued | RegistrationFailed,
        budget: OperationBudget,
    ) -> tuple[OAuthRegistration | None, str | None, AuthErrorCode]:
        """Persist a registration outcome under the registration-key lock.

        A failed forced replacement keeps the current usable record, records
        the failure in its backoff and returns the failure.
        """
        if isinstance(outcome, RegistrationFailed):
            if current is not None:
                marker = self._marked(current, outcome.code, outcome.retry_after)
                await self._swap_registration(
                    guard,
                    current,
                    replace(
                        current,
                        generation=marker.generation,
                        failure=marker.failure,
                        attempts=marker.attempts,
                        next_attempt_at=marker.next_attempt_at,
                    ),
                )
                raise AuthenticationFailure(code=outcome.code)
            await self._swap_registration(
                guard, record, self._marked(record, outcome.code, outcome.retry_after)
            )
            return None, None, outcome.code
        assert self.secret_store is not None and outcome.client_secret is not None
        reference = await self.secret_store.store(outcome.client_secret, budget)
        fresh = OAuthRegistration(
            uuid4().hex,
            outcome.client_id,
            method,
            outcome.client_secret_expires_at,
            reference,
            # The failure count carries over until a token request with this
            # client succeeds, so a client rejected again keeps doubling.
            attempts=record.attempts if record is not None else 0,
        )
        try:
            await self._swap_registration(guard, record, fresh)
        except AuthenticationFailure:
            # Lost to a writer outside this lock: use its record instead.
            winner = _registration_record(await guard.load())
            if winner is None or winner.client_id is None:
                raise
            return winner, await self._secret(winner, budget), "credential_unavailable"
        return fresh, outcome.client_secret, "credential_unavailable"

    async def _register(
        self,
        endpoint: str,
        flow: str,
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

        body = registration_request(flow, redirect, method, policy)
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
        return self._registration_outcome(flow, body, box), cancel

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

    async def _register_login(
        self,
        metadata: OAuthMetadata,
        config: OAuthClientConfiguration,
        budget: OperationBudget,
    ) -> str:
        """Register a public client for one login, with its exact redirect.

        There is no registration record: the login holds the issued client and
        completion commits it with the tokens. Any issued secret is ignored.
        """
        policy, endpoint = config.dynamic_registration, metadata.registration_endpoint
        if policy is None or endpoint is None:
            raise AuthenticationFailure(code="credential_unavailable")
        assert config.redirect_uri is not None
        outcome, cancel = await self._register(
            endpoint, config.flow, policy, "none", config.redirect_uri, budget
        )
        if cancel is not None:
            raise cancel  # The issued client is abandoned with this login.
        if isinstance(outcome, RegistrationFailed):
            raise AuthenticationFailure(code=outcome.code)
        return outcome.client_id

    async def _registration_worked(
        self, key: str, client_id: str, budget: OperationBudget
    ) -> None:
        """Reset the failure count once a token request with the client succeeds."""
        seen = _registration_record(await self.store.load(key, budget))
        if seen is None or not seen.attempts or seen.client_id != client_id:
            return
        async with self.store.coordinate(key, budget) as guard:
            record = _registration_record(await guard.load())
            if record is not None and record.attempts and record.client_id == client_id:
                await self._swap_registration(
                    guard,
                    record,
                    replace(
                        record,
                        generation=uuid4().hex,
                        failure=None,
                        attempts=0,
                        next_attempt_at=None,
                    ),
                )

    async def _drop_registration(
        self, key: str, client_id: str, budget: OperationBudget, *, mark: bool
    ) -> None:
        """Compare-and-delete a client-credentials client after invalid_client.

        `mark` (a repeated invalid_client) leaves a backoff record instead.
        """
        async with self.store.coordinate(key, budget) as guard:
            record = _registration_record(await guard.load())
            if record is None or record.client_id != client_id:
                return  # A newer registration is never deleted.
            await self._swap_registration(
                guard,
                record,
                # A repeated invalid_client counts as a failed registration.
                self._marked(record, "credential_unavailable", None)
                if mark
                # The failure count survives the first rejection's re-register.
                else OAuthRegistration(uuid4().hex, attempts=record.attempts)
                if record.attempts
                else None,
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
        redirect_uri: str | None = None,
    ) -> Ready | PendingLogin | None:
        """Acquire, then reset a client-credentials failure count after the
        grant lock is released, best effort: the token is already committed,
        so a store error there never fails the acquisition."""
        worked: list[tuple[str, str]] = []
        result = await self._acquire_locked(
            target,
            budget,
            challenge,
            rejected,
            interactive=interactive,
            lookup=lookup,
            explicit=explicit,
            force_registration=force_registration,
            redirect_uri=redirect_uri,
            worked=worked,
        )
        for key, client_id in worked:
            try:
                await self._registration_worked(key, client_id, budget)
            except Exception:
                pass  # Only a later backoff is longer than it needs to be.
        return result

    async def _acquire_locked(
        self,
        target: AuthTarget,
        budget: OperationBudget,
        challenge: AuthChallenge | None,
        rejected: str | None,
        *,
        interactive: bool,
        lookup: bool,
        explicit: tuple[str, ...],
        force_registration: bool,
        redirect_uri: str | None,
        worked: list[tuple[str, str]],
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
        # A forced client-credentials re-registration acquires a token with
        # the new client instead of serving the replaced client's.
        forced = False
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
                        if redirect_uri is not None:
                            config = replace(config, redirect_uri=redirect_uri)
                        validate_configuration(
                            target, resource, issuers, challenged, config
                        )
                        chosen = config
                        candidate = _candidate(metadata, resource, config)
                    except AuthenticationFailure:
                        if lookup:
                            raise
                # A failed cached check or a changed principal (issuer, client
                # identity, flow or partition) rediscovers and repairs the
                # binding; the lookup cannot discover, so it fails instead of
                # going anonymous. Never reuse the old principal.
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
                    target,
                    challenge,
                    self.network,
                    self.policy,
                    budget,
                    redirect_uri=redirect_uri,
                )
                chosen = metadata.configuration
            assert chosen is not None
            metadata, blocked = await self._select(
                metadata,
                chosen,
                cached,
                budget,
                prepare=interactive,
                force=force,
                # After invalid_client, read under the lock: an eventually
                # consistent store must not serve the rejected record again.
                coordinated=replaced,
            )
            forced = forced or (
                force
                and metadata.client_source == "dcr"
                and metadata.configuration.flow == "client_credentials"
            )
            force = False  # A forced re-registration happens once per prepare.
            config = metadata.configuration
            # Secrets are operation-local and never enter persisted metadata.
            stored = _persisted(metadata)
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
            if interactive:
                # Host prepare deletes this grant key's expired pending logins
                # (and their verifiers), persisted or not, whatever it returns.
                await self._end_logins(key, budget, lambda item: True)
            # A PKCE DCR grant is refreshed with the client it was issued to.
            issued = stored.client_source == "dcr" and (
                config.flow == "authorization_code_pkce"
            )
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
                        and not forced
                        and token.access_token is not None
                        and (
                            token.expires_at is None
                            or token.expires_at > self.clock() + self.expiry_skew
                        )
                    ):
                        assert record is not None
                        return self._ready(target, key, record)
                    if blocked is not None:
                        # No usable registration: only a stored token works.
                        raise AuthenticationFailure(
                            code=blocked, required_scopes=required
                        )
                    refresh = (
                        token.refresh_token if token is not None and adequate else None
                    )
                    if issued and (
                        record is None or not record.metadata.configuration.client_id
                    ):
                        refresh = None  # No client to present the token with.
                    if config.flow == "client_credentials" or refresh:
                        if not discovered and (interactive or challenge is not None):
                            # Renew endpoint metadata outside the lock, then reload.
                            renew = True
                            continue
                        exchanged, committed = config, stored
                        if issued:
                            assert record is not None
                            exchanged = replace(
                                config,
                                client_id=record.metadata.configuration.client_id,
                            )
                            committed = _with_client(stored, exchanged.client_id)
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
                            committed,
                            exchanged,
                            budget,
                            form,
                            requested,
                            previous=token if refresh else None,
                            retained=token,
                            ceiling=tuple(sorted(granted | set(config.ceiling))),
                            forget_client=issued,
                        )
                        if stored.client_source == "dcr" and not issued:
                            # Recorded now, run after the grant lock.
                            worked.append(
                                (
                                    registration_key(self.namespace, config.issuer),
                                    config.client_id,
                                )
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
                    granted_scopes = token.scopes if token is not None else ()
            except _InvalidClient:
                if stored.client_source == "cimd":
                    raise AuthenticationFailure(code="invalid_configuration") from None
                if stored.client_source != "dcr":
                    raise
                if issued:
                    # The grant was compare-and-deleted; the next prepare
                    # registers a new client for a new login.
                    raise AuthenticationFailure(code="interaction_required") from None
                await self._drop_registration(
                    registration_key(self.namespace, config.issuer),
                    config.client_id,
                    budget,
                    mark=replaced,
                )
                if replaced:
                    # A repeated invalid_client stops here.
                    raise AuthenticationFailure(code="credential_unavailable") from None
                # Re-register at most once per operation, without refetching
                # metadata.
                replaced, renew, fresh = True, False, discovered
                continue
            except _StaleMetadata:
                if discovered or refetched:
                    raise
            else:
                # Registration and the login itself run outside the grant lock.
                return await self._login(
                    key, metadata, config, required, granted_scopes, budget
                )
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
        redirect_uri: str | None = None,
        force_registration: bool = False,
    ) -> Ready | PendingLogin:
        """Host-driven acquisition; the only path that creates pending logins.

        Pass a failure's `required_scopes` back here to request step-up consent.
        `redirect_uri` overrides the configured redirect for this login, e.g. a
        loopback listener on a fresh ephemeral port; a DCR client is registered
        for each login with its exact redirect. `force_registration` replaces a
        usable client-credentials registration so changed registration
        settings take effect.
        """

        async def run() -> Ready | PendingLogin:
            result = await self._acquire(
                target,
                budget,
                challenge,
                interactive=True,
                explicit=tuple(required_scopes),
                force_registration=force_registration,
                redirect_uri=redirect_uri,
            )
            assert result is not None
            return result

        prepared = await self._run(run, budget)
        self._record_prepared(target, prepared)
        return prepared

    async def _complete(
        self,
        target: AuthTarget,
        login: PendingLogin | None,
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
        current = _candidate(metadata, resource, config)
        key = grant_key(target, current)
        if login is not None and login.key != key:
            raise AuthenticationFailure(code="access_denied")
        callback = urlsplit(callback_url)
        values = parse_qs(callback.query, keep_blank_values=True)
        if not any(values.get("state", ())):
            # No state names no login, as for an unknown state.
            raise AuthenticationFailure(code="interaction_required")
        state = login.generation if login is not None else values["state"][0]
        async with self._logins.coordinate(pending_key(key), budget) as guard:
            found = _pending_record(await guard.load())
            pending = next(
                (
                    item
                    for item in (found.logins if found is not None else ())
                    if item.state == state and item.expires_at > self.clock()
                ),
                None,
            )
            if found is None or pending is None:
                raise AuthenticationFailure(code="interaction_required")
            requested = pending.metadata.configuration
            source = pending.metadata.client_source
            assert requested.redirect_uri is not None
            # The login's exact redirect, whatever the host configures now.
            config = replace(config, redirect_uri=requested.redirect_uri)
            validate_configuration(target, resource, issuers, (), config)
            # Complete with the client the login was created under, while
            # current host policy still permits its source.
            document = config.client_metadata_document
            if source != current.client_source or not (
                source == "preregistered"
                or (
                    source == "cimd"
                    and document
                    and document.url == requested.client_id
                )
                or (source == "dcr" and config.dynamic_registration is not None)
            ):
                raise AuthenticationFailure(code="interaction_required")
            # Validate redirect, state and issuer before consuming the login.
            redirect = urlsplit(requested.redirect_uri)
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
            codes = values.get("code", [])
            if "error" not in values:
                if len(codes) != 1 or not codes[0]:
                    raise AuthenticationFailure(code="access_denied")
                await self.network.authorize(callback_url, "authorization", budget)
            # Claim the login once; expired logins go with it.
            now = self.clock()
            rest = tuple(
                item
                for item in found.logins
                if item is not pending and item.expires_at > now
            )
            if not await guard.compare_and_swap(
                found.generation,
                OAuthPendingLogins(uuid4().hex, rest) if rest else None,
            ):
                raise AuthenticationFailure(code="provider_failed", recovery="retry")
        if "error" in values:
            # Valid consent denial consumes the login, never the stored grant.
            if source == "cimd" and values["error"] == ["invalid_client"]:
                raise AuthenticationFailure(code="invalid_configuration")
            raise AuthenticationFailure(code="access_denied")
        if source != "preregistered":
            config = replace(
                config,
                client_id=requested.client_id,
                token_endpoint_auth_method="none",
                client_secret=None,
            )
        stored = _with_client(
            _persisted(replace(current, configuration=config)), config.client_id
        )
        form = {
            "grant_type": "authorization_code",
            "code": codes[0],
            "redirect_uri": requested.redirect_uri,
            "code_verifier": pending.verifier,
        }
        async with self.store.coordinate(key, budget) as guard:
            record = _grant_record(await guard.load())
            previous = record.token if record is not None else None
            try:
                # The newest completed login wins: its client and tokens
                # replace the grant together.
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
                            | set(previous.scopes if previous else ())
                        )
                    ),
                    retained=previous,
                    code=True,
                )
            except _InvalidClient:
                if source == "preregistered":
                    raise
                # Only this login ends; the stored grant, which may hold an
                # older valid client, is kept.
                raise AuthenticationFailure(
                    code="invalid_configuration"
                    if source == "cimd"
                    else "interaction_required"
                ) from None
            assert active.token is not None
            effective = set(active.token.scopes) & set(config.ceiling)
            if not set(config.required_scopes) <= effective:
                raise AuthenticationFailure(
                    code="access_denied", required_scopes=config.required_scopes
                )
            return self._ready(target, key, active)

    async def complete(
        self,
        target: AuthTarget,
        login: PendingLogin | None,
        callback_url: str,
        budget: OperationBudget,
    ) -> Ready:
        """Complete a pending login by its `state`.

        Pass the `PendingLogin` from `prepare`, or None to find the login by the
        callback's `state` (for example a pasted callback URL in another
        process, when pending logins are persisted).
        """
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
        """Explicitly invalidate the current grant and its pending logins.

        A retained handle avoids I/O. This deliberate host action clears the
        current generation, not merely the handle's old generation. Do not call
        reset automatically on stale 401.
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
            await self._end_logins(key, budget, lambda item: False)

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

            def keep(item: PendingState) -> bool:
                if item.state != login.generation:
                    return True
                if grant_key(target, item.metadata) != login.key:
                    raise AuthenticationFailure(code="invalid_configuration")
                return False

            await self._end_logins(login.key, budget, keep)

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
