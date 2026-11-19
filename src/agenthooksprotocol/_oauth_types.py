"""Portable managed-OAuth contracts; importing this module needs no OAuth extra."""

from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
import math
from typing import Literal, Protocol, TYPE_CHECKING

import anyio

from .auth import AuthenticationFailure, AuthErrorCode, AuthTarget, BearerCredential

if TYPE_CHECKING:
    import httpx

EndpointPurpose = Literal["metadata", "token", "authorization", "registration"]
TokenEndpointAuthMethod = Literal["none", "client_secret_basic", "client_secret_post"]
ClientSource = Literal["preregistered", "cimd", "dcr"]


@dataclass(frozen=True)
class OperationBudget:
    """Absolute AnyIO monotonic deadline, never reset by nested operations."""

    deadline: float
    cancel_scope: anyio.CancelScope | None = field(
        default=None, repr=False, compare=False
    )

    @property
    def cancelled(self) -> bool:
        return self.cancel_scope is not None and self.cancel_scope.cancel_called

    def __post_init__(self) -> None:
        if not math.isfinite(self.deadline):
            raise ValueError("Deadline must be finite")

    @classmethod
    def after(
        cls, seconds: float, *, cancel_scope: anyio.CancelScope | None = None
    ) -> "OperationBudget":
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("Budget must be finite and positive")
        now = anyio.current_time()
        enclosing = anyio.current_effective_deadline()
        # AnyIO reports -inf after cancellation. Keep a finite expired budget;
        # the operation's cancellation checkpoint propagates native cancellation.
        return cls(
            min(now + seconds, now if enclosing == -math.inf else enclosing),
            cancel_scope,
        )

    def remaining(self) -> float:
        if self.cancelled:
            from .runtime import OperationCancelledError

            raise OperationCancelledError("Authentication operation cancelled")
        remaining = (
            min(self.deadline, anyio.current_effective_deadline())
            - anyio.current_time()
        )
        if remaining <= 0:
            raise TimeoutError("Authentication operation timed out")
        return remaining


class OAuthNetwork(Protocol):
    """Host enforces TLS, DNS/egress policy and no redirects for every request.

    authorize also checks browser-bound authorization URLs. send MUST NOT merge
    ambient credentials/cookies, follow redirects, or close the borrowed client.
    DNS rebinding protection belongs to this host-controlled network boundary.
    """

    async def authorize(
        self, url: str, purpose: EndpointPurpose, budget: OperationBudget
    ) -> None: ...
    async def send(
        self,
        request: "httpx.Request",
        purpose: EndpointPurpose,
        budget: OperationBudget,
    ) -> "httpx.Response": ...


def _valid_scopes(scopes: tuple[str, ...] | None) -> bool:
    return scopes is None or all(
        isinstance(scope, str)
        and scope
        and all(
            ord(c) == 33 or 35 <= ord(c) <= 91 or 93 <= ord(c) <= 126 for c in scope
        )
        for scope in scopes
    )


class ScopeFailure(AuthenticationFailure):
    """A refusal by the SDK's own scope checks, carrying the operation's full
    required set. Only these keep their scopes at the managed-OAuth boundary;
    scopes on host-raised failures are stripped."""


@dataclass(frozen=True)
class OAuthClientMetadataDocument:
    """A host-published Client ID Metadata Document; the URL is the client_id.

    `redirect_uris` are the document's declared redirects. The SDK never
    fetches the URL.
    """

    url: str
    redirect_uris: tuple[str, ...]


@dataclass(frozen=True)
class OAuthDynamicRegistration:
    """Host permission to register (RFC 7591) at the configuration's exact issuer.

    `scopes` is sent as the registration `scope` only when set. The initial
    access token is resolved through the secret store by reference, sent only
    to this issuer's registration endpoint, and never persisted.
    """

    client_name: str
    software_id: str | None = None
    software_version: str | None = None
    scopes: tuple[str, ...] | None = None
    initial_access_token_ref: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.client_name, str) or not self.client_name:
            raise ValueError("Registration client_name must be nonempty")
        if not _valid_scopes(self.scopes):
            raise ValueError("Invalid OAuth scope")


@dataclass(frozen=True)
class OAuthClientConfiguration:
    """`client_id` is a pre-registered client; leave it empty to let the SDK
    use `client_metadata_document` (PKCE) or `dynamic_registration`.

    `redirect_uri` is the PKCE redirect; `prepare(..., redirect_uri=...)` may
    override it per login (for example a fresh ephemeral loopback port).
    """

    issuer: str
    client_id: str
    flow: Literal["authorization_code_pkce", "client_credentials"]
    scopes: tuple[str, ...] = ()
    redirect_uri: str | None = field(default=None, repr=False)
    client_secret: str | None = field(default=None, repr=False)
    token_endpoint_auth_method: TokenEndpointAuthMethod = "none"
    # Stored pending-login lifetime in seconds (default and maximum 10 minutes).
    login_lifetime: float = 600
    allowed_scopes: tuple[str, ...] | None = None
    required_scopes: tuple[str, ...] = ()
    grant_partition: str | None = None
    client_metadata_document: OAuthClientMetadataDocument | None = None
    dynamic_registration: OAuthDynamicRegistration | None = None

    def __post_init__(self) -> None:
        if not 0 < self.login_lifetime <= 600:
            raise ValueError("Login lifetime must be positive and at most 600")
        for scopes in (self.scopes, self.allowed_scopes, self.required_scopes):
            if not _valid_scopes(scopes):
                raise ValueError("Invalid OAuth scope")
        # Scopes outside the ceiling are refused by the SDK as auth errors when
        # the configuration is used: requested ones as invalid_configuration,
        # required ones as access_denied naming the required set.
        if self.grant_partition is not None and (
            not isinstance(self.grant_partition, str) or not self.grant_partition
        ):
            raise ValueError("Grant partition must be nonempty")

    @property
    def ceiling(self) -> tuple[str, ...]:
        """Locally allowed scopes; defaults to the requested scopes."""
        return self.scopes if self.allowed_scopes is None else self.allowed_scopes


class OAuthTrustPolicy(Protocol):
    """Local resource/issuer/client/flow/scope authority; metadata is not trust."""

    async def resource(self, target: AuthTarget, budget: OperationBudget) -> str: ...
    async def select(
        self,
        target: AuthTarget,
        resource: str,
        issuers: tuple[str, ...],
        required_scopes: tuple[str, ...],
        budget: OperationBudget,
    ) -> OAuthClientConfiguration: ...


@dataclass(frozen=True)
class OAuthMetadata:
    """Binding metadata: the selected client and its source, plus
    authorization-server capabilities.

    For a DCR source the binding holds no issued client: a PKCE grant record
    carries the client it was issued to, and a client-credentials client lives
    in its registration record.
    """

    resource: str
    configuration: OAuthClientConfiguration = field(repr=False)
    token_endpoint: str = field(repr=False)
    authorization_endpoint: str | None = field(default=None, repr=False)
    require_response_issuer: bool = False
    registration_endpoint: str | None = field(default=None, repr=False)
    client_id_metadata_document_supported: bool = False
    token_endpoint_auth_methods: tuple[str, ...] = ()
    client_source: ClientSource = "preregistered"


@dataclass(frozen=True)
class StoredToken:
    """`access_token` is None when only refresh material is usable."""

    access_token: str | None = field(repr=False)
    expires_at: float | None = None
    refresh_token: str | None = field(default=None, repr=False)
    # Granted scopes: response scopes intersected with the allowed ceiling.
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PendingState:
    """One pending login, completed by `state`.

    `metadata.configuration` holds the login's exact redirect, its client
    (for DCR, the client registered for this login) and its acquisition
    ceiling. The PKCE verifier lives only here. `required_scopes` is the
    required set the login was prepared with (host-required, explicit and
    challenged); completion succeeds only if the grant covers it.
    """

    metadata: OAuthMetadata = field(repr=False)
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    authorization_url: str = field(repr=False)
    # Wall-clock expiry fixed at creation; not tied to any caller's deadline.
    expires_at: float
    required_scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class OAuthRecord:
    """A grant: its tokens and the client they were issued to
    (`metadata.configuration.client_id`), committed together."""

    generation: str
    status: Literal["active", "refreshing"]
    metadata: OAuthMetadata = field(repr=False)
    token: StoredToken | None = field(default=None, repr=False)


@dataclass(frozen=True)
class OAuthPendingLogins:
    """Persisted pending logins for one grant key, oldest first."""

    generation: str
    logins: tuple[PendingState, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class OAuthRegistration:
    """A client-credentials DCR registration and/or its failure backoff.

    The client secret lives only in the host secret store under `secret_ref`.
    `failure` is the code of the last failed registration, returned while
    `next_attempt_at` has not passed.
    """

    generation: str
    client_id: str | None = field(default=None, repr=False)
    token_endpoint_auth_method: TokenEndpointAuthMethod = "client_secret_basic"
    client_secret_expires_at: int | None = None
    secret_ref: str | None = field(default=None, repr=False)
    failure: AuthErrorCode | None = None
    attempts: int = 0
    next_attempt_at: float | None = None


StoredRecord = OAuthRecord | OAuthRegistration | OAuthPendingLogins
StoreKey = str


def _frame(prefix: str, fields: tuple[str, ...]) -> str:
    return prefix + "".join(f"{len(value.encode('utf-8'))}:{value}" for value in fields)


def registration_key(namespace: str, issuer: str) -> str:
    """Client-credentials DCR registration identity."""
    return _frame("ahp.oauth.registration:", (namespace, issuer))


def pending_key(grant: str) -> str:
    """Persisted pending logins of one grant key."""
    return _frame("ahp.oauth.pending:", (grant,))


def client_identity(metadata: OAuthMetadata) -> str:
    """The host's configured client source; never an issued DCR client_id."""
    if metadata.client_source == "dcr":
        return "dcr"
    return metadata.client_source + ":" + metadata.configuration.client_id


def binding_key(target: AuthTarget) -> str:
    """Exact destination binding identity, without mutable credential material."""
    if not target.namespace:
        raise ValueError("A credential namespace is required")
    return _frame(
        "ahp.oauth.binding:",
        (
            target.namespace,
            target.backend_id,
            target.purpose,
            target.destination,
        ),
    )


def grant_key(target: AuthTarget, metadata: OAuthMetadata) -> str:
    """OAuth principal identity; isolated by binding by default.

    The allowed ceiling is not identity: it is re-intersected at use.
    """
    config = metadata.configuration
    partition = (
        "binding:" + binding_key(target)
        if config.grant_partition is None
        else "shared:" + config.grant_partition
    )
    return _frame(
        "ahp.oauth.grant:",
        (
            target.namespace,
            config.issuer,
            metadata.resource,
            client_identity(metadata),
            config.flow,
            partition,
        ),
    )


class OAuthStoreGuard(Protocol):
    """Exclusion spans load/reserve/network/CAS. No callback may reenter this key.

    Grant keys hold `OAuthRecord`s, registration keys `OAuthRegistration`s and
    pending keys (only when pending logins are persisted) `OAuthPendingLogins`.

    CAS must commit atomically or reject. Failed/cancelled writes may have
    committed: callers reload rather than blindly restoring previous tokens.
    Ambiguous exchanges retain refresh material for explicit retry/host repair.
    """

    async def load(self) -> StoredRecord | None: ...
    async def compare_and_swap(
        self, expected_generation: str | None, record: StoredRecord | None
    ) -> bool: ...


class OAuthSecretStore(Protocol):
    """Host secret storage for client-credentials DCR secrets (and initial
    access tokens).

    `store` returns a fresh opaque reference; `resolve` returns None when the
    reference no longer resolves.
    """

    async def store(self, value: str, budget: OperationBudget) -> str: ...
    async def resolve(self, reference: str, budget: OperationBudget) -> str | None: ...
    async def delete(self, reference: str, budget: OperationBudget) -> None: ...


class OAuthTokenStore(Protocol):
    async def load_binding(
        self, key: str, budget: OperationBudget
    ) -> OAuthMetadata | None: ...

    async def save_binding(
        self, key: str, metadata: OAuthMetadata, budget: OperationBudget
    ) -> None: ...

    def coordinate(
        self, key: StoreKey, budget: OperationBudget
    ) -> AbstractAsyncContextManager[OAuthStoreGuard]: ...

    async def load(self, key: StoreKey, budget: OperationBudget) -> StoredRecord | None:
        """Uncoordinated read of the record a guard would load.

        It may be stale, but must return a fully committed record (or None),
        never a partially written one. Never waits on `coordinate`; the SDK
        re-checks under the lock before any write.
        """
        ...


@dataclass(frozen=True)
class Ready:
    credential: BearerCredential = field(repr=False)
    kind: Literal["ready"] = field(default="ready", init=False)


@dataclass(frozen=True)
class PendingLogin:
    key: StoreKey = field(repr=False)
    generation: str = field(repr=False)
    authorization_url: str = field(repr=False)
    expires_at: float
    kind: Literal["interaction_required"] = field(
        default="interaction_required", init=False
    )
