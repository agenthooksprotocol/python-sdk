"""Portable managed-OAuth contracts; importing this module needs no OAuth extra."""

from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
import math
from typing import Literal, Protocol, TYPE_CHECKING

import anyio

from .auth import AuthTarget, BearerCredential

if TYPE_CHECKING:
    import httpx

EndpointPurpose = Literal["metadata", "token", "authorization"]


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


@dataclass(frozen=True)
class OAuthClientConfiguration:
    issuer: str
    client_id: str
    flow: Literal["authorization_code_pkce", "client_credentials"]
    scopes: tuple[str, ...] = ()
    redirect_uri: str | None = field(default=None, repr=False)
    client_secret: str | None = field(default=None, repr=False)
    token_endpoint_auth_method: Literal[
        "none", "client_secret_basic", "client_secret_post"
    ] = "none"
    # Stored pending-login lifetime in seconds (default and maximum 10 minutes).
    login_lifetime: float = 600
    allowed_scopes: tuple[str, ...] | None = None
    required_scopes: tuple[str, ...] = ()
    grant_partition: str | None = None

    def __post_init__(self) -> None:
        if not 0 < self.login_lifetime <= 600:
            raise ValueError("Login lifetime must be positive and at most 600")
        for scopes in (self.scopes, self.allowed_scopes, self.required_scopes):
            if scopes is not None and any(
                not isinstance(scope, str)
                or not scope
                or any(
                    not (ord(c) == 33 or 35 <= ord(c) <= 91 or 93 <= ord(c) <= 126)
                    for c in scope
                )
                for scope in scopes
            ):
                raise ValueError("Invalid OAuth scope")
        allowed = set(self.ceiling)
        if not set(self.scopes).issubset(allowed) or not set(
            self.required_scopes
        ).issubset(allowed):
            raise ValueError("Requested and required scopes must be locally allowed")
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
    resource: str
    configuration: OAuthClientConfiguration = field(repr=False)
    token_endpoint: str = field(repr=False)
    authorization_endpoint: str | None = field(default=None, repr=False)
    require_response_issuer: bool = False


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
    metadata: OAuthMetadata = field(repr=False)
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    authorization_url: str = field(repr=False)
    # Wall-clock expiry fixed at creation; not tied to any caller's deadline.
    expires_at: float


@dataclass(frozen=True)
class OAuthRecord:
    generation: str
    status: Literal["active", "refreshing", "pending"]
    metadata: OAuthMetadata = field(repr=False)
    token: StoredToken | None = field(default=None, repr=False)
    pending: PendingState | None = field(default=None, repr=False)


StoreKey = str


def _frame(prefix: str, fields: tuple[str, ...]) -> str:
    return prefix + "".join(f"{len(value.encode('utf-8'))}:{value}" for value in fields)


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
            config.client_id,
            config.flow,
            partition,
        ),
    )


class OAuthStoreGuard(Protocol):
    """Exclusion spans load/reserve/network/CAS. No callback may reenter this key.

    CAS must commit atomically or reject. Failed/cancelled writes may have
    committed: callers reload rather than blindly restoring previous tokens.
    Ambiguous exchanges retain refresh material for explicit retry/host repair.
    """

    async def load(self) -> OAuthRecord | None: ...
    async def compare_and_swap(
        self, expected_generation: str | None, record: OAuthRecord | None
    ) -> bool: ...


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
