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

    def __post_init__(self) -> None:
        if not math.isfinite(self.deadline):
            raise ValueError("Deadline must be finite")

    @classmethod
    def after(cls, seconds: float) -> "OperationBudget":
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("Budget must be finite and positive")
        now = anyio.current_time()
        enclosing = anyio.current_effective_deadline()
        # AnyIO reports -inf after cancellation. Keep a finite expired budget;
        # the operation's cancellation checkpoint propagates native cancellation.
        return cls(min(now + seconds, now if enclosing == -math.inf else enclosing))

    def remaining(self) -> float:
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
    login_lifetime: float = 300

    def __post_init__(self) -> None:
        if not math.isfinite(self.login_lifetime) or self.login_lifetime <= 0:
            raise ValueError("Login lifetime must be finite and positive")


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
    access_token: str = field(repr=False)
    expires_at: float
    refresh_token: str | None = field(default=None, repr=False)
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PendingState:
    metadata: OAuthMetadata = field(repr=False)
    state: str = field(repr=False)
    verifier: str = field(repr=False)
    authorization_url: str = field(repr=False)
    expires_at: float


@dataclass(frozen=True)
class OAuthRecord:
    generation: str
    status: Literal["active", "refreshing", "pending", "rejected"]
    metadata: OAuthMetadata = field(repr=False)
    token: StoredToken | None = field(default=None, repr=False)
    pending: PendingState | None = field(default=None, repr=False)


StoreKey = tuple[object, ...]


class OAuthStoreGuard(Protocol):
    """Exclusion spans load/reserve/network/CAS. No callback may reenter this key.

    CAS must commit atomically or reject. Failed/cancelled writes may have
    committed: callers reload rather than blindly restoring previous tokens.
    A reservation left by cancellation blocks stale refresh reuse until reset.
    """

    async def load(self) -> OAuthRecord | None: ...
    async def compare_and_swap(
        self, expected_generation: str | None, record: OAuthRecord | None
    ) -> bool: ...


class OAuthTokenStore(Protocol):
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
