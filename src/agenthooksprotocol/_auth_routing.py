"""Additive routing and immutable host auth targets (no owned resources)."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, TypeAlias
from urllib.parse import urlsplit

import anyio

from .auth import (
    AuthContext,
    AuthChallenge,
    AuthProvider,
    BearerCredential,
    EnvironmentAuthProvider,
    AuthenticationFailure,
    AuthErrorCode,
    AuthRecovery,
)
from .runtime import OperationCancelledError


@dataclass(frozen=True)
class BearerBinding:
    token_env: str | None = field(default=None, repr=False)
    token_ref: str | None = field(default=None, repr=False)
    type: Literal["bearer"] = field(default="bearer", init=False)


@dataclass(frozen=True)
class OAuthBinding:
    issuer: str = field(repr=False)
    resource: str = field(repr=False)
    client_id: str = field(repr=False)
    flow: Literal["authorization_code_pkce", "client_credentials"]
    # A preset's scopes; None when omitted (no constraint). When present
    # they must equal the selected client's configured scopes.
    scopes: tuple[str, ...] | None = field(default=None, repr=False)
    client_secret_ref: str | None = field(default=None, repr=False)
    type: Literal["oauth"] = field(default="oauth", init=False)


NormalizedBinding: TypeAlias = BearerBinding | OAuthBinding


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    return value


def _url(value: object, schemes: tuple[str, ...] = ("https", "http")) -> str:
    if not isinstance(value, str):
        raise AuthenticationFailure(code="invalid_configuration")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in schemes
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and not any(ord(c) <= 32 or ord(c) == 127 for c in value)
        )
        _ = parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise AuthenticationFailure(code="invalid_configuration") from None
    return value


@dataclass(frozen=True)
class AuthTarget:
    """Read-only wire extensions; normalization does not authorize network access."""

    namespace: str
    backend_id: str
    destination: str = field(repr=False)
    purpose: Literal["event", "upload"]
    binding: Mapping[str, object] | None = field(repr=False)
    typed_binding: NormalizedBinding | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "binding", _freeze(self.binding))

    @property
    def kind(self) -> Literal["bearer", "oauth", "discover"]:
        return self.typed_binding.type if self.typed_binding is not None else "discover"

    @property
    def identity(self) -> tuple[object, ...]:
        return (
            self.namespace,
            self.backend_id,
            self.purpose,
            self.destination,
            self.typed_binding,
        )


def normalize_auth_target(
    context: AuthContext, *, namespace: str = "default"
) -> AuthTarget:
    if not isinstance(namespace, str) or not namespace:
        raise AuthenticationFailure(code="invalid_configuration")
    backend_id = context.backend.get("id", "")
    if not isinstance(backend_id, str) or context.purpose not in ("event", "upload"):
        raise AuthenticationFailure(code="invalid_configuration")
    destination = _url(context.destination)
    binding = context.binding
    typed: NormalizedBinding | None = None
    if binding is not None:
        if not isinstance(binding, dict):
            raise AuthenticationFailure(code="invalid_configuration")
        kind = binding.get("type")
        if kind == "bearer":
            env, ref = binding.get("tokenEnv"), binding.get("tokenRef")
            if (
                ("tokenEnv" in binding) == ("tokenRef" in binding)
                or not isinstance(env if env is not None else ref, str)
                or not (env or ref)
            ):
                raise AuthenticationFailure(code="invalid_configuration")
            typed = BearerBinding(
                env if isinstance(env, str) else None,
                ref if isinstance(ref, str) else None,
            )
        elif kind == "oauth":
            flow = binding.get("flow")
            if flow not in ("authorization_code_pkce", "client_credentials"):
                raise AuthenticationFailure(code="unsupported_binding")
            # OAuth identifiers are HTTPS-only; reject here, not at discovery.
            issuer, resource = (
                _url(binding.get("issuer"), ("https",)),
                _url(binding.get("resource"), ("https",)),
            )
            client_id = binding.get("clientId")
            # Omitted preset scopes are no constraint.
            scopes = binding.get("scopes")
            secret = binding.get("clientSecretRef")
            if (
                urlsplit(issuer).query
                or not isinstance(client_id, str)
                or not client_id
                or (
                    scopes is not None
                    and (
                        not isinstance(scopes, (list, tuple))
                        or any(
                            not isinstance(scope, str)
                            or not scope
                            or any(c.isspace() for c in scope)
                            for scope in scopes
                        )
                    )
                )
                or (secret is not None and (not isinstance(secret, str) or not secret))
            ):
                raise AuthenticationFailure(code="invalid_configuration")
            typed = OAuthBinding(
                issuer,
                resource,
                client_id,
                flow,
                None if scopes is None else tuple(sorted(set(scopes))),
                secret,
            )
        else:
            raise AuthenticationFailure(code="unsupported_binding")
    return AuthTarget(
        namespace, backend_id, destination, context.purpose, binding, typed
    )


@dataclass(frozen=True)
class _RoutedAttempt:
    owner: object = field(repr=False)
    provider: AuthProvider = field(repr=False)
    target: AuthTarget = field(repr=False)
    identity: object = field(repr=False)


class RoutingAuthProvider:
    """Opt-in routes with preemptive discovery-cache lookup for unbound targets.

    Attempts carry their issuing provider without a shared mutable registry.
    A configured route never falls through to another provider on failure.
    """

    def __init__(
        self,
        *,
        bearer: AuthProvider | None = None,
        oauth: AuthProvider | None = None,
        discover: AuthProvider | None = None,
        namespace: str = "default",
    ) -> None:
        self.bearer = bearer if bearer is not None else EnvironmentAuthProvider()
        self.oauth = oauth
        self.discover = discover
        self.namespace = namespace
        self._owner = object()

    async def _invoke(
        self,
        provider: AuthProvider,
        context: AuthContext,
        target: AuthTarget,
        challenge: AuthChallenge | None = None,
    ) -> BearerCredential | None:
        failure: AuthErrorCode | None = None
        recovery: AuthRecovery | None = None
        scopes: tuple[str, ...] = ()
        try:
            credential = (
                await provider.credential(context)
                if challenge is None
                else await provider.challenge(context, challenge)
            )
            await anyio.lowlevel.checkpoint()
        except OperationCancelledError:
            raise
        except AuthenticationFailure as exc:
            failure, recovery, scopes = exc.code, exc.recovery, exc.required_scopes
        except Exception:
            failure = "provider_failed"
        if failure is not None:
            raise AuthenticationFailure(
                code=failure, recovery=recovery, required_scopes=scopes
            )
        if credential is None:
            if challenge is None and target.binding is not None:
                raise AuthenticationFailure(code="credential_unavailable")
            return None
        if not isinstance(credential, BearerCredential):
            raise AuthenticationFailure(code="provider_failed")
        return BearerCredential(
            credential.token,
            _RoutedAttempt(self._owner, provider, target, credential.identity),
        )

    async def credential(self, context: AuthContext) -> BearerCredential | None:
        target = normalize_auth_target(context, namespace=self.namespace)
        if target.kind == "discover":
            if self.discover is None:
                return None
            return await self._invoke(self.discover, context, target)
        provider = self.bearer if target.kind == "bearer" else self.oauth
        if provider is None:
            raise AuthenticationFailure(code="unsupported_binding")
        return await self._invoke(provider, context, target)

    async def challenge(
        self, context: AuthContext, challenge: AuthChallenge
    ) -> BearerCredential | None:
        target = normalize_auth_target(context, namespace=self.namespace)
        attempt = challenge.attempted_identity
        provider: AuthProvider | None
        if (
            isinstance(attempt, _RoutedAttempt)
            and attempt.owner is self._owner
            and attempt.target == target
        ):
            provider = attempt.provider
            challenge = AuthChallenge(
                challenge.status,
                challenge.headers,
                challenge.destination,
                attempt.identity,
                challenge.retry_allowed,
            )
        elif attempt is None and target.kind == "discover":
            provider = self.discover
        else:
            raise AuthenticationFailure(code="invalid_configuration")
        if provider is None:
            return None
        return await self._invoke(provider, context, target, challenge)

    def prepared_generation(self, backend_id: str, destination: str) -> int:
        """Successful host prepares reported by the routed providers."""
        total, seen = 0, set()
        for provider in (self.bearer, self.oauth, self.discover):
            report = getattr(provider, "prepared_generation", None)
            if id(provider) in seen or not callable(report):
                continue
            seen.add(id(provider))
            total += report(backend_id, destination)
        return total


BearerAuthProvider = EnvironmentAuthProvider
