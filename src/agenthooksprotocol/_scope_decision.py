"""The scope decision procedure and error classification (one of each).

`decide` is the only code that decides scopes: every managed-OAuth entry
point calls it. `classify` is the only code that turns an operation's error
into its public `AuthenticationFailure`: it attaches scopes only to the
SDK's own scope outcomes (`DecisionFailure`) and sets `login_ended` only for
`complete`. Both are pure and perform no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

from ._auth_challenge import ChallengeError, parse_challenge
from .auth import AuthChallenge, AuthenticationFailure, AuthErrorCode, AuthRecovery

_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")

Op = Literal["prepare", "credential", "challenge"]
Flow = Literal["authorization_code_pkce", "client_credentials"]


def valid_scopes(scopes: object) -> bool:
    """A tuple of RFC 6749 scope tokens."""
    return isinstance(scopes, tuple) and all(
        isinstance(scope, str) and _TOKEN.fullmatch(scope) is not None
        for scope in scopes
    )


class DecisionFailure(Exception):
    """An outcome of the SDK's own scope logic. Private: never raised by, or
    importable as, a host-facing error type; `classify` converts it."""

    def __init__(self, code: AuthErrorCode, scopes: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code: AuthErrorCode = code
        # Step 0 applied: the operation retires `sent` whatever the outcome.
        self.retire = False
        self.scopes = (
            tuple(sorted(set(scopes)))
            if code in ("access_denied", "interaction_required")
            else ()
        )


@dataclass(frozen=True)
class Challenge:
    """A classified challenge. `scopes` is Ch for a valid 403
    insufficient_scope; `hint` is a 401's `scope` (P)."""

    kind: Literal["none", "401", "insufficient", "insufficient_bare", "malformed"]
    status: int | None = None
    scopes: tuple[str, ...] = ()
    hint: tuple[str, ...] = ()
    resource_metadata: str | None = None


def classify_challenge(challenge: AuthChallenge | None) -> Challenge:
    if challenge is None:
        return Challenge("none")
    status = challenge.status
    if status not in (401, 403):
        return Challenge("malformed", status)
    try:
        metadata, scopes = parse_challenge(status, challenge.headers)
    except ChallengeError:
        # Unparseable, ambiguous, or a 403 other than insufficient_scope.
        return Challenge("malformed", status)
    if status == 401:
        return Challenge("401", status, hint=scopes, resource_metadata=metadata)
    if scopes:
        return Challenge(
            "insufficient", status, scopes=scopes, resource_metadata=metadata
        )
    return Challenge("insufficient_bare", status, resource_metadata=metadata)


def retires(challenge: Challenge, sent: str | None) -> bool:
    """Decide step 0: a 401 retires the generation that was sent (if it is
    still current), before every other step, whatever the outcome."""
    return challenge.status == 401 and sent is not None


@dataclass(frozen=True)
class Policy:
    """The selected client's scope policy for one operation."""

    flow: Flow
    requested: tuple[str, ...]  # S
    ceiling: tuple[str, ...]  # C
    host_required: tuple[str, ...]  # H
    preset: tuple[str, ...] | None  # an explicit preset's scopes, if any


@dataclass(frozen=True)
class Grant:
    """The stored grant as `decide` sees it."""

    generation: str
    granted: tuple[str, ...]
    token_valid: bool
    refresh: bool


Action = Literal["proceed", "use", "refresh", "acquire", "login"]


@dataclass(frozen=True)
class Decision:
    action: Action
    required: tuple[str, ...]  # R
    # Scopes to request: the client-credentials acquisition or the login.
    request: tuple[str, ...] = ()
    # Retire generation `sent` (a 401) before acting.
    retire: bool = False

    def verify(self, granted: tuple[str, ...], ceiling: tuple[str, ...]) -> None:
        """After a refresh or acquisition: the grant must cover R."""
        cover(self.required, granted, ceiling)


def cover(
    required: tuple[str, ...], granted: tuple[str, ...], ceiling: tuple[str, ...]
) -> None:
    """A committed grant must cover R within the current ceiling (decide
    steps 7-8, complete step 7): otherwise access_denied with R."""
    if not set(required) <= set(granted) & set(ceiling):
        raise DecisionFailure("access_denied", required)


def check_configuration(policy: Policy, explicit: tuple[str, ...] = ()) -> None:
    """Decide step 1: requested outside the ceiling, a preset whose scopes
    differ from the requested ones, or an invalid scope token."""
    S, C, H = policy.requested, policy.ceiling, policy.host_required
    if (
        not all(valid_scopes(s) for s in (S, C, H, explicit))
        or (policy.preset is not None and not valid_scopes(policy.preset))
        or not set(S) <= set(C)
        or (policy.preset is not None and set(policy.preset) != set(S))
    ):
        raise DecisionFailure("invalid_configuration")


_PENDING = object()  # The grant is not loaded yet: decide steps 1-4 only.


def decide(
    op: Op,
    policy: Policy,
    explicit: tuple[str, ...],
    challenge: Challenge,
    grant: Grant | None | object = _PENDING,
    sent: str | None = None,
) -> Decision:
    """The single scope decision (contract section 2). Raises
    `DecisionFailure` for a failing outcome.

    Called with the grant omitted it stops after the ceiling (step 4) and
    returns `proceed`, so the caller can refuse before any network I/O;
    called with the loaded grant (or None) it returns the action."""
    # 0. A 401 retires first, whatever follows.
    retire = retires(challenge, sent)
    try:
        return _decide(op, policy, explicit, challenge, grant, sent, retire)
    except DecisionFailure as failure:
        failure.retire = retire
        raise


def _decide(
    op: Op,
    policy: Policy,
    explicit: tuple[str, ...],
    challenge: Challenge,
    grant: Grant | None | object,
    sent: str | None,
    retire: bool,
) -> Decision:
    """Decide steps 1-9."""
    S, C, H = policy.requested, policy.ceiling, policy.host_required
    # 1. Configuration.
    check_configuration(policy, explicit)
    # 2. Challenge form.
    if challenge.kind == "malformed":
        raise DecisionFailure("access_denied")
    if challenge.kind == "insufficient_bare" and not (set(H) | set(explicit)):
        raise DecisionFailure("access_denied")
    R = tuple(sorted(set(H) | set(explicit) | set(challenge.scopes)))
    # 3. The 401 hint: this operation's client-credentials acquisition only.
    hint = set(challenge.hint) & set(C)
    # 4. Ceiling.
    if not set(R) <= set(C):
        raise DecisionFailure("access_denied", R)
    if grant is _PENDING:
        return Decision("proceed", R, retire=retire)
    assert grant is None or isinstance(grant, Grant)
    effective = set(grant.granted) & set(C) if grant is not None else set()
    covered = grant is not None and set(R) <= effective
    # 5. The server disagrees with our record.
    if challenge.kind in ("insufficient", "insufficient_bare") and covered:
        assert grant is not None
        if sent is None or grant.generation == sent:
            raise DecisionFailure("access_denied", R)
    # 6. Use (a newer generation than the rejected one is used as usual).
    stale = sent is not None and grant is not None and grant.generation == sent
    if covered and grant is not None and grant.token_valid and not stale:
        return Decision("use", R, retire=retire)
    previous = set(grant.granted) if grant is not None else set()
    # 7. Refresh.
    if grant is not None and grant.refresh and set(R) <= previous:
        return Decision("refresh", R, retire=retire)
    # 8. Client credentials.
    if policy.flow == "client_credentials":
        request = previous | ((set(S) | set(R) | hint) & set(C))
        return Decision("acquire", R, tuple(sorted(request)), retire)
    # 9. PKCE.
    if op == "prepare":
        request = previous | ((set(S) | set(R)) & set(C))
        return Decision("login", R, tuple(sorted(request)), retire)
    raise DecisionFailure("interaction_required", R)


def classify(
    error: BaseException,
) -> tuple[AuthErrorCode, AuthRecovery | None, tuple[str, ...]]:
    """The only mapping from an operation's error to (code, recovery,
    scopes). Scopes come only from `decide` (and `complete`'s required-set
    check); every other error, including host-raised ones, carries none."""
    if isinstance(error, DecisionFailure):
        return error.code, None, error.scopes
    if isinstance(error, AuthenticationFailure):
        return error.code, error.recovery, ()
    if isinstance(error, ImportError):
        return "unsupported_binding", None, ()
    return "provider_failed", None, ()
