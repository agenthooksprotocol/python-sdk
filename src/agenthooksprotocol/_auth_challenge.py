"""Dependency-free Bearer WWW-Authenticate parsing shared by transport and OAuth."""

from collections.abc import Mapping
import re
from typing import Literal

_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_SCOPE = r"[\x21\x23-\x5b\x5d-\x7e]+"


class ChallengeError(ValueError):
    """`code` is a safe auth error code; no header text is retained."""

    def __init__(self, code: Literal["discovery_failed", "access_denied"]) -> None:
        super().__init__(code)
        self.code = code


def parse_challenge(
    status: int, headers: Mapping[str, str]
) -> tuple[str | None, tuple[str, ...]]:
    """Return (resource_metadata, required scopes) for a 401/Bearer 403.

    A 403 is only accepted as Bearer `insufficient_scope`. Unknown schemes and
    padded token68 values are ignored; malformed Bearer auth-params fail closed.
    A present `scope` must be RFC 6749 scope tokens separated by single spaces;
    an empty, padded, invalid or repeated `scope` fails closed as
    `access_denied` (no scopes are trusted from it).
    """
    if status not in (401, 403):
        return None, ()
    values = [v for k, v in headers.items() if k.lower() == "www-authenticate"]
    if len(values) > 1:
        raise ChallengeError("discovery_failed")
    if not values:
        if status == 403:
            raise ChallengeError("access_denied")
        return None, ()
    # Split only unquoted commas. Quoted-pairs may contain commas and quotes.
    pieces, start, quoted, escaped = [], 0, False, False
    for index, char in enumerate(values[0]):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            pieces.append(values[0][start:index].strip())
            start = index + 1
    if quoted or escaped:
        raise ChallengeError("discovery_failed")
    pieces.append(values[0][start:].strip())
    bearer, params, active = 0, {}, False
    for piece in pieces:
        scheme = re.match(rf"^({_TOKEN})\s+(?!\s*=)(.*)$", piece)
        if scheme or re.fullmatch(_TOKEN, piece):
            name = scheme[1] if scheme else piece
            active = name.lower() == "bearer"
            bearer += active
            if bearer > 1:
                raise ChallengeError("discovery_failed")
            if not scheme:
                continue
            piece = scheme[2].strip()
        if not active:
            continue
        match = re.fullmatch(
            rf'({_TOKEN})\s*=\s*({_TOKEN}|"(?:[^"\\\r\n]|\\[^\r\n])*")', piece
        )
        if match is None:
            if re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", piece):
                continue
            raise ChallengeError("discovery_failed")
        key, value = match[1].lower(), match[2]
        if key in params:
            raise ChallengeError(
                "access_denied" if key == "scope" else "discovery_failed"
            )
        if value.startswith('"'):
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        params[key] = value
    if status == 403 and (bearer != 1 or params.get("error") != "insufficient_scope"):
        raise ChallengeError("access_denied")
    scope = params.get("scope")
    if scope is None:
        return params.get("resource_metadata"), ()
    if not re.fullmatch(rf"{_SCOPE}(?: {_SCOPE})*", scope):
        raise ChallengeError("access_denied")
    return params.get("resource_metadata"), tuple(scope.split(" "))
