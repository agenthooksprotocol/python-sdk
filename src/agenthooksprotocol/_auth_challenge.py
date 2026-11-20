"""Dependency-free Bearer WWW-Authenticate parsing shared by transport and OAuth."""

from collections.abc import Mapping
import re

_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_SCOPE = r"[\x21\x23-\x5b\x5d-\x7e]+"


class ChallengeError(ValueError):
    """An unparseable or ambiguous Bearer challenge, or a 403 other than
    insufficient_scope. Always `access_denied`; no header text is retained."""

    code = "access_denied"

    def __init__(self) -> None:
        super().__init__("access_denied")


def _bearer(headers: Mapping[str, str]) -> tuple[int, list[tuple[str, str]]]:
    """(Bearer challenge count, its auth-params in order, duplicates kept).

    Unknown schemes and padded token68 values are ignored; a malformed
    Bearer auth-param raises ChallengeError.
    """
    values = [v for k, v in headers.items() if k.lower() == "www-authenticate"]
    if len(values) > 1:
        raise ChallengeError()
    if not values:
        return 0, []
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
        raise ChallengeError()
    pieces.append(values[0][start:].strip())
    bearer, params, active = 0, [], False
    for piece in pieces:
        scheme = re.match(rf"^({_TOKEN})\s+(?!\s*=)(.*)$", piece)
        if scheme or re.fullmatch(_TOKEN, piece):
            name = scheme[1] if scheme else piece
            active = name.lower() == "bearer"
            bearer += active
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
            raise ChallengeError()
        key, value = match[1].lower(), match[2]
        if value.startswith('"'):
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        params.append((key, value))
    return bearer, params


def insufficient_scope(headers: Mapping[str, str]) -> bool:
    """Whether a 403 goes to the provider: exactly one Bearer challenge with
    exactly one `error="insufficient_scope"`. Scope validation is the
    provider's job, so a malformed `scope` still routes."""
    try:
        bearer, params = _bearer(headers)
    except ChallengeError:
        return False
    errors = [value for key, value in params if key == "error"]
    return bearer == 1 and errors == ["insufficient_scope"]


def parse_challenge(
    status: int, headers: Mapping[str, str]
) -> tuple[str | None, tuple[str, ...]]:
    """Return (resource_metadata, scope tokens) for a 401/Bearer 403.

    A 403 is only accepted as one Bearer `insufficient_scope`. Every parse
    failure is ChallengeError: two Bearer challenges, a malformed or
    duplicated auth-param, or a `scope` that is not RFC 6749 tokens separated
    by single spaces (empty, padded, tab-separated or an invalid character).
    """
    if status not in (401, 403):
        return None, ()
    bearer, pairs = _bearer(headers)
    if bearer > 1:
        raise ChallengeError()
    params: dict[str, str] = {}
    for key, value in pairs:
        if key in params:
            raise ChallengeError()
        params[key] = value
    if status == 403 and (bearer != 1 or params.get("error") != "insufficient_scope"):
        raise ChallengeError()
    scope = params.get("scope")
    if scope is None:
        return params.get("resource_metadata"), ()
    if not re.fullmatch(rf"{_SCOPE}(?: {_SCOPE})*", scope):
        raise ChallengeError()
    return params.get("resource_metadata"), tuple(scope.split(" "))
