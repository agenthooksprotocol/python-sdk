"""Application codecs for explicit decoding and optional declared admission.

Post-settlement decode_input remains explicit. Codecs supplied to dispatch also
validate detached staged values before any response becomes visible.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, TypeVar

from .generated import JsonValue
from .contract import Candidate

__all__ = ["Codec", "IdentityCodec", "ValueCodecs", "Candidate"]

T = TypeVar("T")


class Codec(Protocol[T]):
    """A caller-owned application serializer; implementations may raise errors."""

    def encode(self, value: T) -> JsonValue: ...

    def decode(self, value: JsonValue) -> T: ...


R = TypeVar("R")
P = TypeVar("P")


def _decode_preserving(codec: Codec[T], value: JsonValue) -> T:
    """Reject lossy codecs; wire data, including opaque extras, stays authoritative."""
    from .runtime import _json_equal, ProtocolError

    decoded = codec.decode(deepcopy(value))
    encoded = codec.encode(deepcopy(decoded))

    def preserves(original: JsonValue, roundtrip: JsonValue) -> bool:
        if isinstance(original, dict):
            return isinstance(roundtrip, dict) and all(
                key in roundtrip and preserves(child, roundtrip[key])
                for key, child in original.items()
            )
        if isinstance(original, list):
            return (
                isinstance(roundtrip, list)
                and len(original) == len(roundtrip)
                and all(preserves(a, b) for a, b in zip(original, roundtrip))
            )
        return _json_equal(original, roundtrip)

    if not preserves(value, encoded):
        raise ProtocolError("Declared codec loses or changes wire data")
    return decoded


@dataclass(frozen=True)
class ValueCodecs:
    """Caller-owned types, not a second AHP wire schema.

    event_codecs validate only explicitly named paths relative to the event.
    This supports opaque host slots without inspecting unspecified extra bags.
    """

    input: Codec[Any] | None = None
    result: Codec[Any] | None = None
    provenance: Codec[Any] | None = None
    event_codecs: Mapping[tuple[str, ...], Codec[Any]] | None = None

    def _validate_event(self, event: dict[str, Any]) -> None:
        if self.input is not None:
            _decode_preserving(self.input, event["tool"]["input"])
        for path, codec in (self.event_codecs or {}).items():
            value: Any = event
            for key in path:
                if not isinstance(value, dict) or key not in value:
                    raise ValueError("Declared host value path is absent")
                value = value[key]
            _decode_preserving(codec, value)

    def _validate_candidate(self, candidate: dict[str, Any] | None) -> None:
        if candidate is None:
            return
        if self.result is not None:
            _decode_preserving(self.result, candidate["value"])
        if self.provenance is not None and "provenance" in candidate:
            _decode_preserving(self.provenance, candidate["provenance"])


class IdentityCodec:
    """Copy JSON without inventing runtime validation for static types."""

    def encode(self, value: JsonValue) -> JsonValue:
        return deepcopy(value)

    def decode(self, value: JsonValue) -> JsonValue:
        return deepcopy(value)
