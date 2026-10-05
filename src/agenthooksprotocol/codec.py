"""Optional application codecs, deliberately separate from AHP admission.

TypedDict models provide static typing only. A codec decodes application JSON
*after* the protocol has settled; decoding failure does not reject hook effects.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Protocol, TypeVar

from .generated import JsonValue

T = TypeVar("T")


class Codec(Protocol[T]):
    """A caller-owned application serializer; implementations may raise errors."""

    def encode(self, value: T) -> JsonValue: ...

    def decode(self, value: JsonValue) -> T: ...


class IdentityCodec:
    """Copy JSON without inventing runtime validation for static types."""

    def encode(self, value: JsonValue) -> JsonValue:
        return deepcopy(value)

    def decode(self, value: JsonValue) -> JsonValue:
        return deepcopy(value)
