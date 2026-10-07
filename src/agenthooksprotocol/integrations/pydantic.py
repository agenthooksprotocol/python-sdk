"""Opt-in Pydantic v2 codec. Install agenthooksprotocol[pydantic]."""

from __future__ import annotations

from typing import Generic, TypeVar, cast

from pydantic import TypeAdapter

from ..generated import JsonValue

T = TypeVar("T")


class PydanticCodec(Generic[T]):
    """Decode application input explicitly, never as an AHP response validator.

    Pass a TypeAdapter, for example ``PydanticCodec(TypeAdapter(ReadArguments))``.
    ValidationError propagates to the caller without modifying a settled result.
    """

    def __init__(self, adapter: TypeAdapter[T]) -> None:
        self.adapter = adapter

    def encode(self, value: T) -> JsonValue:
        return cast(JsonValue, self.adapter.dump_python(value, mode="json"))

    def decode(self, value: JsonValue) -> T:
        return self.adapter.validate_python(value)
