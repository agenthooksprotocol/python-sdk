"""Opt-in Pydantic v2 codec. Install agenthooksprotocol[pydantic]."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Generic, Literal, TypeVar, cast

from pydantic import TypeAdapter

from ..generated import (
    JsonValue,
    McpElicitationElicitRequestFormParams,
    McpElicitationElicitResult,
)
from ..codec import Codec, _decode_preserving
from ..runtime import Validator
from ..contract import ElicitResult, RequestedSchema
from .. import _models

__all__ = ["PydanticCodec", "PydanticFormContract"]

T = TypeVar("T")


class PydanticCodec(Generic[T]):
    """Decode application input explicitly or declare admission-time validation.

    Pass a TypeAdapter, for example ``PydanticCodec(TypeAdapter(ReadArguments))``.
    Explicit decode_input errors do not modify settled results. When supplied
    to dispatch, validation errors reject the entire staged response instead.
    """

    def __init__(self, adapter: TypeAdapter[T]) -> None:
        self.adapter = adapter

    def encode(self, value: T) -> JsonValue:
        return cast(JsonValue, self.adapter.dump_python(value, mode="json"))

    def decode(self, value: JsonValue) -> T:
        return self.adapter.validate_python(value)


class _FormResultCodec(Generic[T]):
    def __init__(
        self, contract: PydanticFormContract[T], mode: Literal["form", "url"]
    ) -> None:
        self.contract = contract
        self.mode = mode

    def encode(self, value: ElicitResult[T]) -> JsonValue:
        result = deepcopy(value.to_dict())
        if value.content is not _models._UNSET:
            result["content"] = self.contract.encode(value.content)
        return cast(JsonValue, _models.McpElicitationElicitResult.from_dict(result))

    def decode(self, value: JsonValue) -> ElicitResult[T]:
        wire = _models.McpElicitationElicitResult.from_dict(cast(dict[str, Any], value))
        answer = self.contract.decode_result(wire, mode=self.mode)
        extra = {
            key: deepcopy(child)
            for key, child in wire.items()
            if key not in ("action", "content", "_meta")
        }
        result = ElicitResult[T](action=wire.action, additional_properties=extra)
        if "_meta" in wire:
            result.meta = cast(dict[str, Any], deepcopy(wire._meta))
        if "content" in wire or (self.mode == "form" and wire.action == "accept"):
            result.content = cast(T, answer)
        return result


class PydanticFormContract(PydanticCodec[T]):
    """Derive restricted MCP requestedSchema and answers from one TypeAdapter.

    Unsupported semantic schema keywords fail during construction. Local enum
    references are expanded; nested objects and arbitrary arrays are not forms.
    Root title/description annotations are not requestedSchema fields.
    """

    def __init__(self, adapter: TypeAdapter[T]) -> None:
        super().__init__(adapter)
        schema = deepcopy(adapter.json_schema())
        definitions = schema.pop("$defs", {})
        schema.pop("title", None)
        schema.pop("description", None)
        if schema.get("type") != "object" or set(schema) - {
            "type",
            "properties",
            "required",
        }:
            raise ValueError("Answer type is not a supported MCP form")
        for name, definition in schema.get("properties", {}).items():
            if "$ref" in definition:
                reference = definition["$ref"]
                if (
                    not reference.startswith("#/$defs/")
                    or reference[8:] not in definitions
                ):
                    raise ValueError("Unsupported form schema reference")
                definition = {
                    **definitions[reference[8:]],
                    **{k: v for k, v in definition.items() if k != "$ref"},
                }
                schema["properties"][name] = definition
        # Canonical admission checks the existing MCP primitive schema union,
        # including all supported constraints. No parallel shape schema exists.
        request = {
            "mode": "form",
            "message": "Validate form",
            "requestedSchema": schema,
        }
        Validator().validate("mcp-elicitation#request", request)
        self._requested_schema = RequestedSchema.from_dict(schema)

    def result_codec(
        self, *, mode: Literal["form", "url"] = "form"
    ) -> Codec[ElicitResult[T]]:
        return _FormResultCodec(self, mode)

    @property
    def requested_schema(self) -> RequestedSchema:
        return deepcopy(self._requested_schema)

    def request(self, message: str) -> McpElicitationElicitRequestFormParams:
        request = {
            "mode": "form",
            "message": message,
            "requestedSchema": deepcopy(self._requested_schema),
        }
        Validator().validate("mcp-elicitation#request", request)
        return cast(McpElicitationElicitRequestFormParams, request)

    def decode_result(
        self,
        result: McpElicitationElicitResult,
        *,
        mode: Literal["form", "url"] = "form",
    ) -> T | None:
        Validator().validate("mcp-elicitation#result", result)
        result = _models.McpElicitationElicitResult.from_dict(
            cast(dict[str, Any], result)
        )
        action = result.action
        if mode == "url" or action != "accept":
            if "content" in result:
                raise ValueError("Content is only allowed for an accepted form")
            return None
        content = result.get("content", {})
        Validator().validate(
            "form-answer", {"schema": self._requested_schema, "value": content}
        )
        return _decode_preserving(self, cast(JsonValue, content))
