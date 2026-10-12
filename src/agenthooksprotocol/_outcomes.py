"""Lossless schema-owned projections of settled wire data.

Reducer bookkeeping stays private. Explicit wire transports use JSON for framing
and validation. These projections validate before hydration; an unsuccessful
decode is never an allowed outcome.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

from . import _models as models, generated as wire
from .event import Event, EventType
from .response import ContextualResponse, response_for_request
from .runtime import ProtocolError

_SchemaCandidate = (
    models.ToolCandidate
    | models.MessagesCandidate
    | models.TextCandidate
    | models.ElicitResultCandidate
    | models.InterceptRequestParamsStateCandidateValueObject
)


def decode_event(value: dict[str, Any]) -> Event:
    cache: dict[Any, Any] = {}
    parsed = wire._parse_descriptor(models._DESCRIPTORS["Event"], value, cache)
    if not parsed["ok"]:
        raise ProtocolError(
            "Cannot decode settled event: " + str(parsed["diagnostics"])
        )
    decoded = models._hydrate(models.Event, parsed["value"], "", cache)
    if not isinstance(decoded, models._WireModel):
        raise ProtocolError("Cannot decode unknown settled event variant")
    return cast(Event, decoded)


def decode_candidate(
    event_type: EventType, value: dict[str, Any] | None
) -> _SchemaCandidate | None:
    if value is None:
        return None
    candidate_models: dict[str, type[models._WireModel]] = {
        "tool.before": models.ToolCandidate,
        "tool.permission.request": models.ToolCandidate,
        "model.request.before": models.MessagesCandidate,
        "context.compact.before": models.TextCandidate,
        "user.elicitation.request": models.ElicitResultCandidate,
    }
    model = candidate_models.get(
        event_type, models.InterceptRequestParamsStateCandidateValueObject
    )
    try:
        return cast(_SchemaCandidate, model.from_dict(deepcopy(value)))
    except (ValueError, TypeError) as exc:
        raise ProtocolError("Cannot decode settled candidate") from exc


def decode_response(event_type: EventType, value: dict[str, Any]) -> ContextualResponse:
    parsed = response_for_request(event_type, deepcopy(value))
    if not parsed["ok"]:
        raise ProtocolError(
            "Cannot decode accepted response: " + str(parsed["diagnostics"])
        )
    return parsed["value"]
