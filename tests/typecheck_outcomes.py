"""Compile-only public consumer contracts; run with strict mypy."""

from typing import assert_type

from agenthooksprotocol import (
    McpElicitationElicitRequestFormParams,
    McpElicitationElicitRequestFormParamsRequestedSchema,
)
from agenthooksprotocol.integrations.pydantic import PydanticFormContract

from agenthooksprotocol import HookResult, _models as models
from agenthooksprotocol.codec import Candidate
from agenthooksprotocol.event import Event
from agenthooksprotocol.response import ContextualResponse


def contracts(outcome: HookResult[dict[str, int], str, dict[str, str]]) -> None:
    assert_type(outcome.event, Event)
    assert_type(outcome.messages, list[models.MessageEffect])
    assert_type(outcome.injections, list[models.InjectEffect])
    assert_type(outcome.accepted_responses, list[ContextualResponse])
    assert_type(outcome.result, str)
    assert_type(outcome.has_result, bool)
    assert_type(outcome.input, dict[str, int])
    assert_type(outcome.candidate, Candidate[str, dict[str, str]] | None)


def form_request_contract(contract: PydanticFormContract[dict[str, int]]) -> None:
    request = contract.request("Answer now")
    assert_type(request, McpElicitationElicitRequestFormParams)
    assert_type(
        request.requested_schema, McpElicitationElicitRequestFormParamsRequestedSchema
    )
    assert_type(request.message, str)
