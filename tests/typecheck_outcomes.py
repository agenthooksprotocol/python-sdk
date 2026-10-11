"""Compile-only public consumer contracts; run with strict mypy."""

from typing import assert_type

from agenthooksprotocol import HookResult, _models as models
from agenthooksprotocol.codec import Candidate
from agenthooksprotocol.event import Event
from agenthooksprotocol.generated import JsonValue
from agenthooksprotocol.response import ContextualResponse
from agenthooksprotocol._outcomes import SchemaCandidate


def contracts(outcome: HookResult[dict[str, int], str, dict[str, str]]) -> None:
    assert_type(outcome.event, Event)
    assert_type(outcome.settled_event, Event)
    assert_type(outcome.messages, list[models.MessageEffect])
    assert_type(outcome.injections, list[models.InjectEffect])
    assert_type(outcome.accepted_responses, list[ContextualResponse])
    assert_type(outcome.accepted_response, ContextualResponse | None)
    assert_type(outcome.candidate, SchemaCandidate | None)
    assert_type(outcome.decoded_result, str)
    assert_type(outcome.has_result, bool)
    assert_type(outcome.decoded_input, dict[str, int])
    assert_type(outcome.decoded_candidate, Candidate[str, dict[str, str]] | None)
    assert_type(outcome.effective_input, JsonValue)
