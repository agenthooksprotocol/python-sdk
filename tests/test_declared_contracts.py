"""Caller contracts are checked during public-facade atomic admission."""

from copy import deepcopy
import unittest

import anyio
from jsonschema.exceptions import ValidationError
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from agenthooksprotocol.integrations.pydantic import PydanticCodec, PydanticFormContract
from agenthooksprotocol.runtime import ProtocolError
from test_typed_contract_regressions import Replies, hooks_for


class Arguments(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")
    required: int
    keep: str
    nullable: int | None
    nested: dict[str, int]

    @model_validator(mode="after")
    def invariant(self):
        if self.required < 0:
            raise ValueError("Required must be nonnegative")
        return self


class Result(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")
    text: str


class Provenance(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")
    source: str


def payload():
    return {
        "tool": {
            "name": "echo",
            "origin": "native",
            "input": {
                "required": 1,
                "keep": "unchanged",
                "nullable": 7,
                "nested": {"a": 1, "b": 2},
            },
        },
        "call": {"id": "call-one"},
        "path": "native",
    }


def merge(value):
    return {"type": "modify", "target": "input", "operation": "merge", "value": value}


def caps():
    return {
        "effects": ["modify", "return", "message"],
        "modify": {"input": {"replace": True, "merge": True}},
    }


class DeclaredContractsTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_partial_merge_preserves_omitted_null_and_replaces_nested_whole(self):
        async def run():
            p = payload()
            before = deepcopy(p)
            transport = Replies(
                {
                    "effects": [
                        merge({"required": 2, "nullable": None, "nested": {"new": 3}})
                    ]
                },
                {"effects": []},
            )
            async with hooks_for("tool.before", caps(), transport, count=2) as hooks:
                result = await hooks.tool_before(
                    p, input_codec=PydanticCodec(TypeAdapter(Arguments))
                )
                self.assertEqual(len(result.accepted_responses), 2, result.diagnostics)
                self.assertIsInstance(result.decoded_input, Arguments)
                self.assertEqual(result.decoded_input.required, 2)
                self.assertEqual(
                    result.input,
                    {
                        "required": 2,
                        "keep": "unchanged",
                        "nullable": None,
                        "nested": {"new": 3},
                    },
                )
                self.assertEqual(
                    transport.requests[1]["params"]["event"]["tool"]["input"],
                    result.input,
                )
            self.assertEqual(p, before)

        self.run_async(run)

    def test_invalid_later_response_rolls_back_all_and_next_sees_prior_valid_state(
        self,
    ):
        async def run():
            transport = Replies(
                {
                    "effects": [
                        merge({"required": 2}),
                        {"type": "return", "value": {"text": "accepted"}},
                    ]
                },
                {
                    "effects": [
                        {"type": "message", "text": "must not publish"},
                        merge({"required": -1}),
                        merge({"required": 2}),
                        {"type": "return", "value": {"text": "must not publish"}},
                    ]
                },
                {"effects": []},
            )
            async with hooks_for("tool.before", caps(), transport, count=3) as hooks:
                result = await hooks.tool_before(
                    payload(),
                    input_codec=PydanticCodec(TypeAdapter(Arguments)),
                    result_codec=PydanticCodec(TypeAdapter(Result)),
                )
                self.assertEqual(len(result.accepted_responses), 2, result.diagnostics)
                self.assertEqual(result.decoded_input.required, 2)
                self.assertIsInstance(result.decoded_candidate.value, Result)
                self.assertEqual(result.decoded_candidate.value.text, "accepted")
                self.assertEqual(result.state["messages"], [])
                self.assertEqual(
                    transport.requests[2]["params"]["event"]["tool"]["input"][
                        "required"
                    ],
                    2,
                )
                self.assertEqual(
                    transport.requests[2]["params"]["state"]["candidate"]["value"],
                    {"text": "accepted"},
                )

        self.run_async(run)

    def test_invalid_result_type_and_invalid_input_type_reject_entire_response(self):
        async def run():
            for effects in (
                [merge({"required": "wrong"})],
                [merge({"required": 2}), {"type": "return", "value": {"text": 42}}],
            ):
                transport = Replies({"effects": effects})
                async with hooks_for("tool.before", caps(), transport) as hooks:
                    result = await hooks.tool_before(
                        payload(),
                        input_codec=PydanticCodec(TypeAdapter(Arguments)),
                        result_codec=PydanticCodec(TypeAdapter(Result)),
                    )
                    self.assertEqual(result.accepted_responses, [])
                    self.assertEqual(result.input, payload()["tool"]["input"])
                    self.assertIsNone(result.decoded_candidate)
                    self.assertTrue(result.diagnostics)

        self.run_async(run)

    def test_lossy_extra_ignore_rejected_and_extra_allow_forwarded(self):
        class Lossy(Arguments):
            model_config = ConfigDict(strict=True, extra="ignore")

        async def run():
            value = {"future": {"body": {"ref": "opaque"}, "parts": None}}
            for cls, accepted in ((Lossy, False), (Arguments, True)):
                transport = Replies({"effects": [merge(value)]})
                async with hooks_for("tool.before", caps(), transport) as hooks:
                    result = await hooks.tool_before(
                        payload(), input_codec=PydanticCodec(TypeAdapter(cls))
                    )
                    self.assertEqual(len(result.accepted_responses), int(accepted))
                    if accepted:
                        self.assertEqual(result.input["future"], value["future"])
                        self.assertEqual(
                            result.decoded_input.model_extra["future"], value["future"]
                        )

        self.run_async(run)

    def test_candidate_absence_vs_literal_null_and_provenance_cleared_on_replacement(
        self,
    ):
        async def run():
            for candidate in (None, {"value": None, "provenance": {"source": "host"}}):
                transport = Replies({"effects": []})
                async with hooks_for("tool.before", caps(), transport) as hooks:
                    result = await hooks.tool_before(
                        payload(),
                        initial_state={"permission": "none", "candidate": candidate},
                        result_codec=PydanticCodec(TypeAdapter(str | None)),
                        provenance_codec=PydanticCodec(TypeAdapter(Provenance)),
                    )
                    if candidate is None:
                        self.assertIsNone(result.decoded_candidate)
                    else:
                        self.assertIsNone(result.decoded_candidate.value)
                        self.assertEqual(
                            result.decoded_candidate.provenance.source, "host"
                        )
            transport = Replies(
                {
                    "effects": [
                        merge({"required": 2}),
                        {"type": "return", "value": "replacement"},
                    ]
                }
            )
            async with hooks_for("tool.before", caps(), transport) as hooks:
                result = await hooks.tool_before(
                    payload(),
                    initial_state={
                        "permission": "none",
                        "candidate": {"value": "old", "provenance": {"source": "host"}},
                    },
                    input_codec=PydanticCodec(TypeAdapter(Arguments)),
                    result_codec=PydanticCodec(TypeAdapter(str)),
                    provenance_codec=PydanticCodec(TypeAdapter(Provenance)),
                )
                self.assertEqual(result.decoded_candidate.value, "replacement")
                self.assertNotIn("provenance", result.decoded_candidate.to_dict())
                self.assertNotIn("provenance", result.candidate)

        self.run_async(run)

    def test_postsettlement_decode_remains_explicit_and_does_not_reject_effects(self):
        async def run():
            transport = Replies({"effects": [merge({"required": "not declared"})]})
            async with hooks_for("tool.before", caps(), transport) as hooks:
                result = await hooks.tool_before(payload())
                self.assertEqual(len(result.accepted_responses), 1)
                before = deepcopy(result.state)
                with self.assertRaises(ValueError):
                    result.decode_input(PydanticCodec(TypeAdapter(Arguments)))
                self.assertEqual(result.state, before)
                self.assertEqual(len(result.accepted_responses), 1)

        self.run_async(run)

    def test_exact_integer_and_detached_typed_views(self):
        async def run():
            large = 2**60 + 1
            transport = Replies(
                {
                    "effects": [
                        merge({"required": large}),
                        {"type": "return", "value": {"text": "accepted"}},
                    ]
                }
            )
            async with hooks_for("tool.before", caps(), transport) as hooks:
                result = await hooks.tool_before(
                    payload(),
                    input_codec=PydanticCodec(TypeAdapter(Arguments)),
                    result_codec=PydanticCodec(TypeAdapter(Result)),
                )
                self.assertEqual(result.decoded_input.required, large)
                self.assertIs(type(result.input["required"]), int)
                typed = result.decoded_input
                typed.nested.clear()
                candidate = result.decoded_candidate
                candidate.value.text = "mutated"
                self.assertEqual(result.input["nested"], {"a": 1, "b": 2})
                self.assertEqual(result.candidate["value"], {"text": "accepted"})

        self.run_async(run)

    def test_replacing_candidate_alone_clears_provenance(self):
        async def run():
            transport = Replies(
                {"effects": [{"type": "return", "value": {"text": "new"}}]}
            )
            async with hooks_for("tool.before", caps(), transport) as hooks:
                result = await hooks.tool_before(
                    payload(),
                    initial_state={
                        "permission": "none",
                        "candidate": {
                            "value": {"text": "old"},
                            "provenance": {"source": "host"},
                        },
                    },
                    result_codec=PydanticCodec(TypeAdapter(Result)),
                    provenance_codec=PydanticCodec(TypeAdapter(Provenance)),
                )
                self.assertEqual(result.decoded_candidate.value.text, "new")
                self.assertNotIn("provenance", result.decoded_candidate.to_dict())

        self.run_async(run)

    def test_declared_host_paths_validate_but_unspecified_native_is_opaque(self):
        async def run():
            p = payload()
            p["native"] = {"parts": None, "body": {"ref": "not-an-attachment"}}
            transport = Replies({"effects": []})
            async with hooks_for("tool.before", caps(), transport) as hooks:
                result = await hooks.tool_before(p)
                self.assertEqual(result.event["native"], p["native"])
            transport = Replies({"effects": []})
            async with hooks_for("tool.before", caps(), transport) as hooks:
                with self.assertRaises(Exception):
                    await hooks.tool_before(
                        p,
                        event_codecs={("native",): PydanticCodec(TypeAdapter(Result))},
                    )
                self.assertEqual(transport.requests, [])

        self.run_async(run)

    def test_single_answer_contract_validates_public_elicitation_admission(self):
        from test_public_content import Store, elicitation
        import json

        class Answer(BaseModel):
            count: int = Field(ge=1, le=4)

            @model_validator(mode="after")
            def additional_invariant(self):
                if self.count == 3:
                    raise ValueError("Three is not allowed")
                return self

        async def run():
            contract = PydanticFormContract(TypeAdapter(Answer))
            original, _ = elicitation(Store())
            original["params"]["event"]["source"] = "urn:test:typed"
            original["params"]["event"]["elicitation"]["request"]["text"] = json.dumps(
                contract.request("Count now")
            )
            for count, accepted in ((2, True), (3, False)):
                value = {
                    "action": "accept",
                    "content": {"count": count},
                    "_meta": {"future": {"parts": None}},
                }
                transport = Replies({"effects": [{"type": "return", "value": value}]})
                async with hooks_for(
                    "user.elicitation.request",
                    original["params"]["capabilities"],
                    transport,
                ) as hooks:
                    result = await hooks.user_elicitation_request(
                        original["params"]["event"],
                        result_codec=contract.result_codec(),
                    )
                    self.assertEqual(
                        len(result.accepted_responses),
                        int(accepted),
                        result.diagnostics,
                    )
                    if accepted:
                        self.assertIsInstance(
                            result.decoded_candidate.value.content, Answer
                        )
                        self.assertEqual(
                            result.decoded_candidate.value.content.count, 2
                        )
                        self.assertEqual(
                            contract.result_codec().encode(
                                result.decoded_candidate.value
                            ),
                            value,
                        )
                    else:
                        self.assertIsNone(result.decoded_candidate)

        self.run_async(run)


class FormContractTests(unittest.TestCase):
    def test_one_answer_type_derives_schema_and_validates_constraints(self):
        class Answer(BaseModel):
            count: int = Field(ge=1, le=4)
            name: str = Field(min_length=2, max_length=5)
            ok: bool

        contract = PydanticFormContract(TypeAdapter(Answer))
        requested = contract.request("Answer now")
        self.assertEqual(
            requested["requestedSchema"]["properties"]["count"]["minimum"], 1
        )
        answer = contract.decode_result(
            {"action": "accept", "content": {"count": 2, "name": "Hi", "ok": True}}
        )
        self.assertIsInstance(answer, Answer)
        for value in (
            {"count": 0, "name": "Hi", "ok": True},
            {"count": 2, "name": "x", "ok": True},
            {"count": 2, "name": "Hi", "ok": "true"},
        ):
            with self.assertRaises(Exception):
                contract.decode_result({"action": "accept", "content": value})
        requested["requestedSchema"]["properties"]["count"]["minimum"] = -100
        self.assertEqual(contract.requested_schema["properties"]["count"]["minimum"], 1)

    def test_omitted_form_answers_decode_empty_optional_and_reject_required(self):
        from test_public_content import Store, elicitation
        import json

        class Empty(BaseModel):
            pass

        class OptionalAnswer(BaseModel):
            ok: bool = False

        class RequiredAnswer(BaseModel):
            ok: bool

        async def run():
            for kind, accepted in (
                (Empty, True),
                (OptionalAnswer, True),
                (RequiredAnswer, False),
            ):
                contract = PydanticFormContract(TypeAdapter(kind))
                wire = {"action": "accept", "_meta": {"future": True}}
                if accepted:
                    self.assertIsInstance(contract.decode_result(wire), kind)
                else:
                    with self.assertRaises((ValueError, ProtocolError, ValidationError)):
                        contract.decode_result(wire)
                self.assertNotIn("content", wire)
                self.assertIsNone(contract.decode_result(wire, mode="url"))
                with self.assertRaises(ValueError):
                    contract.decode_result(
                        {"action": "accept", "content": {}}, mode="url"
                    )
                original, _ = elicitation(Store())
                original["params"]["event"]["source"] = "urn:test:typed"
                original["params"]["event"]["elicitation"]["request"]["text"] = (
                    json.dumps(contract.request("Answer"))
                )
                transport = Replies({"effects": [{"type": "return", "value": wire}]})
                async with hooks_for(
                    "user.elicitation.request",
                    original["params"]["capabilities"],
                    transport,
                ) as hooks:
                    result = await hooks.user_elicitation_request(
                        original["params"]["event"],
                        result_codec=contract.result_codec(),
                    )
                    self.assertEqual(
                        len(result.accepted_responses),
                        int(accepted),
                        result.diagnostics,
                    )
                    if accepted:
                        self.assertIsInstance(
                            result.decoded_candidate.value.content, kind
                        )
                        self.assertNotIn(
                            "content",
                            result.accepted_response["result"]["effects"][0]["value"],
                        )
                    else:
                        self.assertIsNone(result.decoded_candidate)
                self.assertNotIn("content", wire)

        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(run, backend=backend)

    def test_unsupported_shapes_and_constraints_rejected_at_construction(self):
        class Nested(BaseModel):
            value: dict[str, int]

        class Pattern(BaseModel):
            value: str = Field(pattern="^x")

        for kind in (Nested, Pattern, list[int], int):
            with (
                self.subTest(kind=kind),
                self.assertRaises((ValueError, ProtocolError)),
            ):
                PydanticFormContract(TypeAdapter(kind))

    def test_decline_cancel_and_url_have_no_content(self):
        class Answer(BaseModel):
            ok: bool

        contract = PydanticFormContract(TypeAdapter(Answer))
        for action, mode in (
            ("decline", "form"),
            ("cancel", "form"),
            ("accept", "url"),
        ):
            self.assertIsNone(contract.decode_result({"action": action}, mode=mode))
            with self.assertRaises(ValueError):
                contract.decode_result(
                    {"action": action, "content": {"ok": True}}, mode=mode
                )
