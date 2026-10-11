"""Declare caller types at admission without maintaining a second wire schema.

Install agenthooksprotocol[pydantic]. Keep opaque extras with extra="allow";
lossy serializers reject a staged response rather than dropping wire fields.
"""

import json
from typing import Any, cast

import anyio
import httpx

from pydantic import BaseModel, ConfigDict, TypeAdapter

from agenthooksprotocol import HookResult, Hooks, event, wire
from agenthooksprotocol.elicitation import ElicitResult
from agenthooksprotocol.server import asgi, hooks as server
from agenthooksprotocol.transports.http import HTTPTransport
from agenthooksprotocol.integrations.pydantic import PydanticCodec, PydanticFormContract


class Arguments(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")
    path: str


class Result(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")
    contents: str


class Provenance(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")
    source: str


async def intercept_tool(
    hooks: Hooks, payload: dict[str, Any]
) -> HookResult[Arguments, Result, Provenance]:
    # Input, result, and optional provenance have independent caller types.
    return await hooks.dispatch(
        "tool.before",
        payload,
        input_codec=PydanticCodec(TypeAdapter(Arguments)),
        result_codec=PydanticCodec(TypeAdapter(Result)),
        provenance_codec=PydanticCodec(TypeAdapter(Provenance)),
    )


class Answer(BaseModel):
    approved: bool


form = PydanticFormContract(TypeAdapter(Answer))
form_request = form.request("Approve this operation?")
form_result_codec = form.result_codec()


async def main() -> None:
    async def intercept(request: wire.InterceptRequest) -> server.InterceptResult:
        params = cast(dict[str, Any], request["params"])
        if params["event"]["type"] == "tool.before":
            return server.InterceptResult(
                effects=[
                    {
                        "type": "modify",
                        "target": "input",
                        "operation": "merge",
                        "value": {"path": "reviewed.md"},
                    },
                    {"type": "return", "value": {"contents": "Reviewed"}},
                ]
            )
        return server.InterceptResult(
            effects=[
                {
                    "type": "return",
                    "value": {"action": "accept", "content": {"approved": True}},
                }
            ]
        )

    config = {
        "protocolVersion": "draft",
        "hooks": [
            {
                "id": "org.example.contracts",
                "transport": {"type": "http", "url": "http://contracts.test/hooks"},
                "subscriptions": [
                    {
                        "events": ["tool.before", "user.elicitation.request"],
                        "mode": "intercept",
                        "timeoutMs": 1000,
                        "failurePolicy": "fail-closed",
                        "content": {"default": "body"},
                    }
                ],
            }
        ],
    }
    capabilities = {
        "tool.before": {
            "modes": ["intercept"],
            "capabilities": {
                "effects": ["modify", "return"],
                "modify": {"input": {"replace": True, "merge": True}},
            },
        },
        "user.elicitation.request": {
            "modes": ["intercept"],
            "capabilities": {"effects": ["return"], "elicitation": {"form": {}}},
        },
    }
    app = asgi.App(server.Handler(intercept=intercept))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://contracts.test"
    ) as client:
        async with Hooks(
            config,
            source="urn:example:contracts",
            capabilities=capabilities,
            transport=HTTPTransport("http://contracts.test/hooks", client=client),
        ) as harness:
            tool_result = await intercept_tool(
                harness,
                event.ToolBeforeInput(
                    call_id="call-one",
                    name="read",
                    input={"path": "original.md"},
                    path="native",
                    origin="native",
                ),
            )
            assert tool_result.decoded_input.path == "reviewed.md"
            candidate = tool_result.decoded_candidate
            assert candidate is not None and candidate.value.contents == "Reviewed"
            form_result: HookResult[
                wire.JsonValue, ElicitResult[Answer], wire.JsonValue
            ] = await harness.user_elicitation_request(
                {
                    "elicitation": {
                        "mode": "form",
                        "server": "example",
                        "request": {
                            "id": "form-one",
                            "kind": "text",
                            "mediaType": "text/plain",
                            "selection": "body",
                            "text": json.dumps(form_request),
                        },
                    }
                },
                result_codec=form_result_codec,
            )
            supplied = form_result.decoded_candidate
            assert supplied is not None and supplied.value.content.approved
            # Candidates are not permission to execute or proof of human approval.
            print(
                json.dumps(
                    {
                        "path": tool_result.decoded_input.path,
                        "contents": candidate.value.contents,
                        "approved": supplied.value.content.approved,
                    }
                )
            )


if __name__ == "__main__":
    anyio.run(main)
