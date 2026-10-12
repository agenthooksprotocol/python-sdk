"""Declare caller types at admission without maintaining a second wire schema.

Install agenthooksprotocol[pydantic]. Keep opaque extras with extra="allow";
lossy serializers reject a staged response rather than dropping wire fields.
"""

from agenthooksprotocol import capability

import json
from typing import Any

import anyio
import httpx

from pydantic import BaseModel, ConfigDict, TypeAdapter

from agenthooksprotocol import HookResult, Hooks, event, effect
from agenthooksprotocol._models import McpElicitationElicitResult
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
    async def before_tool(ctx: server.ToolBeforeContext) -> server.ToolBeforeReply:
        return server.ToolBeforeReply(
            effects=(
                server.MergeInput({"path": "reviewed.md"}),
                effect.ReturnTool(value={"contents": "Reviewed"}),
            )
        )

    async def intercept_elicitation(
        ctx: server.UserElicitationRequestContext,
    ) -> server.UserElicitationRequestReply:
        return server.UserElicitationRequestReply(
            effects=(
                effect.ReturnElicitResult(
                    value=McpElicitationElicitResult(
                        action="accept",
                        content={"approved": True},
                    )
                ),
            )
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
    capabilities = capability.HostCapabilities(
        tool_before=capability.ToolBeforeCapabilities(
            intercept=capability.ToolBeforeIntercept(
                return_result=True, modify_input=capability.Modify.REPLACE_AND_MERGE
            )
        ),
        user_elicitation_request=capability.UserElicitationRequestCapabilities(
            intercept=capability.UserElicitationRequestIntercept(
                return_result=True, elicitation=capability.Elicitation.FORM
            )
        ),
    )
    app = asgi.App(
        server.Handlers(
            intercept=server.InterceptHandlers(
                tool_before=before_tool,
                user_elicitation_request=intercept_elicitation,
            )
        )
    )
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
            assert tool_result.input.path == "reviewed.md"
            candidate = tool_result.candidate
            assert candidate is not None and candidate.value.contents == "Reviewed"
            form_result: HookResult[
                object, ElicitResult[Answer], object
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
            supplied = form_result.candidate
            assert supplied is not None and supplied.value.content.approved
            # Candidates are not permission to execute or proof of human approval.
            print(
                json.dumps(
                    {
                        "path": tool_result.input.path,
                        "contents": candidate.value.contents,
                        "approved": supplied.value.content.approved,
                    }
                )
            )


if __name__ == "__main__":
    anyio.run(main)
