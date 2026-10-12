# Migrating

## 0.4 → 0.5

0.5.0 removes the draft compatibility surfaces that 0.4.x kept alongside the
typed APIs. This section lists each public name that was removed or renamed
and what to use instead. Wire formats, caller-owned codecs
(`input_codec=`, `result_codec=`, `provenance_codec=`, `event_codecs=`),
per-call `capabilities=` narrowing, and `initial_state=` are unchanged.

Every "After" snippet below runs as written against 0.5.

### Host capabilities

`Hooks(..., capabilities=...)` is now required and accepts only a frozen
`capability.HostCapabilities`. Dictionaries, `capability.Declaration`,
`capability.Mode`, the `capability.intercept()` / `capability.observe()`
builders, and the grant classes (`Allow`, `Deny`, `Ask`, `Message`, `Return`,
`ModifyInput`, `ElicitationForm`, ...) were removed from `capability`.

Each event has a `<Event>Capabilities(intercept=..., observe=...)` declaration
and a `<Event>Intercept(...)` grant class whose fields are only the controls
that event supports. `observe` defaults to `False`. Use `capability.Observe()`
for events you only observe.

> [!IMPORTANT]
> The 0.4 `capability.intercept()` builder advertised **both** intercept and
> observe modes. To keep the same wire declaration, set `observe=True`
> explicitly.

Before (0.4.x):

```python
from agenthooksprotocol import capability

capabilities = {
    "tool.before": capability.intercept().allow().deny().modify_input(replace=True),
    "tool.after": capability.observe(),
    "user.elicitation.request": capability.Declaration(
        modes=[capability.Mode.INTERCEPT],
        grants=[capability.Return(), capability.ElicitationForm()],
    ),
}
```

After (0.5):

```python
from agenthooksprotocol import capability

capabilities = capability.HostCapabilities(
    tool_before=capability.ToolBeforeCapabilities(
        intercept=capability.ToolBeforeIntercept(
            allow=True, deny=True, modify_input=capability.Modify.REPLACE
        ),
        observe=True,  # 0.4 intercept() implied this
    ),
    tool_after=capability.Observe(),
    user_elicitation_request=capability.UserElicitationRequestCapabilities(
        intercept=capability.UserElicitationRequestIntercept(
            return_result=True, elicitation=capability.Elicitation.FORM
        ),
    ),
)
assert capabilities.to_wire()["tool.before"]["modes"] == ["intercept", "observe"]
```

| 0.4 grant / builder method | 0.5 `<Event>Intercept` field |
| --- | --- |
| `Allow()` / `.allow()` | `allow=True` |
| `Ask()` / `.ask()` | `ask=True` |
| `Deny()` / `.deny()` | `deny=True` |
| `Message()` / `.message()` | `message=True` |
| `Return()` / `.return_()` | `return_result=True` |
| `ModifyInput(replace=..., merge=...)` / `.modify_input(...)` | `modify_input=Modify.REPLACE` / `Modify.MERGE` / `Modify.REPLACE_AND_MERGE` |
| `ModifyOutput`, `ModifyPrompt`, `ModifyContent`, `ModifyInstructions`, `ModifySummary`, `ModifyRequest`, `ModifyResponse`, `ModifyWorkspace` (and builder methods) | `modify_output=`, `modify_prompt=`, `modify_content=`, `modify_instructions=`, `modify_summary=`, `modify_request=`, `modify_response=`, `modify_workspace=` with a `Modify` value |
| `ElicitationForm()` / `ElicitationUrl()` (`.elicitation_form()` / `.elicitation_url()`) | `elicitation=Elicitation.FORM` / `Elicitation.URL` / `Elicitation.FORM_AND_URL` |
| `Flow(operations=["stop"], ...)` / `.flow(...)` | `flow=FlowStop(max_continuations=...)` |
| `Flow(operations=["continue", ...], ...)` | `flow=FlowContinue(remaining_continuations=..., continuation_count=..., include_stop=...)` (`tool.after`, `turn.finish.before`) |
| `InjectContext(append=True, deliver_at=[...])` / `.inject_context(...)` | `inject_context=InjectContext(deliver_at=(Delivery.NOW, ...))` |
| `Declaration(modes=[Mode.OBSERVE], ...)` / `observe()` | `capability.Observe()` |

The raw schema capability models that `capability` used to re-export
(`capability.ToolBefore`, `capability.Capabilities`,
`capability.StaticCapabilityManifest`, `capability.EventsItem`, ...) are not
authoring types. Note that `capability.ToolBeforeCapabilities` and the other
`<Event>Capabilities` names now refer to the typed declarations above. If you
need the generated wire models, import them from `agenthooksprotocol` or
`agenthooksprotocol.generated`.

### Harness construction

| 0.4.x | 0.5 |
| --- | --- |
| `Hooks(config, source=..., capabilities={...})` | `Hooks(config, source=..., capabilities=capability.HostCapabilities(...))` (required) |
| `Hooks(..., manifest={...full manifest...})` | `Hooks(..., capabilities=..., manifest_metadata=HostManifestMetadata(...))`. Events and modes come only from `capabilities`. |
| `await hooks.wait()` | `await hooks.wait_observations()` |
| `hooks.dispatch("tool.before", ...)` with any `str` | `event_name` is typed as `EventType` (`from agenthooksprotocol.event import EventType`). Literal event names type-check; dynamic strings do not. |
| (none) | `hooks.subscribes("tool.before")` static-interest lookup |
| `agenthooksprotocol.SchemaCandidate` | Removed. `result.candidate` returns `candidate.Candidate` (also `agenthooksprotocol.Candidate`). |

Before (0.4.x):

```python
hooks = Hooks(
    config,
    source="urn:example:harness",
    manifest={
        "events": [{"event": "session.start", "modes": ["observe"]}],
        "transports": ["in_process"],
        "correlationIdentityFields": ["event.source", "event.id"],
    },
)
...
await hooks.wait()
```

After (0.5):

```python
import anyio
from agenthooksprotocol import Hooks, HostManifestMetadata, capability

config = {
    "protocolVersion": "draft",
    "hooks": [
        {
            "id": "org.example.audit",
            "transport": {"type": "http", "url": "https://hooks.example/ahp"},
            "subscriptions": [
                {
                    "events": ["session.start"],
                    "mode": "observe",
                    "content": {"default": "metadata"},
                }
            ],
        }
    ],
}


async def main() -> None:
    async with Hooks(
        config,
        source="urn:example:harness",
        capabilities=capability.HostCapabilities(session_start=capability.Observe()),
        manifest_metadata=HostManifestMetadata(
            transports=("in_process",),
            correlation_identity_fields=("event.source", "event.id"),
        ),
    ) as hooks:
        assert hooks.manifest["events"] == [
            {"event": "session.start", "modes": ["observe"]}
        ]
        assert hooks.subscribes("session.start")  # static lookup, no I/O
        assert await hooks.wait_observations() == []


anyio.run(main)
```

### `HookResult`

The raw `state` dictionary and the duplicate raw/decoded views were removed.
`result.input` and `result.candidate` now apply the declared `input_codec` /
`result_codec` / `provenance_codec` (without codecs they still return detached
JSON / canonical models).

| 0.4.x | 0.5 |
| --- | --- |
| `result.decision` (`"allow"` by default) | `result.permission` (`Permission.NONE` / `ALLOW` / `ASK` / `DENY`). `NONE` is not approval. |
| `result.effective_input`, `result.decoded_input` | `result.input` |
| `result.decode_input(codec)` | `codec.decode(result.input)`, or pass `input_codec=` to the call |
| `result.decoded_candidate`, `result.schema_candidate` | `result.candidate` |
| `result.raw_candidate` | `result.candidate.to_dict()` (or `None`) |
| `result.decoded_result` | `result.result` (raises `KeyError` when `result.has_result` is `False`) |
| `result.settled_event` | `result.event` (already the typed canonical event) |
| `result.raw_event` | `copy.deepcopy(dict(result.event))` |
| `result.decoded_accepted_responses` | `result.accepted_responses` (typed, in settlement order) |
| `result.accepted_response` | `result.accepted_responses[-1]` when non-empty |
| `result.raw_accepted_response(s)` | `dict(response)` for each entry of `result.accepted_responses` |
| `result.state["flow"]`, `["continuationInstructions"]`, `["continuationRemaining"]` | `result.flow`, `result.instructions`, `result.continuation_remaining` |
| `result.state["messages"]`, `["injections"]`, `["interrupted"]` | `result.messages`, `result.injections`, `result.interrupted` (unchanged) |
| `result.content`, `result.content_references`, `result.decode_content(...)` | Removed. Use `event_codecs={(...path...): codec}` for opaque host slots, and `result.attachments` for owned attachment bodies. |

Before (0.4.x):

```python
if result.decision == "allow":
    command = result.decode_input(ShellCodec())
    log(result.raw_event, result.raw_accepted_responses)
```

The "After" snippet in [Backend servers](#backend-servers) shows the 0.5
`HookResult` attributes in a complete call.

### Effect helpers

The convenience functions and aliases in `agenthooksprotocol.effect` were
removed. Construct the effect model classes, which take the same keyword
arguments. The target-specific helpers (`effect.replace_input`,
`effect.merge_input`, `effect.replace_output`, `effect.merge_prompt`, ...) are
unchanged. In server replies, `hooks.ReplaceInput(value)` and
`hooks.MergeInput(value)` are also available.

| 0.4.x function (aliases) | 0.5 class |
| --- | --- |
| `allow()` | `effect.Allow()` |
| `ask()` | `effect.Ask()` |
| `deny` | `effect.Deny(reason=...)` |
| `message(text=...)` | `effect.Message(text=...)` |
| `continue_flow(...)` (`flow_continue`) | `effect.ContinueFlow(...)` |
| `stop_flow(reason=...)` (`flow_stop`) | `effect.StopFlow(reason=...)` |
| `inject(...)` (`inject_context_append`) | `effect.Inject(deliver_at=..., value=...)` |
| `return_tool(value=...)` (`return_`) | `effect.ReturnTool(value=...)` |
| `return_messages(...)`, `return_text(...)`, `return_elicit_result(...)` | `effect.ReturnMessages(...)`, `effect.ReturnText(...)`, `effect.ReturnElicitResult(...)` |
| `modify_input(...)`, `modify_messages(...)` (`modify`), `modify_text(...)`, `modify_form(...)` (`modify_content`), `modify_workspace(...)` | `effect.ModifyInput(...)`, `effect.ModifyMessages(...)`, `effect.ModifyText(...)`, `effect.ModifyForm(...)`, `effect.ModifyWorkspace(...)` |
| `tool_before_modify(...)`, `tool_after_modify(...)` (`modify_output`), `turn_start_modify(...)` (`modify_prompt`), `context_compact_before_modify(...)` (`modify_instructions`), `context_compact_after_modify(...)` (`modify_summary`), `model_request_before_modify(...)` (`modify_request`), `model_response_after_modify(...)` (`modify_response`), and the other `<event>_modify(...)` functions | `effect.ToolBeforeModify(...)`, `effect.ToolAfterModify(...)`, `effect.TurnStartModify(...)`, `effect.ContextCompactBeforeModify(...)`, `effect.ContextCompactAfterModify(...)`, `effect.ModelRequestBeforeModify(...)`, `effect.ModelResponseAfterModify(...)`, and the matching `effect.<Event>Modify(...)` class |

Before (0.4.x):

```python
effects = [effect.allow(), effect.return_(value={"contents": "Reviewed"})]
```

After (0.5):

```python
from agenthooksprotocol import effect

effects = (
    effect.Allow(),
    effect.ReturnTool(value={"contents": "Reviewed"}),
    effect.replace_input({"path": "reviewed.md"}),
)
assert [item["type"] for item in effects] == ["allow", "return", "modify"]
```

### Backend servers

`server.hooks.Handler` and `server.hooks.InterceptResult` were replaced by
event-specific handler maps, contexts, and replies. `server.asgi.app(...)` was
removed; use `server.asgi.App(...)`. `server.asgi.App` and `server.stdio.serve`
now take `hooks.Handlers`.

| 0.4.x | 0.5 |
| --- | --- |
| `hooks.Handler(intercept=fn, observe=fn)` | `hooks.Handlers(intercept=hooks.InterceptHandlers(tool_before=fn, ...), observe=hooks.ObserveHandlers(tool_before=fn, ...))` |
| `async def intercept(request: InterceptRequest) -> InterceptResult` (one callback for every event) | `def/async def fn(ctx: hooks.<Event>Context) -> hooks.<Event>Reply` per event |
| `async def observe(notification: ObserveNotification) -> None` | `def/async def fn(ctx: hooks.<Event>ObserveContext) -> None` per event |
| `hooks.InterceptResult(effects=[...], extensions=...)` | `hooks.<Event>Reply(effects=(...), extensions=...)`. `effects` is a tuple of generated effect models; plain dictionaries are rejected. |
| `request["params"]["event"]` | `ctx.event` (typed), `ctx.params`, `ctx.envelope`, `ctx.raw` (detached original JSON); intercept contexts also have `ctx.capabilities` and `ctx.state` |
| `asgi.app(handler)` | `asgi.App(handler)` |

An event with no intercept callback answers with JSON-RPC "Method not found".

Before (0.4.x):

```python
from agenthooksprotocol import effect
from agenthooksprotocol.server import asgi, hooks
from agenthooksprotocol.wire import InterceptRequest, ObserveNotification


async def intercept(request: InterceptRequest) -> hooks.InterceptResult:
    return hooks.InterceptResult(
        effects=[effect.replace_input({"command": "echo reviewed"}), effect.Allow()]
    )


async def observe(notification: ObserveNotification) -> None:
    print(notification["params"]["event"]["type"])


app = asgi.app(hooks.Handler(intercept=intercept, observe=observe))
```

After (0.5), including the harness side and the 0.5 `HookResult` attributes:

```python
import anyio
import httpx
from agenthooksprotocol import Hooks, Permission, capability, effect, event, tool
from agenthooksprotocol.server import asgi, hooks
from agenthooksprotocol.transports.http import HTTPTransport

observed: list[str] = []


async def before_tool(ctx: hooks.ToolBeforeContext) -> hooks.ToolBeforeReply:
    return hooks.ToolBeforeReply(
        effects=(hooks.ReplaceInput({"command": "echo reviewed"}), effect.Allow())
    )


def observe_tool(ctx: hooks.ToolBeforeObserveContext) -> None:
    observed.append(ctx.event["type"])


app = asgi.App(
    hooks.Handlers(
        intercept=hooks.InterceptHandlers(tool_before=before_tool),
        observe=hooks.ObserveHandlers(tool_before=observe_tool),
    )
)

config = {
    "protocolVersion": "draft",
    "hooks": [
        {
            "id": "org.example.review",
            "transport": {"type": "http", "url": "http://example.test/hooks"},
            "subscriptions": [
                {
                    "events": ["tool.before"],
                    "mode": "intercept",
                    "timeoutMs": 1000,
                    "failurePolicy": "fail-closed",
                    "content": {"default": "metadata"},
                },
                {
                    "events": ["tool.before"],
                    "mode": "observe",
                    "content": {"default": "metadata"},
                },
            ],
        }
    ],
}


async def main() -> None:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        async with Hooks(
            config,
            source="urn:example:harness",
            capabilities=capability.HostCapabilities(
                tool_before=capability.ToolBeforeCapabilities(
                    intercept=capability.ToolBeforeIntercept(
                        allow=True, modify_input=capability.Modify.REPLACE
                    ),
                    observe=True,
                )
            ),
            transport=HTTPTransport("http://example.test/hooks", client=client),
        ) as harness:
            result = await harness.tool_before(
                event.ToolBeforeInput(
                    call_id="call-1",
                    name="shell",
                    input={"command": "echo original"},
                    path=tool.Path.NATIVE,
                    origin=tool.Origin.NATIVE,
                )
            )
            assert result.permission is Permission.ALLOW  # was result.decision
            assert result.input == {"command": "echo reviewed"}  # was effective_input
            assert result.event["type"] == "tool.before"  # was settled_event
            assert len(result.accepted_responses) == 1  # was accepted_response
            assert result.candidate is None and not result.has_result
    assert observed == ["tool.before"]


anyio.run(main)
```

### Content, diagnostics, and module re-exports

| 0.4.x | 0.5 |
| --- | --- |
| `content.upload(config, data)` | Removed. Remote attachment uploads go through `uploads={backend_id: uploader}` on hook calls (see [Owned attachments](README.md#owned-attachments)). |
| `content.receive(store, headers, data, authorize)` | `await server.attachments.receive(headers, body, authorize=..., storage=...)` or the mountable `server.attachments.App` |
| `content.NoRedirect` | Removed (internal to the removed `content.upload`). |
| `ContentContext(resolve=..., upload=..., attachments=...)` | Removed options, they had no effect. `ContentContext(bindings=..., principal=..., original_request=...)` |
| `ContentSources.edit_context(...)` | Removed (SDK-internal). |
| `agenthooksprotocol._models.content.Receipt` / `UploadReceipt`, `Reference`, `Selection`, `Upload` | `ContentUploadReceipt`, `ContentReference`, `ContentSelection`, `ContentUpload` (same module, or `agenthooksprotocol.generated`) |
| `diagnostics.DiagnosticCode` | `diagnostics.Code` |
| `tool.Input` | `agenthooksprotocol.ExecutionEventTool` |
| `agenthooksprotocol.wire` (alias of `generated`) | `agenthooksprotocol.wire` is now a small module: JSON types, `InterceptRequest`, `InterceptResponse`, `ObserveNotification`, `Event`, `Effect`, and the `parse_*` / `encode_*` codecs. Import everything else from `agenthooksprotocol.generated`. |

After (0.5):

```python
from agenthooksprotocol import ExecutionEventTool, diagnostics, generated, wire
from agenthooksprotocol.server import attachments

assert diagnostics.Code.DEADLINE_EXCEEDED.value == "deadline_exceeded"
assert callable(attachments.receive) and attachments.App is not None
assert generated.ContentUploadReceipt is not None and ExecutionEventTool is not None
assert wire.parse_event is not None
```
