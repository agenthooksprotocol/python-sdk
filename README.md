# Agent Hooks Protocol SDK for Python

A typed, asynchronous SDK for the [Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol) draft. Python 3.11+; AnyIO supports asyncio and Trio. The import package is **`agenthooksprotocol`**, and the primary harness is **`Hooks`**.

## Install

The distribution name is `agenthooksprotocol`. Until the first PyPI release, install a pinned Git commit:

```sh
python -m pip install 'agenthooksprotocol[http] @ git+https://github.com/agenthooksprotocol/python-sdk.git@<commit-sha>'
```

HTTPX is an opt-in dependency (`[http]`). Pydantic is an independent opt-in integration (`[pydantic]`); neither a web framework nor Pydantic is needed for the core SDK or stdio.

## Harness ownership

Read trusted registration JSON with the standard library and construct `Hooks` from the resulting dictionary. Registration validation occurs at construction; each asynchronous boundary ensures readiness. There is no mandatory separate initialization call or special configuration-file loader. Registration can launch processes: **do not load untrusted registrations**.

Use `async with` for a bounded lifetime. Owned processes, observation work, and uploads belong to that lifetime. Injected HTTP clients remain caller-owned. Event-delivery credentials and content-upload credentials have separate scopes; redirects must not forward either authority.

```python
import json
from agenthooksprotocol import Hooks, capability, event, tool

with open("hooks.json") as file:
    config = json.load(file)

async def review(existing_arguments):
    async with Hooks(config, source="urn:example:harness", capabilities={
        "tool.before": capability.Declaration(
            modes=[capability.Mode.INTERCEPT],
            grants=[capability.Allow(), capability.Deny(),
                    capability.ModifyInput(replace=True)],
        ),
    }) as hooks:
        result = await hooks.tool_before(event.ToolBeforeInput(
            call=tool.Call(id="call-1"),
            path=tool.Path.NATIVE,
            tool=tool.Tool(name="read_file", origin=tool.Origin.NATIVE,
                           input=existing_arguments),
        ), initial_state={"permission": "allow", "candidate": None})
        return result  # The host validates effective input and decides execution.
```

Canonical dictionaries are accepted alongside generated declarations. `ModifyInput(replace=True)` grants the `modify` effect and the input-replace operation together; it does not grant merge, other targets, or delivery modes. Form and URL elicitation grants are separate and explicit.

Runnable, statically checked consumer programs live in [`examples/`](examples):

- `typed_tool.py`: JSON registration, generated tool input, typed grants, initial state, real in-process ASGI handler, borrowed HTTP client, and explicit application decoding.
- `common_cases.py`: rewrite/allow, deny, invalid application shape, host policy, occurrence narrowing, native initial state, and fail-open/fail-closed reports. The host operation is an in-memory execution recorder, not a shell.
- `stdio_tool.py` / `stdio_backend.py`: a real owned backend process using the same public Handler, denial, and child cleanup.
- `upload.py`: streamed binary upload, metadata no-read behavior, independent upload credentials, verified descriptor, and caller-owned immutable storage.

- `lifecycle.py`: observation dispatch without blocking settlement, explicit waiting, interrupted requests, idempotent close, and proof that an owned subprocess was reaped.
- `http_auth.py`: real loopback HTTP, canonical backend callbacks, registration `tokenEnv` resolution, and separate content-upload authorization. Its standard-library HTTP routing is example host code, not a production server.

Run them with `uv run python examples/<name>.py`; `uv run mypy` checks the actual public imports and signatures. These examples do not claim an all-pairs cross-language matrix.

## Protocol admission and application input

Generated constructors build JSON-shaped protocol values. Generated `TypedDict` models provide static typing, **not runtime validation**. Structural `parse_*` codecs preserve unknown properties and values; they do not insert defaults, coerce values, or establish permission to execute an operation. Canonical validation and whole-response effect admission remain separate from application-specific input validation.

Capabilities explicitly grant effects and target operations. Supply event capabilities at harness construction; a per-occurrence capability override can narrow them, never widen them. `initial_state` carries the host's native prior decision for one occurrence. A hook-supplied result is a candidate, not an assertion that an operation executed. The host owns its ordinary input validation and actual execution.

After settlement, explicitly decode effective input with `result.decode_input(codec)`. A codec implements `encode(value)` and `decode(json_value)`; `IdentityCodec` copies JSON. The optional `integrations.pydantic.PydanticCodec` accepts a Pydantic `TypeAdapter`. A decoding error does not retroactively reject protocol effects: retain the settled result, raw effective input, accepted responses, and diagnostics, and report host-level rejection without executing.

## Backend servers

`from agenthooksprotocol.server import hooks` exposes the small `hooks.Handler(intercept=..., observe=...)` callback surface and `hooks.InterceptResult`. Both callbacks are asynchronous and receive canonical generated protocol requests. The same protocol dispatcher serves stdio and the framework-neutral ASGI adapter. ASGI does not require Starlette or FastAPI.

Observation is one-way. It does not acquire effect authority and never waits for an acknowledgement. An optional static **harness** manifest can expose `hooks/capabilities`; backend callbacks are not capability discovery and do not manufacture grants.

The attachment receiver verifies byte length and digest through EOF before committing caller-provided immutable storage. Receiver-allocated references are published only after authorization and successful storage commit. Applications choose storage durability and retention.

## Body-bound boundaries

Use `ContentContext` for MCP elicitation and compaction bodies. Its asynchronous `resolve(reference)` and `upload(bytes)` functions are trusted storage/transport adapters, not application-schema callbacks. `upload` must return a verified receiver-allocated immutable descriptor after storage commit. The SDK verifies referenced bytes and replacement descriptors before publishing an accepted state.

Bindings are explicit paths within the canonical event:

| Boundary | Binding |
| --- | --- |
| `user_elicitation_request` | `{"request": ("elicitation", "request")}` |
| `user_elicitation_result` | `{"content": ("elicitation", "result")}` plus `original_request` |
| `context_compact_before` | `{"instructions": ("instructions",)}` |
| `context_compact_after` | `{"summary": ("summary",)}` |

Pass `content=context` to the named boundary. An elicitation result needs the original canonical request snapshot; the SDK does not fabricate correlation, form/URL support, or MCP defaults. Metadata and omitted selections do not read body bytes. Changed bodies receive new immutable references, and a changed compaction input invalidates an earlier supplied summary.

For custom transport integrations, `begin(canonical_request)` returns a `PendingInvocation` with separate acquisition, cancellation, and acceptance. `exchange(canonical_request)` uses the same settlement engine. Content-aware pending invocations use `await accept_content()`; this keeps upload completion and cancellation inside the publication boundary. The ordinary named-method path does this automatically.

## Generated models and provenance

Semantic namespaces (`event`, `tool`, `effect`, `capability`, and registration models) and all named event boundaries come from schema metadata, not a selected handwritten helper list. Constructors may supply fixed protocol literals; parsers never repair missing input. Open fields are retained for forward-compatible JSON round trips.

The low-level `generated` module exports the full schema's typed models, `parse_<root>` / `encode_<root>` codecs, `PROTOCOL_VERSION`, `SCHEMA_REVISION`, and JSON types. `ahp-codegen.lock.json` records immutable generator provenance. Change canonical schemas and generator source in the protocol repository rather than editing generated files.

## Development

```sh
uv sync --group dev --extra http --extra pydantic
uv run python -m unittest discover -s tests
uv run mypy
uv run python -m build
```

Integration tests also use a matching sibling `../agent-hooks-protocol` checkout for shared fixtures and public synthetic certificates. The installed runtime uses its bundled schemas and does not need that checkout. No SDK API executes host tools on your behalf.
