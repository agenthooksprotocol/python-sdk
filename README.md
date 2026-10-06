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

Use `async with` for a bounded lifetime. Each awaited hook call owns its content preparation, delivery, and observations; normal return leaves no detached observation work. Hosts own concurrency through ordinary task groups. `aclose()` stops admission, cancels and joins active owned I/O, releases sources, and reaps owned processes. Repeated/concurrent close is safe; calls after close raise `HooksClosedError`. Await calls before closing if graceful completion is wanted. Injected transports/HTTP clients and shared auth providers remain caller-owned.

```python
import json
from agenthooksprotocol import Hooks, Permission, capability, event, state

with open("hooks.json") as file:
    config = json.load(file)

async def review(existing_arguments):
    async with Hooks(config, source="urn:example:harness", capabilities={
        capability.Event.TOOL_BEFORE: capability.intercept().allow().deny().modify_input(replace=True),
    }) as hooks:
        result = await hooks.tool_before(event.ToolBeforeInput(
            call_id="call-1", name="read_file", input=existing_arguments,
            path="native", origin="native",
        ), initial_state=state.initial(Permission.NONE))
        return result  # Host validation and authorization still precede execution.
```

Generated `Input` objects are distinct from canonical wire events. They flatten only protocol-owned wrappers, never application arguments, and `to_wire()` performs the shared mapping. `path` and `origin` remain separate required facts. Optional host IDs, timestamps, parent IDs, and other facts are retained; `event_id=` overrides an input ID. The SDK supplies type/source and the configured session manifest. Low-level `dispatch` still accepts canonical dictionaries.

Capability builders are immutable: reusing a base declaration does not widen it. `intercept()` deliberately advertises **both intercept and observe**; `observe()` is observation-only. `modify_input(replace=True)` supplies both the effect grant and operation block. Empty operations and observation effect grants are rejected; boundary compatibility is validated before delivery. Form and URL elicitation grants are explicit (`elicitation_form()` / `elicitation_url()`). Raw manifests retain their exact modes; omission never implies permission. Per-call `capabilities=` only narrows configured grants.

Runnable, statically checked consumer programs live in [`examples/`](examples):

- `typed_tool.py`: JSON registration, generated tool input, typed grants, initial state, real in-process ASGI handler, borrowed HTTP client, and explicit application decoding.
- `common_cases.py`: rewrite/allow, deny, invalid application shape, host policy, occurrence narrowing, native initial state, and fail-open/fail-closed reports. The host operation is an in-memory execution recorder, not a shell.
- `stdio_tool.py` / `stdio_backend.py`: a real owned backend process using the same public Handler, denial, and child cleanup.
- `upload.py`: streamed binary upload, metadata no-read behavior, independent upload credentials, verified descriptor, and caller-owned immutable storage.

- `lifecycle.py`: caller-owned task groups, operation-owned observations, interrupted requests, idempotent close, and proof that an owned subprocess was reaped.
- `http_auth.py`: real loopback HTTP, canonical backend callbacks, registration `tokenEnv` resolution, and separate content-upload authorization. Its standard-library HTTP routing is example host code, not a production server.

Run them with `uv run python examples/<name>.py`; `uv run mypy` checks the actual public imports and signatures. These examples do not claim an all-pairs cross-language matrix.

## Protocol admission and application input

Generated constructors build JSON-shaped protocol values. Generated `TypedDict` models provide static typing, **not runtime validation**. Structural `parse_*` codecs preserve unknown properties and values; they do not insert defaults, coerce values, or establish permission to execute an operation. Canonical validation and whole-response effect admission remain separate from application-specific input validation.

Capabilities explicitly grant effects and target operations. Supply event capabilities at harness construction; a per-occurrence capability override can narrow them, never widen them. `initial_state` carries the host's native prior decision for one occurrence. A hook-supplied result is a candidate, not an assertion that an operation executed. The host owns its ordinary input validation and actual execution.

After settlement, explicitly decode effective input with `result.decode_input(codec)`. A codec implements `encode(value)` and `decode(json_value)`; `IdentityCodec` copies JSON. The optional `integrations.pydantic.PydanticCodec` accepts a Pydantic `TypeAdapter`. A decoding error does not retroactively reject protocol effects: retain the settled result, raw effective input, accepted responses, and diagnostics, and report host-level rejection without executing.

`result.permission` is the generated `Permission` enum (`NONE`, `ALLOW`, `ASK`, `DENY`) read from canonical settlement, not an independent decision engine. `NONE` is not approval; `ASK` needs host approval; interruption never authorizes execution. `result.input` is detached accepted JSON, not a claim that backend modifications satisfy an application's original type. `decode_input(codec)` remains an explicit, post-settlement host check. Candidate, canonical event, accepted responses, and diagnostics remain accessible.

`state.initial(Permission.ALLOW)` represents a native decision **already made for this exact occurrence**, not an authorization shortcut. Its default candidate is absent (`null`); `state.Candidate(value=None)` instead means a supplied JSON-null result. Optional typed provenance records facts, not authenticated identity or execution proof. Canonical modifications still invalidate candidates/approval as specified.

Generated backend helpers such as `effect.deny(reason="policy")`, `effect.replace_input(new_args)` and `effect.merge_input(changes)`, and `effect.Return(value=...)` fill discriminants and return canonical effect models. They cannot grant themselves authority: unsupported compound responses are rejected atomically.

### Diagnostics and one call budget

`result.diagnostics` contains generated `diagnostics.Code` values with backend, subscription index, delivery mode, stage, failure policy, and synthetic-denial evidence. Timeout (`deadline_exceeded`), transport failure, validated remote JSON-RPC error (`remote_rpc`), protocol rejection, and content preparation remain distinct. Diagnostics never include backend error messages/data or credentials. Observation failure cannot reopen settlement. Application decode errors and operation exceptions are not recoverable delivery diagnostics.

Use one native deadline scope around the whole operation:

```python
import anyio

with anyio.fail_after(5):
    result = await hooks.tool_before(input)
```

The same remaining budget covers queue/readiness waits, provider waits, selected stream reads/uploads, safe auth retries, interception, and owned observations. Subscription timeouts can shorten it, never reset it. Outer timeout raises `TimeoutError`; explicit task cancellation propagates the native cancellation exception. No partial result is presented as permission to execute. Source/process safety cleanup can extend return beyond the deadline; it is not normal observer processing. Hosts may background the **whole call**, retain its task handle, and await its decision before acting.

### Registration-aware credentials

`Hooks(..., auth_provider=provider)` borrows one provider implementing asynchronous `credential(context)` and `challenge(context, challenge)`. It returns `auth.BearerCredential(token, identity=opaque_attempt_id)` or no credential for an anonymous binding. Context includes the complete selected backend and binding, destination, event/upload purpose, and native cancellation scope. Challenges contain actual status/headers and attempted credential identity, never secret tokens. The harness owns discovery/trust, consent, token exchange/refresh, rotation, caching, and provider lifetime; no SDK OAuth manager or browser worker is required.

The default `auth.EnvironmentAuthProvider` resolves bearer `tokenEnv` or optional `resolve_credential` tokenRef callbacks at delivery time. OAuth bindings require an explicit provider. Missing configured secrets and unsupported mechanisms fail closed. Anonymous success stays anonymous; an explicit provider can authorize challenge discovery under host trust policy. Interception may replay at most once after an eligible 401 Bearer challenge, retaining request identity and serialized body; observations/uploads are never automatically replayed. Upload bindings are independent: event credentials are never an upload fallback. Transport-owned TLS/workload integration is not replaced by this provider.

## Static host manifest

Configure `Hooks(config, *, source, manifest=full_manifest, transport=None, auth_provider=None)` with a complete canonical static manifest, **or** use the existing `capabilities=event_declarations` option. These options are mutually exclusive. The full manifest supplies the same event/mode/effect authority used for admission; it is not backend discovery. `hooks.manifest` returns a detached snapshot.

The event-map shorthand advertises only explicitly declared events and modes. Its derived manifest records a gap for every omitted canonical event and for host-level facilities that the map cannot establish (transports, authentication, tool paths, content categories, limits, and managed policy). Empty lists do not mean universal support. Use a full manifest to declare those facilities accurately; explicit full manifests are preserved rather than augmented with assumed support.

`await hooks.session_start(event.SessionStartInput(session=..., trigger="startup", harness=..., permission_mode="default", items=[]))` needs only occurrence-specific host facts. The SDK supplies `manifest`, `type`, and `source`, and supplies `id`/`time` when absent; `event_id=` takes precedence over a supplied ID. Caller payload fields cannot override the configured type, source, or manifest. Configuration, manifest snapshots, and delivered occurrences are independent copies. See [`examples/session_manifest.py`](examples/session_manifest.py) for a runnable, typechecked receiver example.

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

### Lazy owned sources

`OwnedContentSource(stream, max_bytes=..., timeout=...)` wraps an async native `read(size)`/`receive(size)` stream with `aclose()`. Construction does not read. Size/hash expectations are optional and verified, not trusted. Generated inputs expose named `bind_<slot>_source(source)` methods; repeated content slots additionally require `index=`. For example, `input.bind_items_source(source, index=0)` binds an existing metadata item without putting the stream into wire JSON.

Pass the bound input to a named hook method with `uploads={backend_id: authorized_upload_callback}`. Each callback receives immutable bytes and returns a receiver-allocated canonical content reference; it can use `auth.AuthenticatedHTTPTransport.upload(..., authentication=upload_binding)`. Metadata, omit, and unmatched receivers consume no bytes and require no uploader. Selected body delivery snapshots once within limits, hashes actual raw bytes, uploads independently for each authorized destination, and verifies references before event delivery. Missing receiver authorization fails before reading. Source bindings derive from shared generated metadata; advanced `ContentSources` and existing canonical references/resolvers remain available.

Ownership transfers to the source wrapper, then to the hook operation when passed. Streams close on success, failure, cancellation, and unused selection; snapshots release when the call finishes. Sources are single-operation values, not concurrently reusable. Call `aclose()` or use an async context manager for a source that never reaches a hook call. Cleanup is shielded and bounded separately from the operation budget.

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
