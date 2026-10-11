# Agent Hooks Protocol SDK for Python

A typed, asynchronous SDK for the [Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol) draft. Python 3.11+; AnyIO supports asyncio and Trio. The import package is **`agenthooksprotocol`**, and the primary harness is **`Hooks`**.

## Install

Install the published `agenthooksprotocol` package from [PyPI](https://pypi.org/project/agenthooksprotocol/):

```sh
python -m pip install 'agenthooksprotocol[http]'
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

Generated `Input` objects are distinct from canonical wire events. They flatten only protocol-owned wrappers, never application arguments, and `to_wire()` performs the shared mapping. `path` and `origin` remain separate required facts. Optional host IDs, timestamps, parent IDs, and other facts are retained; `event_id=` overrides an input ID. The SDK supplies type/source and the configured session manifest. Low-level `dispatch` accepts canonical dictionaries.

Capability builders are immutable: reusing a base declaration does not widen it. `intercept()` deliberately advertises **both intercept and observe**; `observe()` is observation-only. `modify_input(replace=True)` supplies both the effect grant and operation block. Empty operations and observation effect grants are rejected; boundary compatibility is validated before delivery. Form and URL elicitation grants are explicit (`elicitation_form()` / `elicitation_url()`). Raw manifests retain their exact modes; omission never implies permission. Per-call `capabilities=` only narrows configured grants.

Runnable, statically checked consumer programs live in [`examples/`](examples):

- `value_codecs.py`: independent argument/result/provenance codecs, admission-time invariants, and a form schema derived from its answer type.
- `typed_tool.py`: JSON registration, generated tool input, typed grants, initial state, real in-process ASGI handler, borrowed HTTP client, and explicit application decoding.
- `common_cases.py`: rewrite/allow, deny, invalid application shape, host policy, occurrence narrowing, native initial state, and fail-open/fail-closed reports. The host operation is an in-memory execution recorder, not a shell.
- `stdio_tool.py` / `stdio_backend.py`: a real owned backend process using the same public Handler, denial, and child cleanup.
- `upload.py`: streamed binary upload, metadata no-read behavior, independent upload credentials, verified upload receipt, and caller-owned immutable storage.

- `lifecycle.py`: caller-owned task groups, operation-owned observations, interrupted requests, idempotent close, and proof that an owned subprocess was reaped.
- `http_auth.py`: real loopback HTTP, canonical backend callbacks, registration `tokenEnv` resolution, and separate content-upload authorization. Its standard-library HTTP routing is example host code, not a production server.

Run them with `uv run python examples/<name>.py`; `uv run mypy` checks the actual public imports and signatures. These examples do not claim an all-pairs cross-language matrix.

## Protocol admission and application input

Generated constructors build JSON-shaped protocol values. Generated `TypedDict` models provide static typing, **not runtime validation**. Structural `parse_*` codecs preserve unknown properties and values; they do not insert defaults, coerce values, or establish permission to execute an operation. Canonical validation and whole-response effect admission remain separate from application-specific input validation.

Capabilities explicitly grant effects and target operations. Supply event capabilities at harness construction; a per-occurrence capability override can narrow them, never widen them. `initial_state` carries the host's native prior decision for one occurrence. A hook-supplied result is a candidate, not an assertion that an operation executed. The host owns its ordinary input validation and actual execution.

Supply `input_codec=`, `result_codec=`, and optional `provenance_codec=` to a named hook method or `dispatch` to declare caller types. Complete staged values are decoded and validated before publication. Object merge is shallow: omitted fields remain unchanged, literal null is retained, and nested values replace whole values. An invalid response publishes none of its effects; earlier accepted responses remain visible to later interceptors. A codec must preserve the wire data it receives, including opaque extra fields. Lossy serialization rejects admission rather than dropping fields.

`result.decoded_input` exposes the declared argument value. `result.decoded_candidate` is an application `Candidate[Result, Provenance]`, or `None` when there is no candidate. Its value can itself be `None`; optional provenance is omitted from `candidate.to_dict()` when absent. Raw `input` and `candidate` views remain detached snapshots. For explicitly selected opaque host slots, use `event_codecs={("params",): codec}` with event-relative paths. Unspecified native, provider, task, permission, and discovery values are not interpreted.

For forms, construct `PydanticFormContract(TypeAdapter(Answer))` from one answer declaration. `request(message)` derives the restricted MCP schema; `result_codec()` decodes the complete MCP result and its accepted answer while preserving opaque result metadata. Unsupported shapes and schema constraints are rejected during construction. Decline, cancel, and URL results have no form content. See [`examples/value_codecs.py`](examples/value_codecs.py).

After settlement, explicitly decode effective input with `result.decode_input(codec)`. A codec implements `encode(value)` and `decode(json_value)`; `IdentityCodec` copies JSON. The optional `integrations.pydantic.PydanticCodec` accepts a Pydantic `TypeAdapter`. A decoding error does not retroactively reject protocol effects: retain the settled result, raw effective input, accepted responses, and diagnostics, and report host-level rejection without executing.

`result.permission` is the generated `Permission` enum (`NONE`, `ALLOW`, `ASK`, `DENY`) read from canonical settlement, not an independent decision engine. `NONE` is not approval; `ASK` needs host approval; interruption never authorizes execution. `result.input` is detached accepted JSON. Declared codecs validate accepted modifications; without a declared codec, the host supplies application validation. `decode_input(codec)` remains an explicit, post-settlement host check. Candidate, canonical event, accepted responses, and diagnostics remain accessible.

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

Configure `Hooks(config, *, source, manifest=full_manifest, transport=None, auth_provider=None)` with a complete canonical static manifest, **or** use `capabilities=event_declarations`. These options are mutually exclusive. The full manifest supplies the same event/mode/effect authority used for admission; it is not backend discovery. `hooks.manifest` returns a detached snapshot.

The event-map shorthand advertises only explicitly declared events and modes. Its derived manifest records a gap for every omitted canonical event and for host-level facilities that the map cannot establish (transports, authentication, tool paths, content categories, limits, and managed policy). Empty lists do not mean universal support. Use a full manifest to declare those facilities accurately; explicit full manifests are preserved rather than augmented with assumed support.

`await hooks.session_start(event.SessionStartInput(session=..., trigger="startup", harness=..., permission_mode="default", items=[]))` needs only occurrence-specific host facts. The SDK supplies `manifest`, `type`, and `source`, and supplies `id`/`time` when absent; `event_id=` takes precedence over a supplied ID. Caller payload fields cannot override the configured type, source, or manifest. Configuration, manifest snapshots, and delivered occurrences are independent copies. See [`examples/session_manifest.py`](examples/session_manifest.py) for a runnable, typechecked receiver example.

## Backend servers

`from agenthooksprotocol.server import hooks` exposes the small `hooks.Handler(intercept=..., observe=...)` callback surface and `hooks.InterceptResult`. Both callbacks are asynchronous and receive canonical generated protocol requests. The same protocol dispatcher serves stdio and the framework-neutral ASGI adapter. ASGI does not require Starlette or FastAPI.

Observation is one-way. It does not acquire effect authority and never waits for an acknowledgement. An optional static **harness** manifest can expose `hooks/capabilities`; backend callbacks are not capability discovery and do not manufacture grants.

The attachment receiver verifies byte length and digest through EOF before committing caller-provided immutable storage. Receiver-allocated references are published only after authorization and successful storage commit. Applications choose storage durability and retention.

## Inline messages and specialized boundaries

Model-visible inputs contain canonical messages with a `role` and ordered
`parts`. Supported roles are `system`, `developer`, `user`, `assistant`, and
`tool`. A text part has `kind="text"`, `mediaType="text/plain"`, and inline
`text`. Serialized JSON is ordinary text. An attachment part has
`kind="attachment"`, a non-text/non-JSON media type, and an immutable binary
body. Construction supplies missing message/part IDs and marks them
`synthesized=True`; explicit IDs remain stable.

```python
from agenthooksprotocol import Attachment

input = {
    "trigger": "manual",
    "items": [{"role": "user", "parts": [
        {"kind": "text", "text": "Review this report."},
        {"kind": "attachment", "mediaType": "application/pdf",
         "body": Attachment.from_bytes(pdf_bytes)},
    ]}],
}
result = await hooks.context_compact_before(input, uploads=authorized_uploads)
async with result:
    data = await result.attachments.read("context.compact.before.items_parts[0][1]")
```

Named hook methods also accept canonical dictionaries with the same direct
attachment bodies. The runtime collects sources and creates receiver-specific
references internally. Construction and metadata/omit projection do not read
or upload attachments. Only schema-owned slots are projected; native payloads,
extensions, and application arguments are opaque. Selection is a ceiling for
each receiver's view: metadata/omit views contain no inline text or attachment
references. Independent receivers apply their own content selections.

Compaction `instructions` and `summary` are canonical text-part lists.
Replacement substitutes the list; merge appends in order. Model-visible message
list targets (`prompt`, `request`, `response`, and tool `output`) have the same
list operations. Tool output edits operate on `tool.after.items`; application
structures are serialized as text parts. Standalone `content` edits require the
boundary context: `user.message.outbound` uses a message list, and accepted form
answers at `user.elicitation.result` use an MCP answer object. Object targets such as tool input and workspace changes use shallow object merge. A response settles
atomically, and each serial receiver sees the committed state. Changed
compaction instructions invalidate an earlier supplied summary.

MCP elicitation `request` and `result` contain selected text parts whose `text`
is the serialized complete MCP JSON payload. The SDK validates parsed payloads,
mode grants, form answers, and correlation without inserting defaults. Result
edits require `original_request=` with the original canonical intercept request
snapshot; answer-object merge is shallow. Elicitation request bodies are immutable
to modification effects. No text/JSON upload callback is needed. Metadata and omit selections
cannot authorize body-dependent effects.

For custom transports, `begin(canonical_request, value_codecs=ValueCodecs(...))` separates acquisition,
cancellation, and acceptance; `exchange(canonical_request)` uses the same
settlement engine. Elicitation correlation can be supplied through
`ContentContext(original_request=..., bindings={"content": ("elicitation", "result")},
principal=authenticated_identity)` and `await pending.accept_content()`.

## Generated models and provenance

Semantic namespaces (`event`, `tool`, `effect`, `capability`, and registration models) and all named event boundaries come from schema metadata, not a selected handwritten helper list. Constructors may supply fixed protocol literals; parsers never repair missing input. Open fields are retained for forward-compatible JSON round trips.

The `wire` namespace exposes canonical JSON-shaped request, notification, effect, and response types with structural codecs. Server callbacks use these raw wire contracts. The low-level `generated` module exports the full schema's typed models, `parse_<root>` / `encode_<root>` codecs, `PROTOCOL_VERSION`, `SCHEMA_REVISION`, and JSON types. `ahp-codegen.lock.json` records immutable generator provenance. Change canonical schemas and generator source in the protocol repository rather than editing generated files.

## Development

```sh
uv sync --group dev --extra http --extra pydantic
uv run python -m unittest discover -s tests
uv run mypy
uv run python -m build
```

Integration tests also use a matching sibling `../agent-hooks-protocol` checkout for shared fixtures and public synthetic certificates. The installed runtime uses its bundled schemas and does not need that checkout. No SDK API executes host tools on your behalf.

### Typed composed payloads

Generated facade constructors retain nested model types through schema
compositions. MCP connection `gaps` parameters accept lists of typed gap models,
and HTTP, SSE, stdio, and custom connection objects expose typed location and gap
attributes. `ModelVisibleItem` is a canonical message with a typed role and ordered parts.

Facade objects are mappings with read-only attributes.
Optional attributes return `None` when absent; mapping membership still records
presence. Omitted and explicit-empty response effects are both neutral; decoded effects provide an empty list without modifying the source wire object. Attributes conflicting with mapping methods use a trailing underscore
(such as `items_`), so `dict.items()` keeps working. Raw wire parsers return lossless mappings. `response.response_for_request(event_type, raw)` returns the generated contextual response selected by the originating event type, not by payload shape.

Use generated nested models for typed constructor arguments. Wire constructors, dictionary decoding, and runtime parsing
check location/evidence alternatives and other structural schema constraints. Application
JSON, native payloads, and extension values remain intentionally dynamic.

Upload receipts and event references are distinct. To attach a successful upload,
use `content.reference(receipt)` (or `{"ref": receipt["ref"]}`). Never attach the
receipt itself: body-selected content carries only the ref, with no outer `size`
or `sha256`. Metadata-only content and body gaps may still disclose size/digest.

### Structural model decoding and effect-family support

```python
from agenthooksprotocol import ContentReference, capability, effect

caps = capability.Capabilities.from_dict({"effects": ["deny", "vendor.custom"]})
assert caps.supports(capability.EffectName.DENY)
assert caps.supports("vendor.custom")
assert effect.EffectName is capability.EffectName
reference = ContentReference.from_dict({"ref": "opaque", "vendor": {"version": 2}})
```

`supports(effect)` is available on generic and incoming capability models. It
checks the advertised `effects` list only. Nested grants do not imply family
support. The result is **not authorization**: it does not check target, operation,
mode, contextual restrictions, or permission. `EffectName` contains schema-derived
known identifiers; custom family identifiers remain ordinary strings.

Wire-model keyword constructors and `Model.from_dict(mapping)` validate with
the same structural descriptor engine as generated `parse_*` functions. The
original composition is retained, including required members, explicit nulls,
literals, closed enums, forbidden combinations, and union ambiguity. This is the
SDK's structural contract, not complete contextual protocol validation.
`from_dict` checks complete wire values and preserves optional-field presence. Decoded known nested values expose the same attributes as constructed values, such as `connection.gaps[0].reason`. Extension and application bags remain intact and do not acquire effect or attachment authority.

Invalid wire models raise `ValueError`; validation failures carry `result`,
`diagnostics`, and `raw` attributes. Use `parse_*` when you need the full result on
both success and failure, including unknown-variant warnings and lossless raw
values. Open extension values remain intact. Finite `Decimal` values are retained;
non-finite numbers and non-JSON values are rejected. Parsing raw JSON through
`parse_*` retains decimal precision; decoding it first with standard-library
`json.loads` cannot recover precision already lost to a float.

Provide valid enum/literal values and all required wire members to `from_dict`. A null candidate, a candidate with
`{"value": null}`, and a candidate with `{"value": 0}` remain distinct; omitting a
required candidate is an error. Generated input projections and capability grant
builders are construction helpers, not wire decode entrypoints; their final wire
objects are validated at the dispatch/parse boundary. Direct dictionary
mutation, standard-library `json.loads`, TypedDict annotations, and type assertions
are not SDK validation entrypoints. Re-parse after manually mutating a mapping.

Nested model attributes expose declared protocol fields. For example, `capability.Capabilities(effects=["modify"], modify={}).modify.input` is `None` when that grant is absent. Family queries are available on generic and per-occurrence capability models.

Constructor aliases cannot silently overwrite wire keys. Supplying both
`tool_name=` and `toolName=` raises `TypeError`, even if the values agree. For
optional/defaulted fields, a lone wire spelling (for example `addressForm=` or
`protocolVersion=`) is used and validated rather than replaced by a default.
Required constructor parameters use their documented Python spelling;
use `from_dict` to decode complete wire-keyed objects. In `from_dict`, distinct
keys such as `toolName` and `tool_name` remain distinct wire/extension keys.

### Owned attachments

Use `Attachment.from_bytes(data)` for immutable Python `bytes`, or
`Attachment.lazy(async_loader, aclose=async_cleanup)` to defer reading. Put
`attachment` directly in an attachment part's `body`. Named `Hooks` methods
accept both dictionary inputs and typed event inputs with the same owner.
For a custom `OwnedContentSource`, use the host-only `content.OwnedAttachment(source)` wrapper in an attachment part's body. This wrapper does not read the source and is not a wire value. The SDK transfers and closes its source under the same invocation ownership rules.

Metadata belongs on the part. See the runnable
[file attachment example](examples/file_attachment.py).

Dispatch transfers ownership once. Successful results retain the exact owner,
including an unread loader, independently of `Hooks` shutdown. Callers close
returned content owners with `async with result:` or `await result.aclose()`.
Cleanup runs for unopened sources too. Create a new attachment for each
invocation; eager attachments can share the same immutable `bytes` object.

The default accepted size is 4 MiB and lazy loading timeout is 30 seconds.
Constructors accept `max_bytes`; lazy construction accepts `timeout`. Loaders
must bound their own allocations. `Attachment(async_stream, ...)` supports
bounded `read(size)`/`receive(max_bytes)` streams. Stream cleanup is shielded and
bounded to one second. Cancellation and failure never retry a loader. Mutable
buffers are rejected, and reads return immutable bytes.

Selected remote binary delivery requires an authorized uploader through
`uploads={backend_id: async_upload}`. Each uploader receives the exact owner's
immutable bytes and returns a committed receipt with `ref`, `size`, and `sha256`.
The SDK validates the receipt against the actual bytes before sending the event.
Upload callbacks remain caller-authorized and scoped to their backend; event
credentials do not authorize uploads to another destination.

`Hooks(..., max_concurrent_uploads=8)` bounds concurrent binary uploads.
The value must be a positive integer. Before serial interception
begins, the SDK prepares uploads for body-selected attachment slots in all
matched subscriptions, including observers. One attachment owner is read once
for multiple subscribers. Metadata, omit, and unmatched selections do not read
or upload its bytes. Result reads and metadata-only delivery require no uploader.

Only confirmed receipts are reused, for the exact attachment owner and backend
ID/subscription index. An uncalled interceptor receives a settled observation
with its confirmed reference after denial or stop. Upload failures are handled by
the affected subscription's failure policy when its delivery is reached; they
do not prevent independent destinations from preparing their uploads. An upload
can commit even if an earlier interceptor later removes the attachment or halts
the chain. Receiver applications manage separate storage durability and retention.
Cancellation cancels and joins pending upload work and closes invocation-owned
sources. Overlapping reads join one materialization and receive the same immutable
bytes or terminal error. Cancelling one reader leaves materialization active for
other readers; the last cancelled reader or owner closure cancels and joins it.
The attachment owns its single pending materialization independently of readers.
A cancelled reader returns and releases its upload permit while another reader
continues. The last reader or owner closure joins cleanup; completed workers are
not retained.

Attachments are the sole byte owners. Binary/file editing is not supported.
Results are invocation-local, not session archives.

### Advanced validation and dispatch

`runtime.Validator` validates bundled canonical schemas and structural codecs. It does not establish request correlation, effect grants, host approval, or permission to execute. Use `Hooks` for complete interception admission.

`server.hooks.Engine` is the framework-neutral backend dispatcher. Supply an explicit validator or static harness manifest when needed. Engine callbacks return protocol effects; the receiving harness validates authority and settles them atomically.

Host session counters (`turns`, `modelRequests`, `toolCalls`, `inputTokens`, `outputTokens`, and extra counter names) are exact nonnegative integers. The SDK preserves supplied values and does not infer counters from events.
