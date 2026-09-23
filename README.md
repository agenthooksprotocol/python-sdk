# Agent Hooks Protocol SDK for Python

The active draft also provides MCP-aligned elicitation, automatic short-circuit
observation delivery, and before/after compaction controls. See the shared
[boundary API guide](https://github.com/agenthooksprotocol/agent-hooks-protocol/blob/main/docs/accepted-boundary-apis.md)
for entrypoints, upload binding, trusted-host obligations, and test scope.

Typed Python models and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The SDK follows the current AHP `draft` schema snapshot and requires Python 3.11 or newer.

## Installation

The package is not yet published to PyPI. Until the first release, pin it directly from GitHub:

```sh
python -m pip install \
  "agent-hooks-protocol @ git+https://github.com/agenthooksprotocol/python-sdk.git@main"
```

For reproducible builds, replace `main` with a commit SHA.

## Quick start

Every public AHP schema has a typed model, a `parse_*` function, and an `encode_*` function.

```python
from agent_hooks_protocol.generated import (
    encode_capabilities,
    parse_capabilities,
)

result = parse_capabilities(
    '{"effects":["deny"],"com.example.preview":true}'
)

if not result["ok"]:
    raise ValueError(result["diagnostics"])

capabilities = result["value"]
print(capabilities["effects"])

encoded = encode_capabilities(capabilities)
```

Parsers accept either JSON text or an already-decoded JSON value. Successful results contain:

- `value`: the typed model
- `raw`: the preserved JSON value
- `diagnostics`: compatibility warnings, such as an unknown enum value

Failed results contain structural diagnostics with a JSON Pointer `path`, machine-readable `code`, `severity`, and message.

## API

The generated module exports:

- `SCHEMA_REVISION` and `PROTOCOL_VERSION`
- typed models for registrations, JSON-RPC messages, hook events, requests, responses, capabilities, and effects
- `parse_<root>(input)` for structural parsing
- `encode_<root>(value)` for JSON encoding
- `ParseResult`, `ParseDiagnostic`, and JSON value aliases

Unknown object fields and unknown discriminator or enum values are retained for forward compatibility. JSON numbers are decoded without losing decimal precision. Parsers do not coerce values, insert defaults, or discard extension data.

## Development

```sh
git clone https://github.com/agenthooksprotocol/python-sdk.git
cd python-sdk
python -m pip install -e .
python -m compileall -q src tests
PYTHONPATH=src python -m unittest discover -s tests
```

Integration tests additionally require the matching protocol draft checkout at
`../agent-hooks-protocol` for shared fixtures and synthetic certificate material.
The installed runtime itself does not need this checkout.

Generated code lives in `src/agent_hooks_protocol/generated.py`. Its provenance is recorded in `ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing the generated file.

## License

Apache-2.0

## Draft integration runtime

`runtime.Validator` checks the canonical Draft 2020-12 schemas **and** this
SDK's generated Python codecs. The installed package includes its canonical
schema bundle and does not require a protocol checkout. `AHP_SCHEMA_DIR` can
select an explicit canonical schema directory for development. Generated codecs
and schemas must describe the same revision; mismatches fail closed. Regenerate
`generated.py`, `schemas.json`, and the codegen lock together from the protocol
repository's generator.

`runtime.apply_response` is the Python evaluator. It stages the whole response,
checks correlation and advertised operations, applies ordered shallow merges or
whole replacements, validates the effective event, then publishes one result.
Unsupported effects or invalid final payloads reject the whole response.
Permission composition is deny > ask > allow; input/destination changes invalidate
old approval and candidate results. `executed` is an eligibility report, not a
host tool invocation. No effect does not grant permission: native permission must
still be obtained, and an applicable ask cannot be erased by a later allow.
`native_authorize(effective_event)` is a required host access-policy guard when
configured: it runs after effective modifications, even for hook `allow`, and gates
both execution and delivery of supplied results. False is refusal; None is pending
and exposes neither execution nor a candidate. Only exact booleans/None are accepted.
An optional separate `native_approve(effective_event)` implements the ordinary
native approval prompt: hook allow can suppress this prompt, never the access guard.
An applicable ask remains pending confirmation, not approval. A host configuring an
access guard without an approval callback declares no additional ordinary prompt.
Without host callbacks or an applicable allow, authorization remains pending.
Callbacks decide policy only; they must not execute the operation themselves.
`validate_operation(effective_event)` supplies application-specific payload checks.
Synthetic test adapters explicitly configure their permissive test-host policy.
Flow stop suppresses execution independently of permission; continue consumes one
boundary continuation, retaining ordered instructions. Injections require the
advertised context/append/delivery capability.

Observers receive the permission-filtered effective event,
with the same logical event ID and no generic disposition or decision summary.
Subscription identities are harness-local and are never sent in an envelope,
execution metadata, or upload header.
After short-circuiting, remaining uncalled matching intercept subscriptions get
`hooks/observe` under their existing permissions and selections. Already-called
interceptors get no automatic second copy; explicit observation subscriptions
remain independent. Interruption ends pending decisions immediately and does not
wait for observer uploads or processing. Upload readiness precedes each delivered
notification. There is no downgrade flag or `/view` fallback.

`lineage.TaskLineage` preserves source-scoped logical identities across projected
views, detects late parent cycles, and allows unknown ancestry at receivers.
`producer=True` additionally requires known parents. Task and workspace payloads
are canonically typed. Task interception supports deny/message only; it cannot
modify task changes or transfer tool approval to a task operation. Identity,
operation, prior state, and parents remain explicit. Workspace modifications target
`workspace.change`. After-events with known prior state must represent a change.

### Content upload

`content.upload(upload_config, data, *, loopback=False)` returns `(status, descriptor)`
on success and `(status, None)` on a rejected upload. Invalid success descriptors
raise `ProtocolError`. Uploads POST raw `bytes` to the **exact** configured endpoint, including its query,
with `Content-Length` and `AHP-Content-SHA256`. The receiver allocates an immutable
reference and returns **201 JSON `{ref, size, sha256}`**. The sender checks the
returned size and hash before publishing any dependent event. Redirects are
rejected; HTTPS is required outside explicit loopback tests. Upload authentication
is independently resolved from `upload_config.auth = {"type": "bearer",
"tokenEnv": "UPLOAD_TOKEN"}`; absent upload auth never inherits event credentials.
Zero bytes and invalid UTF-8 are supported.

`ContentStore` stores immutable bytes in a trusted local authorization scope,
checks size/hash, and resolves normalized references before observe **or**
intercept processing. Authorization comes from credentials or explicit process
trust, never JSON-RPC correlation or event identity. The test adapter's
`uploadSubscriptions` configuration is local credential-to-scope routing;
`null` is an explicit anonymous grant. Its separate readiness `uploadEndpoint`
accepts binary `/content` POSTs, not a JSON upload control request. Lifecycle
fixtures encode binary input as `bodyBase64` only; the client decodes it once,
uploads and confirms it before any referencing wire message. Upload steps may
provide an independent `upload` endpoint/auth object. Standard interop scenarios
can provide an `uploads` array with the same fields.

Run language checks (with matching generated outputs):

```sh
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m unittest discover -s tests -p test_content.py
.venv/bin/python -m compileall -q src/agent_hooks_protocol
```

Shared interoperability fixtures/matrices are maintained separately. These local
adapters are test hosts, not production HTTP deployment or durable cancellation
implementations.

Lifecycle HTTP event authentication supports none, bearer, OAuth client credentials,
workload assertions, and mutual TLS, using the same configuration and checks as
the core adapter. Stdio accepts process trust only. The shared runner’s independent
`uploadAuth: {token, scope?}` server configuration and client `upload`
configuration are supported without inheriting event credentials. Exact incoming
canonical envelopes are captured in received/observed test receipts; those receipts
must be treated as sensitive test content, not production redacted telemetry.

### Catalogue and registration evaluation

The lifecycle adapters also implement `suite: "catalogue"`. They use one actual
capabilities exchange, native settled observation snapshots, and the same HTTP
and stdio event transports. The receiver records exact accepted/rejected messages;
raw negative notifications bypass only sender checks, never receiver validation.
The Python `registration.validate_registration` evaluator checks the actual
validated discovery manifest, subscription event/mode support, operation
requirements, interactive prompting, credential resolution, and enforceable
managed scope. Environment/credential resolvers are trusted host inputs, not
self-reported manifest identity. Registration explicitly requires `content.default`.

`TaskLineage` also checks known task before/after IDs and operations, late-edge
cycles, and content-child role agreement with known owners. These checks stage
all changes before committing, so a rejected event cannot poison later processing.
Model-visible children must still carry their own explicit role even when an owner
is known. Corrected codecs preserve typed synthesized identity markers and validate
`model.response.after` interception; runtime response modifications use normalized
items and preserve execution provenance.

Run the catalogue self-pair across all applicable auth modes:

```sh
# From the workspace root:
python-sdk/.venv/bin/python agent-hooks-protocol/interop/catalogue_matrix.py \
  --client python --server python --workers 3 --timeout 45 \
  --output /tmp/python-catalogue-self.json
```

This is synthetic language-runtime and wire coverage, not evidence that a native
harness produces every event or enforces every possible registration.
