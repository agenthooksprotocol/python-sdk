# Python interoperability adapter

Local synthetic cross-language test adapter, not a production web server or a real
agent/tool runner. Commands in `adapter.json` execute from the Python SDK directory
and accept `--config /absolute/config.json` as specified by the shared
`agent-hooks-protocol/interop/CONTRACT.md`.

## Setup and checks

From `python-sdk/`:

```sh
uv venv .venv
uv pip install --python .venv/bin/python -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m agent_hooks_protocol.interop server --config /absolute/server.json
.venv/bin/python -m agent_hooks_protocol.interop client --config /absolute/client.json
```

Tests use sibling canonical schemas, central scenarios, and explicitly public test
certificates. Set `AHP_SCHEMA_DIR` to use another canonical schema directory. The
runtime resolves all schema references locally (no network schema fetching) and
uses generated Python codecs **and** Draft 2020-12 validation with format checking.
Regenerate codecs with the protocol owner's schema-sync process after schema edits.

Every request and response must pass its complete generated codec and canonical
schema validator. Generated-codec failures are fatal; no event-union compatibility
fallback is used.

## Implemented behavior

- Full JSON-RPC intercept envelopes over HTTP POST `/intercept` and stdio NDJSON;
  stdio never double-wraps the envelope and stdout is protocol-only.
- Independent HTTP GET `/capabilities` and canonical stdio `hooks/capabilities`
  discovery. Stdio requests require `params.protocolVersion: "draft"`; responses
  contain `result.protocolVersion` and `result.manifest.events/gaps`. Complete
  generated and canonical discovery codecs validate both envelopes; aliases and
  the old bare-capabilities result are rejected.
- Atomic staging of allow, deny, ask, modify-input replace/shallow-merge, message,
  return, flow stop/continue, and context inject append now/next_turn.
- Correlation and protocol version checks, capability gating including individual
  modify operations and injection delivery timing, continuation budget checks,
  candidate invalidation on effective input changes, permission precedence,
  modification-before-result binding, and denial/stop suppression of candidates.
  `continuationInstructions` records accepted instructions in response order;
  `continuationRemaining` decrements once for a winning continue, regardless of
  repeated continue effects. A winning stop preserves allowance and retains the
  instruction list for reporting without requesting execution.
- The synthetic task-input contract requires a positive integer `task` after each
  mutation for the core adapter’s synthetic tool named `task`. JSON booleans are not integers.
  Other tools are not assigned an invented input schema. The core adapter passes
  this application validator explicitly. Both test adapters explicitly supply a
  synthetic native policy that permits the effective operation when no override
  applies; the reusable runtime defaults to no native authorization. Ask and deny
  cannot be bypassed by that native policy.
- Real bearer authorization; OAuth client-credentials token endpoint calls; HS256
  OAuth/workload signature, issuer, audience, purpose, expiry and not-before checks;
  real mutually authenticated TLS. Authorization precedes receipt recording and
  protects capability discovery too. Duplicate Authorization headers, including
  differently cased duplicates, are rejected before accepted receipts on both
  endpoints. HTTP and OAuth requests never follow redirects; regression tests
  cover 301, 302, 303, 307 and 308 redirects to a separate local origin.
- Loopback ephemeral listeners, atomic readiness/report files, separate control
  `/health`, `/receipts`, `/release`, `/shutdown`, explicit release barriers,
  exact canonical message receipts (test payloads only; no credential headers), bounded I/O, and stdio child termination/reaping.
- A negative response fixture is intentionally transmitted to test client rejection;
  ordinary server responses and all incoming intercept requests are validated.
  Transport/setup failures do not satisfy response-rejection scenarios.

## Deliberate limits

- Application is a deterministic *local synthetic boundary evaluator*, not native
  harness execution. `executed` indicates whether the synthetic tool would run.
  Flow decisions and injection queues are reportable local state; no external model
  call, next-turn scheduler, filesystem mutation, or production authorization is
  claimed. Modification targets other than `input` are rejected, not ignored.
- Scenarios are independent boundaries; no long-lived session store, subscription
  registry, policy engine, parallel hook scheduler, observe transport, replay cache,
  or durable deferred approval is implemented. Existing candidate/permission state
  can be supplied in canonical request params.
- OAuth implements this test issuer's client-credentials profile, not interactive
  PKCE, discovery/registration, refresh tokens, scopes, or production federation.
  Workload authentication implements only the shared HS256 test profile, not JWKS,
  asymmetric signatures or cloud identity providers. Tokens and TLS keys are never
  written to receipts or reports. All redirects are disabled, including OAuth token
  requests; configs/endpoints must remain trusted local test inputs.
- The shared TLS certificates currently omit authority key identifiers. The adapter
  disables Python 3.13's extra `VERIFY_X509_STRICT` profile for this fixture while
  retaining chain, hostname, expiry and mandatory client-certificate verification.
  Untrusted client-certificate rejection is tested. Do not use these public keys or
  this local adapter as production security infrastructure.
- Stdio uses process trust; configured HTTP auth modes are reported `inapplicable`.
  HTTP unknown auth configurations fail closed. HTTP request/stdio response bounds
  are 4 MiB with a 10-second watchdog; process cleanup has a 3-second grace period.
  Barriers must be released by the external controller before that watchdog.
- Canonical schemas are loaded from the installed package bundle at process
  startup. `AHP_SCHEMA_DIR` optionally selects a matching external schema directory;
  deploying the runtime does not require a sibling protocol checkout.

## Binary upload authorization

Core adapter `uploadSubscriptions` maps receiver-local scope names to independent
upload token environment names (null explicitly authorizes anonymous upload).
Event auth configuration uses `auth.scope`, or `stdioScope` for process trust,
to authorize access to confirmed content. Correlation IDs never select a scope.
A credential must resolve to exactly one configured upload scope. The fixture
scope map is not a registration or wire subscription API.

Uploads use raw bytes and receive `201 application/json` with the receiver's
immutable `{ref,size,sha256}`. Clients validate the descriptor before rewriting
fixture-local reference placeholders and publishing dependent events. Unknown
configuration members are accepted, while recognized fields remain validated.

The compaction wire adapter takes per-scope `credentials` in its host plan.
Receiver `AHP_COMPACTION_TOKENS` and `AHP_COMPACTION_UPLOAD_TOKENS` are independent
JSON token-to-scope maps. HTTP `/hooks/intercept` selects the hook action and
content scope from the authenticated credential, never from a URL or event field.
Stdio receives its scope through trusted process startup configuration. The elicitation wire adapter likewise uses one local
scope and requires separate `AHP_ELICITATION_UPLOAD_TOKEN` / plan `uploadToken`;
it never inherits `AHP_ELICITATION_TOKEN` / plan `token` for uploads.
