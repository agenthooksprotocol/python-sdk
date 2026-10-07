# Python lifecycle adapter

From this SDK directory:

```sh
.venv/bin/python -m agenthooksprotocol.lifecycle_server --config ABS_PATH
.venv/bin/python -m agenthooksprotocol.lifecycle_client --config ABS_PATH
.venv/bin/python -m unittest discover -s tests
```

The shared protocol repository's `interop/LIFECYCLE.md` and
`interop/CONTRACT.md` define the test adapter contract. Incoming messages
and accepted responses use canonical Draft 2020-12 validation plus generated
Python codecs. The Python evaluator applies effects, not fixture expected values.

## Event authentication and receipts

HTTP supports all five core modes: none, bearer, OAuth client credentials,
workload assertions, and mTLS. It reuses the core token/claim verification,
client credential resolution, TLS configuration, and redirect rejection.
Authentication precedes protocol processing and receipt recording. Controls run
on a separate loopback listener. Stdio uses process trust only and rejects event
authentication configuration; stdout contains protocol traffic only.

Receipts record the exact received canonical JSON envelope as `message`:
`{kind: received, id, message}` and
`{kind: observed, eventId, event, message}`. They contain test payloads,
not authentication headers. They are not redacted production telemetry.

## Settled observations

Observers receive the permission-filtered effective event without wire subscription identity,
with the same logical event ID and no generic disposition or decision summary.
After short-circuiting, remaining uncalled matching intercept subscriptions get
`hooks/observe` under their existing permissions and selections. Already-called
interceptors get no automatic second copy; explicit observation subscriptions
remain independent. Interruption ends the owning chain operation without starting
further interception or observation work. A separately invoked explicit observe
operation remains independent. Upload readiness precedes each delivered
notification. There is no downgrade flag or `/view` fallback.

## Independent binary uploads

A separate raw HTTP `uploadEndpoint` is advertised in readiness. Server
`uploadAuth: {token, scope?}` configures independent bearer trust and an optional scope.
The alternate `uploadSubscriptions` configuration maps local authorization scopes to
token environment names; null explicitly grants anonymous upload within that scope.
Event content access uses the separately authenticated `auth.scope` (HTTP) or
trusted `stdioScope` (stdio), never message correlation. When explicit scopes are
absent, upload bearer trust and event/process trust share one receiver-local context.
Explicit scopes must be nonempty strings. No anonymous upload scope is granted
by default; configure anonymous grants explicitly.
Client `upload` supplies endpoint, timeoutMs, maxBytes, and optional bearer tokenEnv.
For stdio, an absent upload endpoint is filled from the child's readiness record.
Neither event credentials nor event TLS configuration are inherited by uploads.

Fixture `bodyBase64` is decoded once. The client sends raw arbitrary octets,
including empty/non-UTF8 bytes, to the exact endpoint. Immutable references are
scoped by credential-derived authorization and verified for size/hash before both intercept and observe.
Only 201 with a validated JSON `{ref,size,sha256}` descriptor confirms availability.
The receiver allocates the immutable reference; senders transmit neither references
nor subscription identifiers in upload headers. Deliberately malformed declared size/hash
fixtures are sent over loopback HTTP to obtain actual receiver status, not counted
as successful rejection after a local exception. Upload receipts retain metadata
and actual status, never bytes.

## Limits of the test host

Controls provide barriers, receipt collection, marks, and cleanup—not a semantic
oracle or delivery guarantee. The test host explicitly permits native execution
when no applicable permission override exists, evaluated after modifications;
this is not implicit runtime approval or a production authorization policy.
Capabilities must be supplied for the actual boundary: absent or unsupported
modify operations, flow operations, and injection timing reject atomically.

Cancellation is logical and in-memory, not physical process termination or durable
cancellation. Pending transport futures deliberately remain drainable to exercise
late responses. FIFO applies only within a response ID; unknown responses are
ignored and cannot resolve other attempts. Optional childPidFile records watchdog
cleanup metadata, and normal stdio completion reaps the child and joins its reader.
Shared matrices own cross-language coverage; Python tests independently exercise
all event auth modes, upload auth separation, binary framing, exact receipts,
permission/capability checks, task/workspace payloads, and source-scoped lineage.

## Catalogue suite

`suite: "catalogue"` reuses the authenticated event transports and independent
upload transport. One real `hooks/capabilities` request starts each client
connection (HTTP POST `/capabilities` or stdio). Its validated, correlated response
is captured in discovery receipts and is the only manifest used for registration.
The test host advertises observations for all 17 Execution events and five
change/file events, interception only for tool.before, and no managed-policy
support. It does not accept fixture manifests or expected outcomes as authority.

Observers receive the permission-filtered effective event without wire subscription identity,
with the same logical event ID and no generic disposition or decision summary.
After short-circuiting, remaining uncalled matching intercept subscriptions get
`hooks/observe` under their existing permissions and selections. Already-called
interceptors get no automatic second copy; explicit observation subscriptions
remain independent. Interruption ends the owning chain operation without starting
further interception or observation work. A separately invoked explicit observe
operation remains independent. Upload readiness precedes each delivered
notification. There is no downgrade flag or `/view` fallback.

The SDK-local registration evaluator checks schemas, duplicate backend IDs,
transport/auth support, exact and wildcard event/mode coverage, required effects
and modify operations, interactive ask, explicit content selection and failure
policy, and enforceable subscription scope. Credential environment and optional
credential resolver inputs are trusted host configuration, never manifest identity.
No registration endpoint is contacted, and credential values are not reported.
Unknown suites or operations fail rather than silently skipping.

## Authorization and cancellation safety

Required host access policy (`native_authorize`) and ordinary prompt approval
(`native_approve`) are separate callbacks. Hook allow may bypass only the ordinary
prompt; a negative access-policy decision blocks both execution and supplied-result
selection. Pending policy approval exposes no supplied result. Test-host policy is
explicit, not obtained from fixture expected values or untrusted request identity.

Acceptance reserves a single in-flight evaluation, snapshots its inputs, releases
the state lock for host callbacks, then rechecks the reservation/terminal state
before publishing. Cancellation invalidates the reservation. Deterministic reentrant
and cross-thread barrier tests cover cancellation inside a blocked authorization
callback, duplicate acceptance, and preservation of already accepted state.
Previously accepted flow, instructions, injections, and continuation allowance
survive empty subsequent responses. Sender isolation tests configure event bearer
auth while omitting upload auth and inspect the actual upload receiver's headers.

### Serial-chain wire coverage

Shared `chain` fixtures run one public `Hooks.dispatch` operation over the real
adapter transports. The SDK owns serial interception, failure policy, atomic
settlement, content projection, and selection of remaining uncalled intercept
subscriptions and explicit observers. The adapter supplies receiver barriers and
records actual transport invocations; it does not fold effects or run a second
observation-selection loop.

Interruption cancels the SDK call's native scope while the receiver holds its
response. The receiver timeline must be `received`, `cancelled`, `chain-settled`,
then `replied`, with no chain observation receipts. The fixture drains that
already-sent late response only after the stopped milestone and never feeds it
back into acceptance. A new standalone observation is tested separately and
remains deliverable. Non-interrupted calls complete their owned observations.

Cases cover deny/stop/compound deny+stop, fail-open continuation, fail-closed
short-circuiting, native observation, effective input, metadata/omit projection,
and already-called subscription suppression. Shared verification compares exact
receiver-captured envelopes and rejects extra notifications; local reports are
not sufficient evidence. See the protocol repository's
`spec/draft/observation-disposition.md` and
`interop/observation-chain-scenarios.json`.
