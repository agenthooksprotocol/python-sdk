# Framework-neutral Python server

```python
from agenthooksprotocol.generated import InterceptRequest, ObserveNotification
from agenthooksprotocol.server import hooks, asgi, stdio


async def intercept(request: InterceptRequest) -> hooks.InterceptResult:
    return hooks.InterceptResult(effects=[{"type": "deny", "reason": "Policy"}])


async def observe(notification: ObserveNotification) -> None:
    pass


handler = hooks.Handler(intercept=intercept, observe=observe)
app = asgi.App(handler)  # Mount with any ASGI server; no Starlette dependency.
# await stdio.serve(handler)  # AnyIO: asyncio or Trio.
# response = await handler(utf8_json_bytes)  # dict or None
# response = await handler.process(canonical_request_dict)
```

Callbacks receive canonical generated request/notification dictionaries. Effects
are canonical `generated.Effect` dictionaries. The SDK validates request and
response schemas and intercept/event correlation. The harness remains responsible
for effect capability gating, authorization, native approval, atomic application,
and runtime settlement; dispatch does not execute effects.

`hooks.Engine(handler, validator=None, harness_manifest=None).handle(bytes)` is
the common dispatcher. The optional static manifest describes a **harness**, not
backend discovery. Only configuring this manifest enables `hooks/capabilities`.
`Handler` has no capabilities callback. A direct callable handler caches its
engine; use an explicit Engine when supplying a validator or static manifest.

JSON-RPC error responses retain request IDs when valid. Valid notification
envelopes never produce a response, including malformed params, unknown methods,
and callback failures. Invalid JSON/envelopes produce JSON-RPC errors. HTTP uses
204 for notifications and 200 for JSON-RPC responses. `hooks.HTTPError(status,
body=b"", content_type=b"text/plain; charset=utf-8")` from an intercept callback
emits that HTTP status and body. On stdio, a canonical JSON-RPC error body
with the matching request ID is preserved, regardless of HTTP status. Other
bodies are carried in internal-error `error.data` with `httpStatus` and a UTF-8
`body` string, or `bodyBase64` for binary data. Framing/output limits still apply.
Cancellation propagates. Exceptions from callbacks do not disclose their details.

## Transports and resource ownership

`asgi.App(handler, max_bytes=4194304, **engine_options)` and its `asgi.app` alias
accept HTTP POST at their mounted path. Routing, authentication, TLS, request
timeouts and deployment concurrency limits belong to the caller/framework. HTTP
request bodies are bounded; disconnect before dispatch does not invoke callbacks.
Only HTTP scopes are supported (configure ASGI-server lifespan handling or mount
inside a framework). No framework or HTTP client is imported.

`await stdio.serve(handler, input=None, output=None, max_bytes=4194304,
**engine_options)` accepts borrowed AnyIO byte streams. Defaults borrow binary
stdin/stdout. On POSIX, default pipes use cancellable descriptor readiness without
changing flags or closing descriptors. They require exclusive access and must
not have prior buffered reads/writes. Other default streams offload operations to
threads and flush each reply; these fallback operations defer cancellation until
completion to avoid abandoning a reader on a borrowed stream. Applications
requiring prompt cancellation on non-pipe/default platforms should supply
cancellable AnyIO streams. No streams are closed by the SDK. Do not write
logs to stdout. Processing is serial and awaits output before another callback.

NDJSON uses UTF-8 and requires a newline, including the last record. The byte
limit excludes that newline. Invalid bounded JSON/UTF-8 returns a parse error;
an overlong or unterminated frame raises ValueError and stops serving. Output
messages are also bounded. CRLF is accepted as JSON trailing whitespace. Caller
streams must honor their `receive(max_bytes)` bound. Borrowed iterators are not
closed even on rejection; owners must close generators with `aclosing` as needed.

## Attachments

```python
from agenthooksprotocol.server import attachments


async def authorize(credentials):
    # Validate upload credentials, independently of hook/subscription identity.
    return 201, authenticated_scope


class Store:
    async def commit(self, *, scope, ref, data):
        # Atomically publish these immutable bytes, without replacing a ref.
        # The scope/ref pair must govern subsequent authorized access.
        ...


upload_app = attachments.App(authorize=authorize, storage=Store())
# descriptor = await attachments.receive(headers, body_iterator,
#     authorize=authorize, storage=Store())
# async with attachments.parse(headers, body_iterator) as verified:
#     use(verified.data, verified.size, verified.sha256)
```

Authorize returns `(201, non-None scope)`, `(401, None)`, or `(403, None)`.
`parse` is a borrowed async context manager that buffers bounded bytes and yields
only after EOF, exact declared size, lowercase SHA-256, and canonical upload
framing have been verified. It is **not** an authorization or commit operation.
Headers may be a mapping or a sequence of name/value pairs; sequences preserve
duplicates for rejection. Binary ASGI headers are supported. The default maximum
is 4 MiB; pass `max_bytes` to configure it.

`receive` authorizes before reading, verifies through EOF, allocates an opaque
reference, and awaits `storage.commit(scope=..., ref=..., data=...)` before
returning the canonical content-reference descriptor. `attachments.App` returns
201 JSON only after that return. Storage errors become 500 without exception
leakage. Rejected framing and authorization carry HTTP error bodies. Disconnect
and cancellation during reading do not commit; cancellation during commit is the
store's responsibility. Stores must publish atomically and never expose partial
bytes. The caller chooses persistence: in-memory storage is valid; automatic
cross-process durability is not required. Successful commits followed by lost
responses can leave orphan references; retention/garbage collection belongs to
the store. Attachment download serving is not provided.
