# Authentication routing

`auth.RoutingAuthProvider` is opt-in. Existing `AuthProvider` implementations,
`EnvironmentAuthProvider`, and `Hooks(auth_provider=...)` retain their entry
points and host-owned lifetime. The router does not replace an existing custom
provider or start background work.

```python
from agenthooksprotocol import auth

provider = auth.RoutingAuthProvider(
    bearer=auth.BearerAuthProvider(resolve_credential=vault.resolve),
    oauth=host_oauth,
    discover=host_oauth,
    namespace="host-account/session-owner",
)
# Hooks(..., auth_provider=provider)
```

`vault.resolve(reference)` can return a secret or await one. `host_oauth` supplies
the existing async `credential(context)` and `challenge(context, challenge)`
methods; see [the typed composition example](../examples/auth_routing.py).
A custom provider owns its OAuth mechanics. The optional managed provider below
implements discovery, exchange and refresh while keeping trust policy, network
access, storage/coordination, consent UI and callback transport host-controlled.

## Routes and failures

- Explicit `Authorization` wins and bypasses provider acquisition/challenges.
  Registration `transport.headers` are explicitly shared with content uploads,
  as before; avoid a shared Authorization header if upload auth must differ.
- A bearer binding uses only `bearer` (environment/reference resolution by
  default). An OAuth binding uses only `oauth`. A missing OAuth route raises
  `unsupported_binding` for either registered OAuth flow.
- An unbound endpoint asks `discover.credential(context)` for an already
  authorized credential. The managed provider uses persisted binding metadata
  and grants, including for notifications and uploads that cannot be replayed.
  That lookup never runs protected-resource discovery or starts a login. It may
  refresh an expired token or re-acquire a client-credentials grant with the
  persisted authorization-server metadata (fetching only the stored issuer's
  metadata if it is missing). A known binding that cannot be renewed fails the
  operation, with `interaction_required` when consent is needed. Only a store
  miss or a host policy refusal sends anonymously. Full discovery runs only on a
  cache miss, a host `prepare` or challenge handling. If a renewal fails on
  persisted metadata without an OAuth error response (network, redirect, 404),
  the provider refetches the stored issuer's metadata once and retries; a
  changed issuer or failed refetch reports `discovery_failed`, repaired by `prepare`. A 401 marks the rejected
  token stale even if it has not expired, so it is renewed, never resent. An unknown first contact's
  challenge can trigger trusted discovery. Use host `prepare` before the first
  unsafe call if it needs auth.
- Missing configured credentials raise `credential_unavailable` before HTTP
  delivery. Failure never falls through to another route or anonymous delivery.
- Opaque attempt identities retain the issuing provider and original identity,
  even if the router's configured route changes while HTTP is in flight.
  Attempts cannot cross namespaces, destinations, backends, or event/upload
  purposes. The router itself owns no cache or coordinated registry.
- The transport owns replay: `hooks/intercept`, `hooks/configuration` and
  `hooks/capabilities` requests replay once, with the same id and body, after a
  Bearer 401 or a valid Bearer 403 `insufficient_scope` challenge; a second
  rejection fails. Other 403 responses are denied. Notifications and uploads
  never replay, but their challenge still reaches the provider so the next
  operation sends a credential. Providers must not resend application requests.

`auth.normalize_auth_target(context, namespace=...)` returns a frozen
`AuthTarget`, with a deeply read-only wire `binding` (including extensions) and
`typed_binding` of `BearerBinding`, `OAuthBinding`, or `None`. `kind` is
`bearer`, `oauth`, or `discover`. OAuth fields use snake_case, and requested scopes
are sorted/deduplicated. `destination` remains separate from OAuth `resource`.
`identity` includes namespace, backend, purpose, full destination and typed
binding; it is an isolation key, not a persistent record or log-safe string.
Normalization validates syntax only, not DNS/egress authorization.

`AuthenticationFailure` remains a `ProtocolError` and adds safe `code` and
`recovery` (`configure`, `login`, `retry`, `none`). Codes are
`invalid_configuration`, `unsupported_binding`, `credential_unavailable`,
`interaction_required`, `access_denied`, `refresh_rejected`, `discovery_failed`,
`untrusted_destination`, and `provider_failed`. Public exception text is fixed;
legacy positional messages and raw provider exceptions are not exposed.
Defaults are `configure` for configuration, unsupported binding, unavailable
credential and untrusted destination; `login` for required interaction and
rejected refresh; `retry` for discovery/provider failure; and `none` for denied
access. `interaction_required` can carry validated `required_scopes`; pass them
to `prepare(..., required_scopes=...)` to request step-up consent.
`access_denied` may report them for diagnostics only. Hosts can use these values to choose configuration, consent or retry UI.
Structured provider classifications survive the transport boundary, without
retaining secret-bearing exception contexts. Cancellation remains native under
asyncio and Trio, and provider calls stay inside the enclosing operation budget.

## Optional managed OAuth

Install `agenthooksprotocol[oauth]` to use `agenthooksprotocol.oauth`. The extra
adds only HTTPX; core and stdio installs do not need it. Importing the module
starts no network activity. PKCE (S256), token requests and client
authentication use the standard library through the host's HTTPX network
boundary, not a separate HTTP client stack.

```python
from agenthooksprotocol import auth, oauth

# network, policy and store are host implementations of the protocols below.
managed = oauth.ManagedOAuthProvider(
    network=network,
    policy=policy,
    store=store,
    namespace="host-account/session-owner",
)
provider = auth.RoutingAuthProvider(
    bearer=auth.BearerAuthProvider(resolve_credential=vault.resolve),
    oauth=managed,
    discover=managed,
    namespace="host-account/session-owner",
)
# Hooks(..., auth_provider=provider)
```

Use the same namespace for normalization, the router and the managed provider;
a namespace represents a credential owner, not a globally shared default.
Managed OAuth requires a nonempty backend `id`; unidentified backends fail
configuration rather than sharing an invented identity.
See [the typed host-controlled example](../examples/managed_oauth.py). It takes
host capabilities rather than offering an unsafe sample DNS policy or token store.
No AHP wire-schema fields or dynamic client registration are introduced.
Host-store key and record compatibility is described below.

### Prepare, interact, complete

`await managed.prepare(target, budget, challenge=challenge)` accepts a normalized
`auth.AuthTarget` and returns `oauth.Ready` (with a `credential`) or
`oauth.PendingLogin`. Client credentials exchange without interaction. For
`authorization_code_pkce`, configure a client and redirect URI; the host displays
the S256 authorization URL and receives the callback through its own UI and
transport. HTTPS redirects are required except HTTP to literal loopback IPs for
desktop/CLI clients. The SDK starts no browser or listener.

Each call takes its own budget; waiting for the user happens between calls:

```python
from agenthooksprotocol import oauth

async def authorize(managed, target, receive_callback):
    result = await managed.prepare(target, oauth.OperationBudget.after(30))
    if isinstance(result, oauth.Ready):
        return result
    # Host UI displays the URL; never log it or the callback.
    callback_url = await receive_callback(result)
    return await managed.complete(
        target, result, callback_url, oauth.OperationBudget.after(30)
    )
```

A pending login is a stored record. Its lifetime is fixed at creation by
`login_lifetime` (default and maximum 600 seconds) and does not depend on the
creating `prepare` call's deadline or cancellation. Any provider or process
sharing the store can `complete` it with the `PendingLogin` handle. A later
`prepare` reuses an unexpired pending login, whatever its deadline, when the
redirect matches and its requested and required scopes are within the pending
scopes. Otherwise it supersedes it with a login requesting the old pending
scopes plus the new scopes within the caller's ceiling, storing the union of
both ceilings; the old callback then fails
`interaction_required`. A pending login ends once: completion (including
consent denial), supersede, `cancel` or expiry. Invalid state, redirect or
issuer does not consume it. Reuse requires the exact redirect, so hosts sharing a store
must keep the redirect URI stable per grant.

Persisted binding metadata and valid tokens remain usable by recreated
providers without rediscovery. Do not serialize the pending handle as an AHP
message or log URLs, store keys, credential identities, client secrets or tokens.

Use `await managed.cancel(target, pending, budget)` to abandon that pending
operation without deleting a valid stored grant. `reset` is
a separate explicit logout/repair action described below.

Delivery `credential`/`challenge` calls use a default 30-second `operation_timeout`,
capped by the enclosing operation. They never create pending interactive logins:
`interaction_required` / `login` tells the host to call `prepare` with its own
consent budget. Unknown unbound first contact can remain anonymous; an already
authorized unbound target sends cached credentials up front.

### Required host capabilities

- **`OAuthTrustPolicy`**: `resource(target, budget)` selects the protected
  resource; `select(target, resource, issuers, required_scopes, budget)` returns
  an `OAuthClientConfiguration`. The host authorizes the resource, exact issuer,
  client, flow and scopes from local policy. Remote metadata is not authority.
  Supported flows are `authorization_code_pkce` and `client_credentials`;
  endpoint authentication is `none`, `client_secret_basic` or
  `client_secret_post`. The host provisions client IDs/secrets and redirect URIs.
- **`OAuthNetwork`**: `authorize(url, purpose, budget)` checks metadata, token
  and browser-bound authorization URLs. `send(request, purpose, budget)` must
  enforce TLS, DNS/egress policy (including rebinding protection) for the actual
  connection, reject redirects, and avoid ambient cookies or credentials. It
  must not close a borrowed host client. Merely validating a URL string is not
  a safe production implementation. The SDK rejects redirect responses and
  bounds response size, but cannot enforce the host's network boundary for it.
- **`OAuthTokenStore`**: implement all three entry points:
  `await load_binding(key, budget) -> OAuthMetadata | None`,
  `await save_binding(key, metadata, budget) -> None`, and
  `coordinate(key, budget)`, an async context manager yielding an exclusive guard
  with `await load()` and atomic
  `await compare_and_swap(expected_generation, record) -> bool`.
  Binding metadata contains trusted principal/endpoint information but no client
  secret. Persist it alongside securely stored grants so a recreated provider
  can locate credentials without rediscovery. Resolve current client secrets
  through policy selection when exchanges need them; secret rotation does not
  change grant identity. Guard exclusion must cover every provider/process
  sharing the grant key, including token network awaits. Make lock acquisition
  cancellation-aware, and do not reenter the same key from host callbacks.
  A per-provider lock or plain dictionary is not sufficient for shared storage.

Explicit OAuth presets use issuer metadata without first requiring protected-
resource metadata. Issuer and resource must be HTTPS. Authorization-server
metadata uses RFC 8414 defaults: if `grant_types_supported` is missing,
`client_credentials` is treated as unsupported, and if
`token_endpoint_auth_methods_supported` is missing, only `client_secret_basic`
is supported (so public clients need the server to advertise `none`). Unbound discovery uses protected-resource metadata with
`resource_metadata` challenge support and validates its exact source identity.
Local policy remains authoritative. Resource indicators are sent on token
exchange and refresh; destination/resource/issuer identifiers are exact, including
trailing slashes and queries where permitted. Do not normalize mismatches away.

### Configure scopes and storage isolation

`OAuthClientConfiguration.scopes` is the requested set. `allowed_scopes` is the
local ceiling and defaults to requested scopes when omitted. `required_scopes`
contains explicit operation requirements. All scopes use OAuth's ASCII grammar;
requested and required scopes must be inside the ceiling. An acquisition
(including step-up or re-acquisition) requests the previous grant plus the
requested and required scopes within the caller's ceiling, and records the
response scopes within the previous grant plus the acquisition ceiling (the one
stored on the pending login, or the client-credentials caller's), so step-up
never loses earlier scopes. A refresh records the
response scopes within the **previously granted** scopes, so it never broadens a
grant. Extra scopes, such as `openid` or every scope a client holds, are ignored,
not an error. Omitted response `scope` means the requested scopes on acquisition
and the previous grant on refresh. At use, effective scopes are the grant within
the **current** ceiling: narrowing or widening a ceiling never loses a grant. The
ceiling governs what the SDK requests and records; it does not limit what an
issued token can do at the resource server. An operation fails `access_denied`
only when an explicit or challenged required scope is missing.

A Bearer 403 `insufficient_scope` requirement applies only to the challenged
operation and the acquisition it triggers; it is not stored on the binding.
Forbidden scopes fail with `access_denied`. If the challenge omits `scope`,
explicit host requirements must identify the needed scopes; otherwise access is
denied. PKCE returns `interaction_required` with the required scopes for a host
`prepare`; client credentials acquire approved scopes without human login.

The binding key identifies namespace, backend ID, purpose and exact destination.
The separate grant key identifies namespace, issuer, resource, client ID, flow
and partition. The allowed ceiling, requested/granted scopes, client
secrets/references, auth method and mutable metadata are not grant identity.
Default partitions isolate bindings, including event and upload targets. Set the
same nonempty `grant_partition` only when local policy independently authorizes
both bindings to share the same OAuth principal. An upload never implicitly
inherits event authorization.

Store keys are opaque strings using length-prefixed UTF-8 fields. If adapting a
store with tuple keys, explicitly migrate both binding lookup metadata and grants
to these keys, or clear the old entries and prepare authorization again. Do not
silently alias old tuple keys or unrelated destinations to a shared grant.

### Rotation, failure and repair

Unknown expiry is usable: an omitted `expires_in` does not force refresh or
invalidate a token. `expires_in` must be a positive integer (or digit string);
known expiry uses an `expiry_skew` of 30 seconds by default. A rotated refresh
token is persisted before reporting operation-level scope insufficiency.

An invalid token response (non-Bearer type, malformed `expires_in`, scope or
token) is never dispatched and fails `provider_failed`. An invalid initial
exchange persists nothing; an invalid refresh response keeps only a valid
rotated refresh token. No outcome leaves a record in the in-flight `refreshing`
state. A timeout, 5xx, non-OAuth response or transient OAuth error retains
refresh material and advises retry, not automatic login. An ambiguous exchange
may have rotated credentials externally; a retry can ultimately return
`invalid_grant`. A PKCE refresh `invalid_grant` drops both tokens (unless a
newer record already replaced them) and fails `refresh_rejected`. Client
credentials remain noninteractive. After a 401 the rejected access token is not
sent again.

`await managed.reset(target, budget, handle=pending_or_credential)` deliberately
clears the **current** grant, not just the handle's generation. Without a handle,
it uses cached binding metadata; it does not discover an unknown target. Use it
for explicit host logout/repair, never automatically for a stale 401. It can
affect other bindings sharing an explicit grant partition. Use `cancel` instead
to abandon only a pending login. The SDK has no background refresh or implicit
file store, and the transport alone owns application-request replay.


### Verify a host integration

Run the native asyncio/Trio HTTP, coordinated-store and TLS transport regressions:

```sh
uv sync --locked --all-extras
PYTHONPATH=src:tests uv run --locked --all-extras python -m unittest test_oauth_contracts test_auth_routing test_managed_oauth_runtime test_oauth_discovery
```

The vendored `tests/fixtures/sdk-auth-lifecycle.json` comes from
`agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json`. Its lifecycle
entries are a coverage manifest, not executable proof of SDK behavior; native
tests exercise the key/token vectors through actual HTTP, storage and dispatch.
