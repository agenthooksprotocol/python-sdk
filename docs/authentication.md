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
  An unknown first contact starts anonymously; its challenge can trigger trusted
  discovery. Use host `prepare` before the first unsafe call if it needs auth.
- Missing configured credentials raise `credential_unavailable` before HTTP
  delivery. Failure never falls through to another route or anonymous delivery.
- Opaque attempt identities retain the issuing provider and original identity,
  even if the router's configured route changes while HTTP is in flight.
  Attempts cannot cross namespaces, destinations, backends, or event/upload
  purposes. The router itself owns no cache or coordinated registry.
- The transport owns replay: eligible interception/configuration requests can
  retry once after a Bearer 401 or a valid Bearer 403 `insufficient_scope`
  challenge. Other 403 responses are denied. Notifications, observations and
  uploads never replay; providers must not resend application requests.

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
access. Hosts can use these values to choose configuration, consent or retry UI.
Structured provider classifications survive the transport boundary, without
retaining secret-bearing exception contexts. Cancellation remains native under
asyncio and Trio, and provider calls stay inside the enclosing operation budget.

## Optional managed OAuth

Install `agenthooksprotocol[oauth]` to use `agenthooksprotocol.oauth`. The extra
adds Authlib and HTTPX; core and stdio installs do not need them. Importing the
module starts no network activity and does not require Authlib. Exchanges use
Authlib's OAuth/PKCE and client-authentication primitives through the host's
HTTPX network boundary, not a separate HTTP client stack.

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

Create one consent budget inside an active AnyIO task, including time for user
interaction. Supply the host's native cancellation scope explicitly:

```python
import anyio
from agenthooksprotocol import oauth

async def authorize(managed, target, receive_callback):
    with anyio.fail_after(300) as owner:
        budget = oauth.OperationBudget.after(300, cancel_scope=owner)
        try:
            result = await managed.prepare(target, budget)
            if isinstance(result, oauth.Ready):
                return result
            # Host UI displays the URL; never log it or the callback.
            callback_url = await receive_callback(result)
            return await managed.complete(target, result, callback_url, budget)
        finally:
            owner.cancel()  # Mark the consent context ended, including normal exit.

```

The host must enforce its deadline and cancellation while waiting for user input.
Reuse the **original budget** when polling `prepare`. A pending login is reused
only while its original owner is eligible, its original deadline covers the
requested budget, and requested/required scopes and redirect URI match. Giving
completion a new budget cannot extend the original deadline or login lifetime
(`login_lifetime` defaults to 300 seconds). Invalid state, redirect or issuer does
not consume a valid pending login; valid completion can claim it only once.

Keep the same provider instance for interactive preparation and completion.
Consent ownership is process-local: native scopes are not persisted, and a
recreated provider must prepare fresh consent. Persisted binding metadata and
valid tokens remain usable by recreated providers without rediscovery. Retain
the pending handle for its target/user; do not serialize it as an AHP message or
log URLs, store keys, credential identities, client secrets or tokens.

Use `await managed.cancel(target, pending, budget)` to abandon that pending
operation without deleting a valid stored grant. For cancellation cleanup, supply
an active cleanup budget; do not reuse a canceled scope as its owner. `reset` is
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
resource metadata. Unbound discovery uses protected-resource metadata with
`resource_metadata` challenge support and validates its exact source identity.
Local policy remains authoritative. Resource indicators are sent on token
exchange and refresh; destination/resource/issuer identifiers are exact, including
trailing slashes and queries where permitted. Do not normalize mismatches away.

### Configure scopes and storage isolation

`OAuthClientConfiguration.scopes` is the requested set. `allowed_scopes` is the
local ceiling and defaults to requested scopes when omitted. `required_scopes`
contains explicit operation requirements. All scopes use OAuth's ASCII grammar;
requested and required scopes must be inside the ceiling. An initial response
may narrow requested scopes or add only locally allowed scopes. A refresh response
can only retain or narrow the **previously granted** scopes, even when the local
ceiling allows more. Omitted response `scope` inherits requested scopes on
acquisition and the previous granted scopes on refresh. Broader scopes require
fresh PKCE consent or a new client-credentials grant. Requested scopes alone are
not mandatory for delivery.

A Bearer 403 `insufficient_scope` records permitted step-up requirements for the
binding. Forbidden scopes fail with `access_denied`. If the challenge omits
`scope`, explicit host requirements must identify the needed scopes; otherwise
access is denied. PKCE advises host-owned consent; client credentials can acquire
approved scopes without human login. No effectful operation is replayed.

The binding key identifies namespace, backend ID, purpose and exact destination.
The separate grant key identifies namespace, issuer, resource, client ID, flow,
**allowed scope ceiling**, and partition. Requested/granted scopes, client
secrets/references, auth method and mutable metadata are not grant identity.
Default partitions isolate bindings, including event and upload targets. Set the
same nonempty `grant_partition` only when local policy independently authorizes
both bindings to share the same OAuth principal and allowed ceiling. An upload
never implicitly inherits event authorization.

Store keys are opaque strings using length-prefixed UTF-8 fields. If adapting a
store with tuple keys, explicitly migrate both binding lookup metadata and grants
to these keys, or clear the old entries and prepare authorization again. Do not
silently alias old tuple keys or unrelated destinations to a shared grant.

### Rotation, failure and repair

Unknown expiry is usable: an omitted `expires_in` does not force refresh or
invalidate a token. Explicit invalid expiry is rejected; known expiry uses an
`expiry_skew` of 30 seconds by default. A successfully received rotated refresh
credential is persisted before reporting operation-level scope insufficiency.
Tokens outside local permission policy or the prior refresh grant are persisted
with `StoredToken.quarantined=True` and a `quarantined` grant status, retaining
rotated refresh material before `access_denied` is reported. Stores must preserve
this marker when serializing records. The SDK does not dispatch or refresh a
quarantined access token, including after provider recreation or pending-login
cancellation. Explicit fresh consent or client-credentials acquisition can
replace it with a valid grant; reset deliberately discards the retained grant.
Adapters accepting experimental records from before this marker must invalidate
any records whose refresh-scope history cannot be established.

A timeout, 5xx, non-OAuth response or transient OAuth error retains refresh
material and advises retry, not automatic login. An ambiguous exchange may have
rotated credentials externally; a retry can ultimately return `invalid_grant`.
There is no promise of rollback at the authorization server. Definitive PKCE
refresh rejection advises a new login. Client credentials remain noninteractive.
Storage writes may commit before cancellation is observed: never restore old
refresh tokens blindly.

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
PYTHONPATH=src:tests uv run --locked --all-extras python -m unittest test_oauth_contracts test_auth_routing test_managed_oauth test_managed_oauth_runtime test_oauth_discovery
```

The vendored `tests/fixtures/sdk-auth-lifecycle.json` comes from
`agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json`. Its lifecycle
entries are a coverage manifest, not executable proof of SDK behavior; native
tests exercise the key/token vectors through actual HTTP, storage and dispatch.
