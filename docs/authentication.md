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
  cache miss, a host `prepare` or challenge handling. If the token endpoint
  provably did not process a renewal (DNS, connect or TLS-handshake failure, or
  404/410), the provider refetches the stored issuer's metadata once and retries;
  a changed issuer or failed refetch reports `discovery_failed`, repaired by
  `prepare`. Ambiguous failures after sending (read timeout or reset, 5xx,
  non-OAuth body, redirect) report `provider_failed` with no immediate retry,
  so a rotated refresh token is never replayed. Once a token request's bytes are written
  (reported through HTTPX's request `trace` extension, which `send` must pass
  through), receiving and storing its response is shielded from caller
  cancellation and bounded by `commit_timeout` (default 30 seconds); before
  that, cancellation stops the request promptly. A 401 marks the rejected
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
  Bearer 401, or a 403 whose header is exactly one Bearer challenge with
  `error="insufficient_scope"` (the provider validates its `scope`, so a
  malformed one fails `access_denied` there); a second rejection fails, and
  its token is still handed to the provider, which retires it on a 401. Other
  403 responses are returned without a retry. Notifications and uploads
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
access. Only `interaction_required` and `access_denied` carry
`required_scopes`, deduplicated and sorted, and always the operation's full
required set R: host-required (`OAuthClientConfiguration.required_scopes`),
explicit (`prepare(..., required_scopes=...)`) and a Bearer 403
`insufficient_scope` challenge's scopes. Requested scopes (configured `scopes`
and an OAuth binding preset's `scopes`) are never part of R. Pass the scopes of
`interaction_required` to `prepare(..., required_scopes=...)` to request step-up
consent. `access_denied` names R when the SDK's scope decision refuses: R
outside the allowed ceiling, a grant narrower than R, or a 403 for scopes the
stored grant already records. Within `ManagedOAuthProvider` scopes are opt-in:
only those outcomes of its single scope decision (and `complete`'s check of a
login's R) carry them. Every other error, including any raised by host
callbacks, stores or networks (trust policy, client selection, destination
checks) and token-endpoint errors, carries none: scopes a host sets are
stripped. Hosts can use these values to choose configuration, consent or retry
UI.
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
No AHP wire-schema fields are introduced; client registration is host policy
(see [Client registration](#client-registration)).
Host-store key and record compatibility is described below.

### Prepare, interact, complete

`await managed.prepare(target, budget, challenge=challenge)` accepts a normalized
`auth.AuthTarget` and returns `oauth.Ready` (with a `credential`) or
`oauth.PendingLogin`. Client credentials exchange without interaction. For
`authorization_code_pkce`, configure a client and redirect URI; the host displays
the S256 authorization URL and receives the callback through its own UI and
transport. HTTPS redirects are required except HTTP to literal loopback IPs
(`127.0.0.1`, `[::1]`) for desktop/CLI clients; `localhost` is
`invalid_configuration`. As in MCP clients, a host may bind a fresh ephemeral
loopback port per login and pass it as `prepare(..., redirect_uri=...)`, with
no redirect configured at all (only creating a login needs one); that
exact redirect, with its port, is used for registration, authorization, the
callback check and the token request. The SDK starts no browser or listener.

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

As in MCP clients, a pending login belongs to the provider that created it,
which receives its callback and completes it by `state`; pass the
`PendingLogin` handle, or `None` to find it by the callback's `state`. With
`ManagedOAuthProvider(..., persist_pending_logins=True)` pending logins are
stored through `store.coordinate` instead, so another process sharing the store
can complete one from a pasted callback URL. The PKCE verifier is only ever in
the pending login, never in binding metadata or logs. A pending login's lifetime
is fixed at creation by `login_lifetime` (default and maximum 600 seconds) and
does not depend on the creating `prepare` call's deadline or cancellation;
expired logins are deleted.

Every `prepare` that needs consent creates a new pending login. Up to
`max_pending_logins` (default 5) may exist per grant key, counted per provider,
or per store when persisted; one more cancels the oldest in the same atomic
write. Completing one never invalidates another: each completion replaces the
grant's client and tokens, so the newest completed login wins. A pending login
ends once: completion (including consent denial), `cancel` (including by the
cap) or expiry.

`complete` runs in this order:

1. It finds the pending login named by the callback's `state`, under the
   target's stored binding, before any host callback runs. If there is none
   (the `state` is absent or unknown, or its login expired or ended), it fails
   `interaction_required`, whatever handle is passed.
2. It validates the callback: the exact redirect (scheme, host, port, path and
   the redirect's own query; parameters the authorization server adds, such
   as `session_state`, are allowed), no fragment or userinfo, exactly one
   `state`, no `iss` other than the issuer, exactly one of `code` or `error`,
   and no duplicated parameter. A handle naming another login than the
   callback's `state` (including one from an older `prepare` under another
   grant key) is an invalid callback too. An invalid or unparseable callback
   fails `access_denied` with `login_ended` False and leaves the logins
   pending.
3. It applies host policy: client selection, the login's client source,
   which fails `invalid_configuration` when host policy no longer permits it,
   and the destination check of the callback, for every valid callback
   including a consent denial. A failure keeps its code, carries no scopes and
   leaves the login pending.
4. It claims the login once.
5. A consent denial then fails `access_denied` (`invalid_configuration` for a
   CIMD `invalid_client`).
6. A token-endpoint `invalid_grant` fails `interaction_required`, and
   `invalid_client` fails `credential_unavailable` for a pre-registered client,
   `invalid_configuration` for a CIMD client and `interaction_required` for a
   DCR client. Any other token-endpoint error, an unreachable or 404 endpoint,
   or an invalid token response fails `provider_failed`. These errors carry no
   scopes.

A pending login records the required set R it was prepared with (host-required
at that time, explicit and any challenged scopes; a record from an older
release, without R, uses the prepare-time host-required scopes its
configuration holds, even when empty, and only a record lacking them uses the
current ones). `complete`
succeeds only if
the granted scopes within the current ceiling cover that R; otherwise it fails
`access_denied` with that R, still persisting the grant (and any rotated refresh
token) and consuming the login. Every `AuthenticationFailure`, `TimeoutError`
or `OperationCancelledError` raised by `complete` has a boolean `login_ended`:
`True` when the login named by the callback's `state` no longer exists after
the call (consumed, expired or unknown), `False` while it is still pending (for
example an invalid callback or a host-policy failure before the claim). If the
claim's outcome is uncertain, the store is re-read on a fresh short budget; a
login that still cannot be found to be gone counts as pending. It does not
change the code or recovery, appears only on `complete` errors, and is never
copied from a host error.

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
  `client_secret_post`. The host provisions redirect URIs and either a client
  ID/secret or permission for the SDK to obtain one (below).
- **`OAuthNetwork`**: `authorize(url, purpose, budget)` checks metadata, token,
  registration and browser-bound authorization URLs. Refuse a destination by
  raising `AuthenticationFailure(code="untrusted_destination")`. `send(request, purpose, budget)` must
  enforce TLS, DNS/egress policy (including rebinding protection) for the actual
  connection, reject redirects, and avoid ambient cookies or credentials. It
  must not close a borrowed host client. Merely validating a URL string is not
  a safe production implementation. The SDK rejects redirect responses and
  bounds response size, but cannot enforce the host's network boundary for it.
- **`OAuthTokenStore`**: implement all four entry points:
  `await load_binding(key, budget) -> OAuthMetadata | None`,
  `await save_binding(key, metadata, budget) -> None`,
  `await load(key, budget)`, an uncoordinated read of a key's record that never
  waits on its lock; it may be stale but must return a fully committed record,
  never a partially written one, and
  `coordinate(key, budget)`, an async context manager yielding an exclusive guard
  with `await load()` and atomic
  `await compare_and_swap(expected_generation, record) -> bool`.
  Grant keys hold `OAuthRecord`s, client-credentials registration keys
  `OAuthRegistration`s and, with `persist_pending_logins`, pending keys
  `OAuthPendingLogins`, through the same guard.
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

### Client registration

The SDK selects the client per exact issuer and flow, in this order:

1. **Pre-registered**: a nonempty `OAuthClientConfiguration.client_id` (always
   used for an explicit OAuth preset). CIMD and DCR are never attempted.
2. **Client ID Metadata Document**: PKCE only, when the configuration sets
   `client_metadata_document=OAuthClientMetadataDocument(url, redirect_uris)` and
   the issuer metadata has `client_id_metadata_document_supported: true`. The URL
   is the `client_id` (public client, auth method `none`). It must be HTTPS with a
   path and no userinfo, fragment or dot segments, and the redirect must be one of
   `redirect_uris`, where a loopback redirect is compared without its port (RFC
   8252 section 7.3), so `http://127.0.0.1/callback` covers every ephemeral port;
   otherwise `invalid_configuration`. The SDK never fetches it.
   `invalid_client` for a CIMD client is `invalid_configuration`, with no DCR
   fallback.
3. **Dynamic Client Registration (RFC 7591)**: when the configuration for that
   issuer sets `dynamic_registration=OAuthDynamicRegistration(client_name, ...)`
   and the metadata advertises an HTTPS `registration_endpoint`. Client
   credentials also need `secret_store` and a `client_secret_basic` or
   `client_secret_post` method.
4. Otherwise `credential_unavailable`.

Leave `client_id` empty to opt into 2 and 3. The grant key holds the
configured client identity (`preregistered:<client_id>`, `cimd:<url>` or `dcr`),
never an issued DCR `client_id`, so re-registering never moves a grant. A
recorded CIMD or DCR selection stays in use when only issuer metadata changes; a
host policy change (a pre-registered client, a different CIMD URL, removed DCR
permission) reselects, which is a new grant key, so PKCE needs new consent.

```python
managed = oauth.ManagedOAuthProvider(
    network=network, policy=policy, store=store, namespace=namespace,
    secret_store=secrets,  # store(value) -> ref, resolve(ref), delete(ref)
)
# policy.select(...) returns, for a permitted issuer:
oauth.OAuthClientConfiguration(
    issuer, "", "authorization_code_pkce", redirect_uri=redirect,
    client_metadata_document=oauth.OAuthClientMetadataDocument(url, (redirect,)),
    dynamic_registration=oauth.OAuthDynamicRegistration(
        "My Adapter", software_id="my-adapter", software_version="1.2.3",
        initial_access_token_ref="vault:iat",  # optional, sent only to this issuer
    ),
)
```

**PKCE**, as in MCP clients: only the host `prepare` that creates a pending
login registers, with that login's exact redirect and `application_type:
"native"` for a loopback redirect; delivery paths return
`interaction_required`. Each login registers anew and there is no registration
record: the login holds the issued client, and completion commits it with the
tokens in the grant record. Refresh uses that stored client. Any issued
`client_secret` is ignored. `invalid_client` at completion ends only that login
(`interaction_required`) and keeps the stored grant; at refresh it returns
`interaction_required` and deletes the grant only while it still holds the
presented client and refresh token.

**Client credentials** keep one registration record per namespace and issuer,
registered under `store.coordinate` on any acquisition (including the up-front
lookup) when no usable record exists, and shared by every client-credentials
grant for that issuer. Concurrent processes register once. Like a token request,
a registration request whose bytes were written is received and committed
despite caller cancellation. The record holds the client ID, its registered
token-endpoint auth method and secret expiry; the client secret is written only
to `secret_store`, the record holds its reference, and replaced or deleted
records delete their reference. `registration_access_token` and
`registration_client_uri` are ignored. An expired or unresolvable secret
re-registers. A token-endpoint `invalid_client` deletes that client,
re-registers and retries once; a repeated `invalid_client` is
`credential_unavailable` and counts as a failed registration for the backoff,
so a server that accepts registrations but rejects their clients is not
re-registered on every operation. After a failed registration no process sharing the
store registers for that issuer until a backoff passes (failures count until a
token request with a registered client succeeds): `registration_backoff`
(default 60 seconds) doubling to `registration_backoff_max` (default 1 hour), or
a later `Retry-After` up to the same cap. Meanwhile the last failure's code is
returned, so a retryable failure stays `provider_failed` (`retry`), and a
still-valid stored token keeps working. Host `prepare` bypasses the backoff;
`prepare(..., force_registration=True)` replaces a usable registration so
changed registration settings take effect, and acquires a token with the new
client even when a valid one is stored; a failed replacement keeps the current
registration, records the failure in the backoff and returns it.

### Configure scopes and storage isolation

`OAuthClientConfiguration.scopes` is the requested set. `allowed_scopes` is the
local ceiling and defaults to requested scopes when omitted. `required_scopes`
contains host-required scopes. All scopes use OAuth's ASCII grammar; an
invalid token fails `invalid_configuration` when the configuration is used,
never at construction. An OAuth binding preset's `scopes`
are optional: omitted means no constraint, and present they must equal the
selected client's configured scopes.

Every entry point (`prepare`, delivery `credential`, the up-front lookup and
`challenge`) runs one scope decision, in this order: a 401 first retires the
token that was sent (if it is still the stored one), whatever follows, and
before any target or configuration check whenever the attempt identifies the
rejected grant; then
configuration (requested scopes outside the ceiling, a preset that differs, or
an invalid scope token, including a malformed `prepare(...,
required_scopes=...)`, fail `invalid_configuration`); then the challenge form
(an unparseable or ambiguous Bearer challenge, including a token68 or bare
name where a Bearer auth-param belongs, a 403 other than
`insufficient_scope`, or a bare `insufficient_scope` with no host-required or
explicit scopes fail `access_denied` with no scopes); then the ceiling (R
outside it fails `access_denied` with R); then the stored grant (use, refresh,
client-credentials acquisition, or for PKCE a login on `prepare` and
`interaction_required` with R elsewhere). The configuration and ceiling are
decided locally, before any authorization-server request, and with no network
request at all when the binding or a preset is known; a cached binding is never
rediscovered because of them. An unbound target first makes only the
protected-resource metadata fetch that client selection needs.

An acquisition or login (including step-up or re-acquisition) requests the previous grant plus the
requested and required scopes within the caller's ceiling, and records the
response scopes within the previous grant plus the acquisition ceiling (the one
stored on the pending login, or the client-credentials caller's), so step-up
never loses earlier scopes. A refresh records the
response scopes within the **previously granted** scopes, so it never broadens a
grant. Extra scopes, such as `openid` or every scope a client holds, are ignored,
not an error. Omitted response `scope` means the requested scopes on acquisition
and the previous grant on refresh; a JSON `null` or blank `scope` (only spaces,
tabs, CR or LF) is treated as omitted. Any other `scope` must be scope tokens
separated by single spaces, and any other JSON type is malformed: the response
fails `provider_failed`. At use, effective scopes are the grant within
the **current** ceiling: narrowing or widening a ceiling never loses a grant. The
ceiling governs what the SDK requests and records; it does not limit what an
issued token can do at the resource server. An operation fails `access_denied`
only when a scope of R is missing; a grant without a requested or preset scope
still satisfies an operation whose R it covers.

As in MCP clients, a 401 means the token was rejected: the SDK retires it
before any other decision, then renews. Scopes in a 401 Bearer challenge's
`scope` that are inside the ceiling are requested only by a client-credentials
acquisition in that same operation; they are never stored, never requested by
a sign-in or a later operation, never required, and never make a 401 fail
`access_denied`. A 401 with `error="insufficient_scope"` is still a 401.

Only a Bearer 403 `insufficient_scope` creates a step-up requirement. It
applies only to the challenged operation and the acquisition it triggers; it is
not stored on the binding. A challenged scope outside the allowed ceiling fails
`access_denied` with R. If the challenge omits `scope`, host-required or
explicit scopes must identify the needed scopes; otherwise access is denied
with no scopes. If the stored grant already records R (within the current
ceiling) for the rejected token, the 403 fails `access_denied` with R: the
token is not replayed, no consent loop starts and no login is created. If a
newer stored token than the rejected one covers R, it is used. A challenge
`scope` must be scope tokens separated by single spaces; an empty, padded,
invalid or repeated `scope` fails `access_denied` with no scopes. PKCE returns
`interaction_required` with R for a host `prepare`; client credentials acquire
approved scopes without human login.

The binding key identifies namespace, backend ID, purpose and exact destination.
The separate grant key identifies namespace, issuer, resource, client identity,
flow and partition. The allowed ceiling, requested/granted scopes, client
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
`invalid_grant`. Only PKCE grants refresh; client credentials always
reissue, noninteractively. Token-endpoint errors on a refresh or reissue
carry no scopes: a PKCE refresh `invalid_grant` drops both tokens (unless a
newer record already replaced them) and fails `refresh_rejected`, and a
client-credentials `invalid_grant` fails `credential_unavailable`;
`invalid_client` is classified by client source (`credential_unavailable`
for a pre-registered client, `invalid_configuration` for CIMD,
`interaction_required` for a PKCE DCR client; a client-credentials DCR client
re-registers once and re-acquires, and a repeated `invalid_client` fails
`credential_unavailable`); `unauthorized_client` fails
`credential_unavailable`; any other OAuth error (including `access_denied`
and `invalid_scope`), an unreachable endpoint or an invalid response fails
`provider_failed`. After a 401 the rejected access token is not sent again.

`await managed.reset(target, budget, handle=pending_or_credential)` deliberately
clears the **current** grant and its pending logins, not just the handle's
generation. Without a handle,
it uses cached binding metadata; it does not discover an unknown target. Use it
for explicit host logout/repair, never automatically for a stale 401. It can
affect other bindings sharing an explicit grant partition. Use `cancel` instead
to abandon only a pending login. The SDK has no background refresh or implicit
file store, and the transport alone owns application-request replay.


### Verify a host integration

Run the native asyncio/Trio HTTP, coordinated-store and TLS transport regressions:

```sh
uv sync --locked --all-extras
PYTHONPATH=src:tests uv run --locked --all-extras python -m unittest test_oauth_contracts test_auth_routing test_managed_oauth_runtime test_oauth_registration test_oauth_discovery
```

The vendored `tests/fixtures/sdk-auth-lifecycle.json` comes from
`agent-hooks-protocol/conformance/draft/sdk-auth-lifecycle.json`. Its lifecycle
entries are a coverage manifest, not executable proof of SDK behavior; native
tests exercise the key/token vectors through actual HTTP, storage and dispatch.
