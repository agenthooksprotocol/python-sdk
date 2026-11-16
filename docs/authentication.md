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
- An unbound endpoint starts anonymously. Only its challenge is sent to
  `discover`, when supplied. Successful anonymous requests stay anonymous.
- Missing configured credentials raise `credential_unavailable` before HTTP
  delivery. Failure never falls through to another route or anonymous delivery.
- Opaque attempt identities retain the issuing provider and original identity,
  even if the router's configured route changes while HTTP is in flight.
  Attempts cannot cross namespaces, destinations, backends, or event/upload
  purposes. The router itself owns no cache or coordinated registry.
- The transport still owns bounded replay: eligible interception/configuration
  requests can replay once; observations and uploads never replay. Providers
  must not independently resend the application request.

`auth.normalize_auth_target(context, namespace=...)` returns a frozen
`AuthTarget`, with a deeply read-only wire `binding` (including extensions) and
`typed_binding` of `BearerBinding`, `OAuthBinding`, or `None`. `kind` is
`bearer`, `oauth`, or `discover`. OAuth fields use snake_case, and requested scopes
are sorted/deduplicated. `destination` remains separate from OAuth `resource`.
`identity` includes namespace, backend, purpose, full destination and typed
binding; it is an isolation key, not a persistent record or log-safe string.
Normalization validates syntax only, not DNS/egress authorization.

`AuthenticationFailure` remains a `ProtocolError` and adds safe `code` and
optional `recovery` (`configure`, `login`, `retry`, `stop`). Codes are
`invalid_configuration`, `unsupported_binding`, `credential_unavailable`,
`interaction_required`, `access_denied`, `refresh_rejected`, `discovery_failed`,
`untrusted_destination`, and `provider_failed`. Public exception text is fixed;
legacy positional messages and raw provider exceptions are not exposed.
Structured provider classifications survive the transport boundary, without
retaining secret-bearing exception contexts. Cancellation remains native under
asyncio and Trio, and provider calls stay inside the enclosing operation budget.

## Optional managed OAuth

Install `agenthooksprotocol[oauth]` to use `agenthooksprotocol.oauth`. The extra
adds Authlib, HTTPX2 and HTTPX; core and stdio installs do not need them. Importing the
module does not start network activity or require Authlib. Exchanges require the
extra. Authlib 1.9.6 uses its supported HTTPX2 integration, not the deprecated
HTTPX fallback. HTTPX2 and HTTPX have distinct request, response and stream
classes: the adapter explicitly bridges buffered OAuth messages to the existing
HTTPX-based host network contract. Hosts do not need to migrate their clients.
HTTPX2's HTTPcore2/truststore dependencies are confined to the optional extra;
actual OAuth connections still pass through the host's TLS/DNS/egress boundary,
with environment trust disabled and no redirect following.
The older Authlib compatibility probes remain library-level tests;
`tests/test_managed_oauth_runtime.py` and `tests/test_oauth_discovery.py` exercise
the managed implementation on asyncio and Trio.

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
See [the typed host-controlled example](../examples/managed_oauth.py). It takes
host capabilities rather than offering an unsafe sample DNS policy or token store.
No persistent schema changes or dynamic client registration are introduced.

### Prepare, interact, complete

`managed.prepare(target, budget, challenge=None)` accepts a normalized
`auth.AuthTarget` and returns either `oauth.Ready` (with a `credential`) or
`oauth.PendingLogin`. Client credentials exchange without interaction; the
`authorization_code_pkce` flow creates an S256 authorization URL. The host must
supply locally configured client details and a callback URI for PKCE.

For a pending login, the host displays `authorization_url`, receives a callback
through its own authenticated application flow, and calls
`managed.complete(target, pending, callback_url, budget)`, which returns `Ready`.
Do not log the authorization URL, callback, store keys, credential identity,
client secrets or tokens. Retain the pending handle for that target and user;
it is not a wire value. Completion validates the pending generation, lifetime,
callback, state and issuer requirements before exchanging the code. Repeated
prepare calls share the pending generation rather than launching new logins.

Create `oauth.OperationBudget.after(seconds)` inside an active AnyIO task.
Its absolute monotonic deadline includes coordination, discovery and exchange;
nested work cannot reset it or extend an enclosing cancellation deadline. User
interaction happens outside these bounded operations. Give completion a new
budget after the callback arrives, still within the pending login lifetime
(`OAuthClientConfiguration.login_lifetime`, default 300 seconds).

The provider also implements `credential` and `challenge` for `Hooks` routing.
These calls have a default 30-second `operation_timeout`, capped by the enclosing
operation. A pending login raises `AuthenticationFailure` with
`code="interaction_required"` and `recovery="login"`; it does not open UI or
return a pending handle through the transport. The host uses `prepare` to obtain
that handle. Unbound acquisition stays anonymous until a challenge.

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
- **`OAuthTokenStore`**: `coordinate(key, budget)` yields an exclusive guard
  with `load()` and atomic `compare_and_swap(expected_generation, record)`.
  Exclusion must cover all providers/processes sharing the key, including
  network awaits under that guard. Host callbacks must not reenter the same
  key. Persist secrets securely, and make acquisition cancellation-aware.
  A plain dictionary or per-provider lock does not satisfy shared coordination.

The helper performs protected-resource metadata discovery with challenged
`resource_metadata` and path-specific/root fallback, resource/issuer validation,
local scope checks, and RFC 8707 resource binding on exchange and refresh.
The store key separates credential namespace, backend, event/upload purpose,
destination, binding, resource, issuer and client configuration. Do not reuse
event credentials as an upload fallback.

### Rotation, failure and repair

Guarded generation reservations coalesce exchange/refresh and protect against
stale 401s invalidating a newer credential. A failed or cancelled refresh/code
exchange can leave a reservation unusable rather than risk reusing a rotated
refresh token. Definitive rejection is classified separately from transient
failure; native cancellation still propagates. Host storage may have committed
a cancelled write, so never restore an old token blindly.

`managed.reset(target, budget, handle=pending_or_credential)` is an explicit host
repair/logout action. A retained handle avoids discovery; without one, reset
performs discovery (and accepts an optional `challenge`). Reset clears the
**current** generation, not merely the handle's old generation. Do not call it
automatically for stale 401s. The host decides whether and when to start a new
login. `expiry_skew` defaults to 30 seconds. There is no background refresh,
browser, listener, worker, implicit file store or application-request replay.

CI installs the OAuth extra, Trio and `trustme` for the local TLS test; the unittest suites exercise both AnyIO
backends internally. Run the focused checks with:

```sh
python -m pip install -e '.[oauth]' trio trustme
python -m unittest discover -s tests -p 'test_*oauth*.py'
```
