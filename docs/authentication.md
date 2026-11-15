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
It remains responsible for OAuth discovery, trust policy, token storage,
coordination, consent UI, callback transport, exchange and refresh.

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

## Managed OAuth: security gate, not an available feature

This change does **not** ship a managed OAuth provider or an `oauth` extra.
Both authorization-code PKCE and client-credentials registrations still need a
host provider. Without one they return typed `unsupported_binding`, not an
apparently successful login or an anonymous fallback. No implicit browser,
listener, background worker, file store, or new persistent schema is introduced.

The opt-in compatibility spike in `tests/test_managed_oauth.py` verifies Authlib
1.6.12 `AsyncOAuth2Client` with HTTPX on asyncio and Trio: S256/state validation,
resource-bound PKCE completion and client-credentials exchange, explicit refresh
resource propagation, native cancellation, raw OAuth error descriptions, and
secret-bearing POST forwarding under a cross-origin 307. These are library
behavior probes, **not** end-to-end managed-provider acceptance tests. Authlib
alone neither supplies the AHP/MCP trust contract nor makes redirects safe.

Before exposing an adapter, it must implement MCP 2025-11-25 discovery ordering
(`resource_metadata`, path-specific/root fallback), RFC 9728 resource validation,
exact issuer validation, locally allowed scopes, RFC 8707 resource binding on
exchange and refresh, and host-controlled DNS/destination/redirect policy for
all metadata/registration/authorization/token endpoints. It also needs a
host-injected coordinated store with generation-safe refresh and pending-login
completion, stale-401 handling, cancellation during coordination/discovery,
bounded login attempts, and full redaction and parity evidence. No store
boundary or single-flight/refresh-rotation guarantee is claimed by this PR.

Reproduce the isolated dependency probes without changing the base install:

```sh
uv run --with 'authlib==1.6.12' python -m unittest discover -s tests -p test_managed_oauth.py
```
