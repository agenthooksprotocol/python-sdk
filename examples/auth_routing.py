"""Compose local bearer references with a host-owned OAuth implementation.

This example does not exchange OAuth tokens or start a browser/listener. The
host_oauth argument implements the existing async AuthProvider protocol.
"""

from agenthooksprotocol import auth


def routing_provider(
    host_oauth: auth.AuthProvider,
    resolve_secret: auth.SecretResolver,
) -> auth.RoutingAuthProvider:
    return auth.RoutingAuthProvider(
        bearer=auth.BearerAuthProvider(resolve_credential=resolve_secret),
        oauth=host_oauth,
        discover=host_oauth,
        namespace="host-account/session-owner",
    )


async def vault_reference(reference: str) -> str | None:
    # Replace this allowlisted lookup with the host's async secret manager.
    # No credential values or references should be included in diagnostics.
    return {"vault/event": "example-event-token"}.get(reference)


# provider = routing_provider(host_oauth, vault_reference)
# hooks = Hooks(registration=registration, auth_provider=provider)
# The selected backend's bearer tokenRef may name "vault/event"; OAuth bindings
# use host_oauth. A missing secret never falls through to the OAuth route.
