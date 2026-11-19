"""Host-controlled OAuth composition; no sample production network or store.

Install agenthooksprotocol[oauth]. The host supplies policy, a DNS/egress-safe
network, and a coordinated secret store; see docs/authentication.md. This module
starts no browser, listener, worker or HTTP client, and prints no credentials.
"""

from collections.abc import Awaitable, Callable

from agenthooksprotocol import auth, oauth


NAMESPACE = "host-account/session-owner"


def managed_provider(
    network: oauth.OAuthNetwork,
    policy: oauth.OAuthTrustPolicy,
    store: oauth.OAuthTokenStore,
) -> oauth.ManagedOAuthProvider:
    """Borrow host capabilities; their lifecycle remains with the host."""
    return oauth.ManagedOAuthProvider(
        network=network,
        policy=policy,
        store=store,
        namespace=NAMESPACE,
    )


def routing_provider(
    managed: oauth.ManagedOAuthProvider,
    resolve_secret: auth.SecretResolver,
) -> auth.RoutingAuthProvider:
    """Pass this router to Hooks(auth_provider=...)."""
    return auth.RoutingAuthProvider(
        bearer=auth.BearerAuthProvider(resolve_credential=resolve_secret),
        oauth=managed,
        discover=managed,
        namespace=NAMESPACE,
    )


async def login(
    managed: oauth.ManagedOAuthProvider,
    context: auth.AuthContext,
    interact: Callable[[oauth.PendingLogin], Awaitable[str]],
    *,
    challenge: auth.AuthChallenge | None = None,
) -> oauth.Ready:
    """Prepare and complete a login in the host's authenticated user session.

    interact displays pending.authorization_url and receives the callback URL
    through host-owned UI/transport. It must bind the pending handle to this user
    and target, enforce its expires_at, and never log either URL. Client
    credentials can return Ready immediately without invoking interact.
    """
    target = auth.normalize_auth_target(context, namespace=NAMESPACE)
    # The pending login lives in this provider with its own fixed lifetime; each
    # call has a short budget and the user interaction happens between them.
    result = await managed.prepare(
        target, oauth.OperationBudget.after(30), challenge=challenge
    )
    if isinstance(result, oauth.Ready):
        return result
    # No SDK browser or listener is created. With persist_pending_logins=True,
    # another process sharing the store can complete it by the callback state.
    callback_url = await interact(result)
    return await managed.complete(
        target, result, callback_url, oauth.OperationBudget.after(30)
    )


# To abandon consent without deleting a valid grant:
# await managed.cancel(target, pending, oauth.OperationBudget.after(5))
# On an explicit host logout/repair action, not automatically on a stale 401:
# await managed.reset(target, oauth.OperationBudget.after(30), handle=pending)
# The next Hooks request acquires its credential through routing_provider.
