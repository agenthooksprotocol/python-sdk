"""Serve request-local configuration through the ordinary server handler API.

Run as an NDJSON stdio backend with:
    python examples/dynamic_configuration.py

ASGI applications can mount ``app`` behind their authentication middleware.
Middleware selects ``request_configuration`` for its authenticated request and
resets its ContextVar token afterwards; AHP request fields are not identity.
"""

from contextvars import ContextVar
from datetime import timedelta

import anyio

from agenthooksprotocol import Configuration, content, event, subscription
from agenthooksprotocol.server import asgi, hooks, stdio


def policy(timeout: timedelta) -> Configuration:
    return Configuration(
        subscriptions=[
            subscription.Intercept(
                events=[event.TOOL_BEFORE],
                timeout=timeout,
                failure_policy=subscription.FailurePolicy.FAIL_OPEN,
                content=content.metadata(),
            ),
        ],
    )


request_configuration: ContextVar[Configuration] = ContextVar(
    "request_configuration", default=policy(timedelta(milliseconds=750))
)


async def configure(ctx: hooks.ConfigurationContext) -> Configuration:
    # ctx.params, ctx.envelope, and ctx.raw are validated request evidence.
    # The selected policy belongs to the enclosing application request context.
    return request_configuration.get()


def before(ctx: hooks.ToolBeforeContext) -> hooks.ToolBeforeReply:
    return hooks.ToolBeforeReply()


handlers = hooks.Handlers(
    configuration=configure,
    intercept=hooks.InterceptHandlers(tool_before=before),
)
app = asgi.App(handlers)


if __name__ == "__main__":
    anyio.run(stdio.serve, handlers)
