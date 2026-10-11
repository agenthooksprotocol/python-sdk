"""A real backend process: stdout contains protocol frames only."""

import anyio
from agenthooksprotocol import effect
from agenthooksprotocol.wire import InterceptRequest, ObserveNotification
from agenthooksprotocol.server import hooks, stdio


async def intercept(request: InterceptRequest) -> hooks.InterceptResult:
    return hooks.InterceptResult(
        effects=[effect.Deny(reason="Example policy rejects this operation")]
    )


async def observe(notification: ObserveNotification) -> None:
    return None


async def main() -> None:
    # Defaults borrow standard streams; serve does not close them.
    await stdio.serve(hooks.Handler(intercept=intercept, observe=observe))


if __name__ == "__main__":
    anyio.run(main)
