"""A real backend process: stdout contains protocol frames only."""

import anyio
from agenthooksprotocol import effect
from agenthooksprotocol.server import hooks, stdio


async def intercept(ctx: hooks.ToolBeforeContext) -> hooks.ToolBeforeReply:
    return hooks.ToolBeforeReply(
        effects=(effect.Deny(reason="Example policy rejects this operation"),)
    )


async def observe(ctx: hooks.ToolBeforeObserveContext) -> None:
    return None


async def main() -> None:
    # Defaults borrow standard streams; serve does not close them.
    await stdio.serve(
        hooks.Handlers(
            intercept=hooks.InterceptHandlers(tool_before=intercept),
            observe=hooks.ObserveHandlers(tool_before=observe),
        )
    )


if __name__ == "__main__":
    anyio.run(main)
