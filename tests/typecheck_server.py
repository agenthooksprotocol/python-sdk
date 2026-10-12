"""Static server contract fixture: run mypy with --warn-unused-ignores.

Every intentional rejection has an error-code-specific ignore. An API that
silently permits one of these calls produces an unused-ignore diagnostic.
"""

from typing import assert_type

from agenthooksprotocol import effect, event
from agenthooksprotocol.codec import Codec
from agenthooksprotocol.contract import Candidate
from agenthooksprotocol.server import hooks


def before(ctx: hooks.ToolBeforeContext) -> hooks.ToolBeforeReply:
    assert_type(ctx.event, event.ToolBeforeEvent)
    return hooks.ToolBeforeReply(
        effects=(hooks.ReplaceInput({"safe": True}), effect.Allow())
    )


async def async_before(ctx: hooks.ToolBeforeContext) -> hooks.ToolBeforeReply:
    return before(ctx)


def observe(ctx: hooks.ToolBeforeObserveContext) -> None:
    assert_type(ctx.event, event.ToolBeforeEvent)


async def async_observe(ctx: hooks.ToolBeforeObserveContext) -> None:
    observe(ctx)


hooks.Handlers(
    intercept=hooks.InterceptHandlers(tool_before=before),
    observe=hooks.ObserveHandlers(tool_before=observe),
)
hooks.Handlers(
    intercept=hooks.InterceptHandlers(tool_before=async_before),
    observe=hooks.ObserveHandlers(tool_before=async_observe),
)


def after(ctx: hooks.ToolAfterContext) -> hooks.ToolAfterReply:
    return hooks.ToolAfterReply()


def wrong_reply(ctx: hooks.ToolBeforeContext) -> hooks.ToolAfterReply:
    return hooks.ToolAfterReply()


def observe_control(ctx: hooks.ToolBeforeObserveContext) -> hooks.ToolBeforeReply:
    return hooks.ToolBeforeReply()


def observe_any(ctx: hooks.AnyObserveContext) -> None:
    event_type: str = ctx.event.type
    if isinstance(ctx, hooks.ToolBeforeObserveContext):
        assert_type(ctx.event, event.ToolBeforeEvent)
    del event_type


async def async_observe_any(ctx: hooks.AnyObserveContext) -> None:
    observe_any(ctx)


hooks.ObserveHandlers(tool_before=observe, any=observe_any)
hooks.ObserveHandlers(any=async_observe_any)
hooks.ObserveHandlers(any=observe)  # type: ignore[arg-type]
hooks.InterceptHandlers(tool_before=after)  # type: ignore[arg-type]
hooks.InterceptHandlers(tool_before=wrong_reply)  # type: ignore[arg-type]
hooks.ObserveHandlers(tool_before=observe_control)  # type: ignore[arg-type]
hooks.ToolAfterReply(effects=(effect.Allow(),))  # type: ignore[arg-type]
hooks.ToolBeforeReply(effects=[])  # type: ignore[arg-type]
hooks.Handlers(intercept=before)  # type: ignore[arg-type]


def input_slot(ctx: hooks.ToolBeforeContext, codec: Codec[int]) -> None:
    assert_type(ctx.decode_input(codec), int)
    hooks.ReplaceInput(1, codec=codec)
    hooks.ReplaceInput("wrong", codec=codec)  # type: ignore[misc]


def candidate_slot(
    ctx: hooks.ToolBeforeContext, result: Codec[str], provenance: Codec[bool]
) -> None:
    assert_type(ctx.decode_candidate(result, provenance), Candidate[str, bool] | None)
