"""Event-specific callback records and replies for the shared server engine.

Full generated envelopes remain available as evidence. Reply records omit
JSON-RPC IDs and protocol versions: correlation belongs to the server.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeAlias, TypeVar, overload

from ..codec import Codec
from ._slots import _ToolInput, _ToolCandidate

from .. import _models as models, event


@dataclass(frozen=True, slots=True, kw_only=True)
class _InterceptContext:
    params: models.InterceptRequestParams
    envelope: models.InterceptRequest
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True, kw_only=True)
class _ObserveContext:
    params: models.ObserveNotificationParams
    envelope: models.ObserveNotification
    raw: dict[str, Any]


InputT = TypeVar("InputT")


@overload
def ReplaceInput(args: Mapping[str, Any]) -> models.ModifyInputEffect: ...
@overload
def ReplaceInput(args: InputT, *, codec: Codec[InputT]) -> models.ModifyInputEffect: ...


def ReplaceInput(
    args: Any, *, codec: Codec[Any] | None = None
) -> models.ModifyInputEffect:
    """Replace a tool input, optionally encoding its caller-owned contract."""
    value = codec.encode(args) if codec is not None else dict(args)
    if not isinstance(value, dict):
        raise TypeError("Tool input must encode to an object")
    return models.ModifyInputEffect(target="input", operation="replace", value=value)


@overload
def MergeInput(args: Mapping[str, Any]) -> models.ModifyInputEffect: ...
@overload
def MergeInput(args: InputT, *, codec: Codec[InputT]) -> models.ModifyInputEffect: ...


def MergeInput(
    args: Any, *, codec: Codec[Any] | None = None
) -> models.ModifyInputEffect:
    """Shallow-merge a tool input; the host validates the declared contract."""
    value = codec.encode(args) if codec is not None else dict(args)
    if not isinstance(value, dict):
        raise TypeError("Tool input must encode to an object")
    return models.ModifyInputEffect(target="input", operation="merge", value=value)


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigChangeAfterObserveContext(_ObserveContext):
    event: event.ConfigChangeAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigChangeBeforeContext(_InterceptContext):
    event: event.ConfigChangeBeforeEvent
    capabilities: models.ConfigChangeBeforeCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigChangeBeforeReply:
    effects: tuple[models.DenyEffect | models.MessageEffect, ...] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigChangeBeforeObserveContext(_ObserveContext):
    event: event.ConfigChangeBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ContextCompactAfterContext(_InterceptContext):
    event: event.ContextCompactAfterEvent
    capabilities: models.ContextCompactAfterCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ContextCompactAfterReply:
    effects: tuple[
        models.ContextCompactAfterModifyEffect
        | models.InjectEffect
        | models.MessageEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ContextCompactAfterObserveContext(_ObserveContext):
    event: event.ContextCompactAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ContextCompactBeforeContext(_InterceptContext):
    event: event.ContextCompactBeforeEvent
    capabilities: models.ContextCompactBeforeCapabilities
    state: models.TextState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ContextCompactBeforeReply:
    effects: tuple[
        models.ContextCompactBeforeModifyEffect
        | models.DenyEffect
        | models.InjectEffect
        | models.MessageEffect
        | models.ReturnTextEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ContextCompactBeforeObserveContext(_ObserveContext):
    event: event.ContextCompactBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class FileChangedObserveContext(_ObserveContext):
    event: event.FileChangedEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class HookFailureObserveContext(_ObserveContext):
    event: event.HookFailureEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelErrorObserveContext(_ObserveContext):
    event: event.ModelErrorEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelRequestBeforeContext(_InterceptContext):
    event: event.ModelRequestBeforeEvent
    capabilities: models.ModelRequestBeforeCapabilities
    state: models.MessagesState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelRequestBeforeReply:
    effects: tuple[
        models.DenyEffect
        | models.InjectEffect
        | models.MessageEffect
        | models.ModelRequestBeforeModifyEffect
        | models.ReturnMessagesEffect
        | models.StopFlowEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelRequestBeforeObserveContext(_ObserveContext):
    event: event.ModelRequestBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelResponseAfterContext(_InterceptContext):
    event: event.ModelResponseAfterEvent
    capabilities: models.ModelResponseAfterCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelResponseAfterReply:
    effects: tuple[
        models.MessageEffect
        | models.ModelResponseAfterModifyEffect
        | models.StopFlowEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelResponseAfterObserveContext(_ObserveContext):
    event: event.ModelResponseAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelSwitchAfterObserveContext(_ObserveContext):
    event: event.ModelSwitchAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelSwitchBeforeContext(_InterceptContext):
    event: event.ModelSwitchBeforeEvent
    capabilities: models.ModelSwitchBeforeCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelSwitchBeforeReply:
    effects: tuple[
        models.DenyEffect | models.MessageEffect | models.StopFlowEffect, ...
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelSwitchBeforeObserveContext(_ObserveContext):
    event: event.ModelSwitchBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionEndObserveContext(_ObserveContext):
    event: event.SessionEndEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionStartContext(_InterceptContext):
    event: event.SessionStartEvent
    capabilities: models.SessionStartCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionStartReply:
    effects: tuple[models.InjectEffect | models.MessageEffect, ...] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionStartObserveContext(_ObserveContext):
    event: event.SessionStartEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskChangeAfterObserveContext(_ObserveContext):
    event: event.TaskChangeAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskChangeBeforeContext(_InterceptContext):
    event: event.TaskChangeBeforeEvent
    capabilities: models.TaskChangeBeforeCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskChangeBeforeReply:
    effects: tuple[models.DenyEffect | models.MessageEffect, ...] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskChangeBeforeObserveContext(_ObserveContext):
    event: event.TaskChangeBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolAfterContext(_InterceptContext, _ToolInput):
    event: event.ToolAfterEvent
    capabilities: models.ToolAfterCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolAfterReply:
    effects: tuple[
        models.ContinueFlowEffect
        | models.InjectEffect
        | models.MessageEffect
        | models.StopFlowEffect
        | models.ToolAfterModifyEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolAfterObserveContext(_ObserveContext, _ToolInput):
    event: event.ToolAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolBatchAfterContext(_InterceptContext):
    event: event.ToolBatchAfterEvent
    capabilities: models.ToolBatchAfterCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolBatchAfterReply:
    effects: tuple[
        models.InjectEffect | models.MessageEffect | models.StopFlowEffect, ...
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolBatchAfterObserveContext(_ObserveContext):
    event: event.ToolBatchAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolBeforeContext(_InterceptContext, _ToolInput, _ToolCandidate):
    event: event.ToolBeforeEvent
    capabilities: models.ToolBeforeCapabilities
    state: models.ToolState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolBeforeReply:
    effects: tuple[
        models.AllowEffect
        | models.AskEffect
        | models.DenyEffect
        | models.InjectEffect
        | models.MessageEffect
        | models.ReturnToolEffect
        | models.StopFlowEffect
        | models.ToolBeforeModifyEffect
        | models.ModifyInputEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolBeforeObserveContext(_ObserveContext, _ToolInput):
    event: event.ToolBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolPermissionRequestContext(_InterceptContext, _ToolInput, _ToolCandidate):
    event: event.ToolPermissionRequestEvent
    capabilities: models.ToolPermissionRequestCapabilities
    state: models.ToolState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolPermissionRequestReply:
    effects: tuple[
        models.AllowEffect
        | models.DenyEffect
        | models.MessageEffect
        | models.StopFlowEffect
        | models.ToolPermissionRequestModifyEffect
        | models.ModifyInputEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolPermissionRequestObserveContext(_ObserveContext, _ToolInput):
    event: event.ToolPermissionRequestEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolPermissionResolvedObserveContext(_ObserveContext):
    event: event.ToolPermissionResolvedEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ToolProgressObserveContext(_ObserveContext):
    event: event.ToolProgressEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnEndObserveContext(_ObserveContext):
    event: event.TurnEndEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnFinishBeforeContext(_InterceptContext):
    event: event.TurnFinishBeforeEvent
    capabilities: models.TurnFinishBeforeCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnFinishBeforeReply:
    effects: tuple[
        models.ContinueFlowEffect
        | models.MessageEffect
        | models.StopFlowEffect
        | models.TurnFinishBeforeModifyEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnFinishBeforeObserveContext(_ObserveContext):
    event: event.TurnFinishBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnProgressObserveContext(_ObserveContext):
    event: event.TurnProgressEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnStartContext(_InterceptContext):
    event: event.TurnStartEvent
    capabilities: models.TurnStartCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnStartReply:
    effects: tuple[
        models.DenyEffect
        | models.InjectEffect
        | models.MessageEffect
        | models.StopFlowEffect
        | models.TurnStartModifyEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class TurnStartObserveContext(_ObserveContext):
    event: event.TurnStartEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class UserAttentionObserveContext(_ObserveContext):
    event: event.UserAttentionEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class UserElicitationRequestContext(_InterceptContext):
    event: event.UserElicitationRequestEvent
    capabilities: models.UserElicitationRequestCapabilities
    state: models.ElicitResultState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserElicitationRequestReply:
    effects: tuple[
        models.DenyEffect | models.MessageEffect | models.ReturnElicitResultEffect, ...
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserElicitationRequestObserveContext(_ObserveContext):
    event: event.UserElicitationRequestEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class UserElicitationResultContext(_InterceptContext):
    event: event.UserElicitationResultEvent
    capabilities: models.UserElicitationResultCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserElicitationResultReply:
    effects: tuple[
        models.MessageEffect
        | models.UserElicitationResultModifyEffect
        | models.ModifyFormEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserElicitationResultObserveContext(_ObserveContext):
    event: event.UserElicitationResultEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class UserMessageInboundContext(_InterceptContext):
    event: event.UserMessageInboundEvent
    capabilities: models.UserMessageInboundCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserMessageInboundReply:
    effects: tuple[
        models.DenyEffect
        | models.MessageEffect
        | models.UserMessageInboundModifyEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserMessageInboundObserveContext(_ObserveContext):
    event: event.UserMessageInboundEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class UserMessageOutboundContext(_InterceptContext):
    event: event.UserMessageOutboundEvent
    capabilities: models.UserMessageOutboundCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserMessageOutboundReply:
    effects: tuple[
        models.DenyEffect
        | models.MessageEffect
        | models.UserMessageOutboundModifyEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserMessageOutboundObserveContext(_ObserveContext):
    event: event.UserMessageOutboundEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class WorkspaceChangeAfterObserveContext(_ObserveContext):
    event: event.WorkspaceChangeAfterEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class WorkspaceChangeBeforeContext(_InterceptContext):
    event: event.WorkspaceChangeBeforeEvent
    capabilities: models.WorkspaceChangeBeforeCapabilities
    state: models.InterceptRequestParamsState | None


@dataclass(frozen=True, slots=True, kw_only=True)
class WorkspaceChangeBeforeReply:
    effects: tuple[
        models.DenyEffect
        | models.MessageEffect
        | models.WorkspaceChangeBeforeModifyEffect
        | models.ModifyWorkspaceEffect,
        ...,
    ] = ()
    extensions: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class WorkspaceChangeBeforeObserveContext(_ObserveContext):
    event: event.WorkspaceChangeBeforeEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class InterceptHandlers:
    """Interception callbacks receive and return only their named event types."""

    config_change_before: (
        Callable[
            [ConfigChangeBeforeContext],
            ConfigChangeBeforeReply | Awaitable[ConfigChangeBeforeReply],
        ]
        | None
    ) = None
    context_compact_after: (
        Callable[
            [ContextCompactAfterContext],
            ContextCompactAfterReply | Awaitable[ContextCompactAfterReply],
        ]
        | None
    ) = None
    context_compact_before: (
        Callable[
            [ContextCompactBeforeContext],
            ContextCompactBeforeReply | Awaitable[ContextCompactBeforeReply],
        ]
        | None
    ) = None
    model_request_before: (
        Callable[
            [ModelRequestBeforeContext],
            ModelRequestBeforeReply | Awaitable[ModelRequestBeforeReply],
        ]
        | None
    ) = None
    model_response_after: (
        Callable[
            [ModelResponseAfterContext],
            ModelResponseAfterReply | Awaitable[ModelResponseAfterReply],
        ]
        | None
    ) = None
    model_switch_before: (
        Callable[
            [ModelSwitchBeforeContext],
            ModelSwitchBeforeReply | Awaitable[ModelSwitchBeforeReply],
        ]
        | None
    ) = None
    session_start: (
        Callable[
            [SessionStartContext], SessionStartReply | Awaitable[SessionStartReply]
        ]
        | None
    ) = None
    task_change_before: (
        Callable[
            [TaskChangeBeforeContext],
            TaskChangeBeforeReply | Awaitable[TaskChangeBeforeReply],
        ]
        | None
    ) = None
    tool_after: (
        Callable[[ToolAfterContext], ToolAfterReply | Awaitable[ToolAfterReply]] | None
    ) = None
    tool_batch_after: (
        Callable[
            [ToolBatchAfterContext],
            ToolBatchAfterReply | Awaitable[ToolBatchAfterReply],
        ]
        | None
    ) = None
    tool_before: (
        Callable[[ToolBeforeContext], ToolBeforeReply | Awaitable[ToolBeforeReply]]
        | None
    ) = None
    tool_permission_request: (
        Callable[
            [ToolPermissionRequestContext],
            ToolPermissionRequestReply | Awaitable[ToolPermissionRequestReply],
        ]
        | None
    ) = None
    turn_finish_before: (
        Callable[
            [TurnFinishBeforeContext],
            TurnFinishBeforeReply | Awaitable[TurnFinishBeforeReply],
        ]
        | None
    ) = None
    turn_start: (
        Callable[[TurnStartContext], TurnStartReply | Awaitable[TurnStartReply]] | None
    ) = None
    user_elicitation_request: (
        Callable[
            [UserElicitationRequestContext],
            UserElicitationRequestReply | Awaitable[UserElicitationRequestReply],
        ]
        | None
    ) = None
    user_elicitation_result: (
        Callable[
            [UserElicitationResultContext],
            UserElicitationResultReply | Awaitable[UserElicitationResultReply],
        ]
        | None
    ) = None
    user_message_inbound: (
        Callable[
            [UserMessageInboundContext],
            UserMessageInboundReply | Awaitable[UserMessageInboundReply],
        ]
        | None
    ) = None
    user_message_outbound: (
        Callable[
            [UserMessageOutboundContext],
            UserMessageOutboundReply | Awaitable[UserMessageOutboundReply],
        ]
        | None
    ) = None
    workspace_change_before: (
        Callable[
            [WorkspaceChangeBeforeContext],
            WorkspaceChangeBeforeReply | Awaitable[WorkspaceChangeBeforeReply],
        ]
        | None
    ) = None


AnyObserveContext: TypeAlias = (
    ConfigChangeAfterObserveContext
    | ConfigChangeBeforeObserveContext
    | ContextCompactAfterObserveContext
    | ContextCompactBeforeObserveContext
    | FileChangedObserveContext
    | HookFailureObserveContext
    | ModelErrorObserveContext
    | ModelRequestBeforeObserveContext
    | ModelResponseAfterObserveContext
    | ModelSwitchAfterObserveContext
    | ModelSwitchBeforeObserveContext
    | SessionEndObserveContext
    | SessionStartObserveContext
    | TaskChangeAfterObserveContext
    | TaskChangeBeforeObserveContext
    | ToolAfterObserveContext
    | ToolBatchAfterObserveContext
    | ToolBeforeObserveContext
    | ToolPermissionRequestObserveContext
    | ToolPermissionResolvedObserveContext
    | ToolProgressObserveContext
    | TurnEndObserveContext
    | TurnFinishBeforeObserveContext
    | TurnProgressObserveContext
    | TurnStartObserveContext
    | UserAttentionObserveContext
    | UserElicitationRequestObserveContext
    | UserElicitationResultObserveContext
    | UserMessageInboundObserveContext
    | UserMessageOutboundObserveContext
    | WorkspaceChangeAfterObserveContext
    | WorkspaceChangeBeforeObserveContext
)
"""Any event-specific observation context, as passed to ``ObserveHandlers.any``."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ObserveHandlers:
    """Observation callbacks cannot return protocol controls.

    ``any`` is an optional catch-all invoked with the event-specific context only
    when no per-event callback is registered for the observed event.
    """

    any: Callable[[AnyObserveContext], None | Awaitable[None]] | None = None

    config_change_after: (
        Callable[[ConfigChangeAfterObserveContext], None | Awaitable[None]] | None
    ) = None
    config_change_before: (
        Callable[[ConfigChangeBeforeObserveContext], None | Awaitable[None]] | None
    ) = None
    context_compact_after: (
        Callable[[ContextCompactAfterObserveContext], None | Awaitable[None]] | None
    ) = None
    context_compact_before: (
        Callable[[ContextCompactBeforeObserveContext], None | Awaitable[None]] | None
    ) = None
    file_changed: (
        Callable[[FileChangedObserveContext], None | Awaitable[None]] | None
    ) = None
    hook_failure: (
        Callable[[HookFailureObserveContext], None | Awaitable[None]] | None
    ) = None
    model_error: Callable[[ModelErrorObserveContext], None | Awaitable[None]] | None = (
        None
    )
    model_request_before: (
        Callable[[ModelRequestBeforeObserveContext], None | Awaitable[None]] | None
    ) = None
    model_response_after: (
        Callable[[ModelResponseAfterObserveContext], None | Awaitable[None]] | None
    ) = None
    model_switch_after: (
        Callable[[ModelSwitchAfterObserveContext], None | Awaitable[None]] | None
    ) = None
    model_switch_before: (
        Callable[[ModelSwitchBeforeObserveContext], None | Awaitable[None]] | None
    ) = None
    session_end: Callable[[SessionEndObserveContext], None | Awaitable[None]] | None = (
        None
    )
    session_start: (
        Callable[[SessionStartObserveContext], None | Awaitable[None]] | None
    ) = None
    task_change_after: (
        Callable[[TaskChangeAfterObserveContext], None | Awaitable[None]] | None
    ) = None
    task_change_before: (
        Callable[[TaskChangeBeforeObserveContext], None | Awaitable[None]] | None
    ) = None
    tool_after: Callable[[ToolAfterObserveContext], None | Awaitable[None]] | None = (
        None
    )
    tool_batch_after: (
        Callable[[ToolBatchAfterObserveContext], None | Awaitable[None]] | None
    ) = None
    tool_before: Callable[[ToolBeforeObserveContext], None | Awaitable[None]] | None = (
        None
    )
    tool_permission_request: (
        Callable[[ToolPermissionRequestObserveContext], None | Awaitable[None]] | None
    ) = None
    tool_permission_resolved: (
        Callable[[ToolPermissionResolvedObserveContext], None | Awaitable[None]] | None
    ) = None
    tool_progress: (
        Callable[[ToolProgressObserveContext], None | Awaitable[None]] | None
    ) = None
    turn_end: Callable[[TurnEndObserveContext], None | Awaitable[None]] | None = None
    turn_finish_before: (
        Callable[[TurnFinishBeforeObserveContext], None | Awaitable[None]] | None
    ) = None
    turn_progress: (
        Callable[[TurnProgressObserveContext], None | Awaitable[None]] | None
    ) = None
    turn_start: Callable[[TurnStartObserveContext], None | Awaitable[None]] | None = (
        None
    )
    user_attention: (
        Callable[[UserAttentionObserveContext], None | Awaitable[None]] | None
    ) = None
    user_elicitation_request: (
        Callable[[UserElicitationRequestObserveContext], None | Awaitable[None]] | None
    ) = None
    user_elicitation_result: (
        Callable[[UserElicitationResultObserveContext], None | Awaitable[None]] | None
    ) = None
    user_message_inbound: (
        Callable[[UserMessageInboundObserveContext], None | Awaitable[None]] | None
    ) = None
    user_message_outbound: (
        Callable[[UserMessageOutboundObserveContext], None | Awaitable[None]] | None
    ) = None
    workspace_change_after: (
        Callable[[WorkspaceChangeAfterObserveContext], None | Awaitable[None]] | None
    ) = None
    workspace_change_before: (
        Callable[[WorkspaceChangeBeforeObserveContext], None | Awaitable[None]] | None
    ) = None


_INTERCEPT_CONTEXTS: dict[str, Any] = {
    "config.change.before": (
        ConfigChangeBeforeContext,
        ConfigChangeBeforeReply,
        models.ConfigChangeBeforeCapabilities,
        models.InterceptRequestParamsState,
    ),
    "context.compact.after": (
        ContextCompactAfterContext,
        ContextCompactAfterReply,
        models.ContextCompactAfterCapabilities,
        models.InterceptRequestParamsState,
    ),
    "context.compact.before": (
        ContextCompactBeforeContext,
        ContextCompactBeforeReply,
        models.ContextCompactBeforeCapabilities,
        models.TextState,
    ),
    "model.request.before": (
        ModelRequestBeforeContext,
        ModelRequestBeforeReply,
        models.ModelRequestBeforeCapabilities,
        models.MessagesState,
    ),
    "model.response.after": (
        ModelResponseAfterContext,
        ModelResponseAfterReply,
        models.ModelResponseAfterCapabilities,
        models.InterceptRequestParamsState,
    ),
    "model.switch.before": (
        ModelSwitchBeforeContext,
        ModelSwitchBeforeReply,
        models.ModelSwitchBeforeCapabilities,
        models.InterceptRequestParamsState,
    ),
    "session.start": (
        SessionStartContext,
        SessionStartReply,
        models.SessionStartCapabilities,
        models.InterceptRequestParamsState,
    ),
    "task.change.before": (
        TaskChangeBeforeContext,
        TaskChangeBeforeReply,
        models.TaskChangeBeforeCapabilities,
        models.InterceptRequestParamsState,
    ),
    "tool.after": (
        ToolAfterContext,
        ToolAfterReply,
        models.ToolAfterCapabilities,
        models.InterceptRequestParamsState,
    ),
    "tool.batch.after": (
        ToolBatchAfterContext,
        ToolBatchAfterReply,
        models.ToolBatchAfterCapabilities,
        models.InterceptRequestParamsState,
    ),
    "tool.before": (
        ToolBeforeContext,
        ToolBeforeReply,
        models.ToolBeforeCapabilities,
        models.ToolState,
    ),
    "tool.permission.request": (
        ToolPermissionRequestContext,
        ToolPermissionRequestReply,
        models.ToolPermissionRequestCapabilities,
        models.ToolState,
    ),
    "turn.finish.before": (
        TurnFinishBeforeContext,
        TurnFinishBeforeReply,
        models.TurnFinishBeforeCapabilities,
        models.InterceptRequestParamsState,
    ),
    "turn.start": (
        TurnStartContext,
        TurnStartReply,
        models.TurnStartCapabilities,
        models.InterceptRequestParamsState,
    ),
    "user.elicitation.request": (
        UserElicitationRequestContext,
        UserElicitationRequestReply,
        models.UserElicitationRequestCapabilities,
        models.ElicitResultState,
    ),
    "user.elicitation.result": (
        UserElicitationResultContext,
        UserElicitationResultReply,
        models.UserElicitationResultCapabilities,
        models.InterceptRequestParamsState,
    ),
    "user.message.inbound": (
        UserMessageInboundContext,
        UserMessageInboundReply,
        models.UserMessageInboundCapabilities,
        models.InterceptRequestParamsState,
    ),
    "user.message.outbound": (
        UserMessageOutboundContext,
        UserMessageOutboundReply,
        models.UserMessageOutboundCapabilities,
        models.InterceptRequestParamsState,
    ),
    "workspace.change.before": (
        WorkspaceChangeBeforeContext,
        WorkspaceChangeBeforeReply,
        models.WorkspaceChangeBeforeCapabilities,
        models.InterceptRequestParamsState,
    ),
}
_OBSERVE_CONTEXTS: dict[str, Any] = {
    "config.change.after": ConfigChangeAfterObserveContext,
    "config.change.before": ConfigChangeBeforeObserveContext,
    "context.compact.after": ContextCompactAfterObserveContext,
    "context.compact.before": ContextCompactBeforeObserveContext,
    "file.changed": FileChangedObserveContext,
    "hook.failure": HookFailureObserveContext,
    "model.error": ModelErrorObserveContext,
    "model.request.before": ModelRequestBeforeObserveContext,
    "model.response.after": ModelResponseAfterObserveContext,
    "model.switch.after": ModelSwitchAfterObserveContext,
    "model.switch.before": ModelSwitchBeforeObserveContext,
    "session.end": SessionEndObserveContext,
    "session.start": SessionStartObserveContext,
    "task.change.after": TaskChangeAfterObserveContext,
    "task.change.before": TaskChangeBeforeObserveContext,
    "tool.after": ToolAfterObserveContext,
    "tool.batch.after": ToolBatchAfterObserveContext,
    "tool.before": ToolBeforeObserveContext,
    "tool.permission.request": ToolPermissionRequestObserveContext,
    "tool.permission.resolved": ToolPermissionResolvedObserveContext,
    "tool.progress": ToolProgressObserveContext,
    "turn.end": TurnEndObserveContext,
    "turn.finish.before": TurnFinishBeforeObserveContext,
    "turn.progress": TurnProgressObserveContext,
    "turn.start": TurnStartObserveContext,
    "user.attention": UserAttentionObserveContext,
    "user.elicitation.request": UserElicitationRequestObserveContext,
    "user.elicitation.result": UserElicitationResultObserveContext,
    "user.message.inbound": UserMessageInboundObserveContext,
    "user.message.outbound": UserMessageOutboundObserveContext,
    "workspace.change.after": WorkspaceChangeAfterObserveContext,
    "workspace.change.before": WorkspaceChangeBeforeObserveContext,
}

__all__ = [
    "InterceptHandlers",
    "ObserveHandlers",
    "AnyObserveContext",
    "ReplaceInput",
    "MergeInput",
    "ConfigChangeAfterObserveContext",
    "ConfigChangeBeforeContext",
    "ConfigChangeBeforeReply",
    "ConfigChangeBeforeObserveContext",
    "ContextCompactAfterContext",
    "ContextCompactAfterReply",
    "ContextCompactAfterObserveContext",
    "ContextCompactBeforeContext",
    "ContextCompactBeforeReply",
    "ContextCompactBeforeObserveContext",
    "FileChangedObserveContext",
    "HookFailureObserveContext",
    "ModelErrorObserveContext",
    "ModelRequestBeforeContext",
    "ModelRequestBeforeReply",
    "ModelRequestBeforeObserveContext",
    "ModelResponseAfterContext",
    "ModelResponseAfterReply",
    "ModelResponseAfterObserveContext",
    "ModelSwitchAfterObserveContext",
    "ModelSwitchBeforeContext",
    "ModelSwitchBeforeReply",
    "ModelSwitchBeforeObserveContext",
    "SessionEndObserveContext",
    "SessionStartContext",
    "SessionStartReply",
    "SessionStartObserveContext",
    "TaskChangeAfterObserveContext",
    "TaskChangeBeforeContext",
    "TaskChangeBeforeReply",
    "TaskChangeBeforeObserveContext",
    "ToolAfterContext",
    "ToolAfterReply",
    "ToolAfterObserveContext",
    "ToolBatchAfterContext",
    "ToolBatchAfterReply",
    "ToolBatchAfterObserveContext",
    "ToolBeforeContext",
    "ToolBeforeReply",
    "ToolBeforeObserveContext",
    "ToolPermissionRequestContext",
    "ToolPermissionRequestReply",
    "ToolPermissionRequestObserveContext",
    "ToolPermissionResolvedObserveContext",
    "ToolProgressObserveContext",
    "TurnEndObserveContext",
    "TurnFinishBeforeContext",
    "TurnFinishBeforeReply",
    "TurnFinishBeforeObserveContext",
    "TurnProgressObserveContext",
    "TurnStartContext",
    "TurnStartReply",
    "TurnStartObserveContext",
    "UserAttentionObserveContext",
    "UserElicitationRequestContext",
    "UserElicitationRequestReply",
    "UserElicitationRequestObserveContext",
    "UserElicitationResultContext",
    "UserElicitationResultReply",
    "UserElicitationResultObserveContext",
    "UserMessageInboundContext",
    "UserMessageInboundReply",
    "UserMessageInboundObserveContext",
    "UserMessageOutboundContext",
    "UserMessageOutboundReply",
    "UserMessageOutboundObserveContext",
    "WorkspaceChangeAfterObserveContext",
    "WorkspaceChangeBeforeContext",
    "WorkspaceChangeBeforeReply",
    "WorkspaceChangeBeforeObserveContext",
]
