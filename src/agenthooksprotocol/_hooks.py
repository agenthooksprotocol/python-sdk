"""Public asynchronous harness; schema validation and settlement stay canonical.

Capabilities map event names to ``{modes: [...], capabilities: {...}}``.
Dispatch inputs are event-specific payload objects, not tool arguments alone.
Ordinary host authorization and domain validation remain the caller's job.
"""

from __future__ import annotations

from typing import Any, TypeVar
from types import TracebackType
from .codec import Codec
from .generated import JsonValue

from copy import deepcopy
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

import anyio
from jsonschema import FormatChecker

from .runtime import ProtocolError, Validator, apply_response
from .lifecycle import Lifecycle
from .lineage import TaskLineage
from ._boundaries import BoundaryMixin
from ._content import ContentContext, merge_effective, project_content

T = TypeVar("T")


@dataclass
class HookResult:
    """Raw committed wire state. Decoding never rolls back accepted effects."""

    event: dict[str, Any]
    state: dict[str, Any]
    accepted_responses: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    @property
    def input(self) -> JsonValue:
        return deepcopy(self.state.get("input", {}))

    @property
    def effective_input(self) -> JsonValue:
        return self.input

    @property
    def decision(self) -> str:
        return self.state.get("decision", "allow")

    @property
    def permission(self) -> str:
        return self.state.get("permission", "none")

    @property
    def candidate(self) -> dict[str, Any] | None:
        """Settled candidate, not authorization to deliver it."""
        return deepcopy(self.state.get("candidate"))

    @property
    def accepted_response(self) -> dict[str, Any] | None:
        return (
            deepcopy(self.accepted_responses[-1]) if self.accepted_responses else None
        )

    def decode_input(self, codec: Codec[T]) -> T:
        return codec.decode(self.input)

    @property
    def content(self) -> dict[str, Any]:
        """Explicit settled body targets; no inferred primary content."""
        return deepcopy(self.state.get("content", {}))

    @property
    def content_references(self) -> dict[str, Any]:
        return deepcopy(self.state.get("content_references", {}))

    def decode_content(self, target: str, codec: Codec[T]) -> T:
        return codec.decode(deepcopy(self.state["content"][target]))


class PendingInvocation:
    """A single canonical lifecycle, with acquisition separate from acceptance."""

    def __init__(
        self,
        request: dict[str, Any],
        validator: Validator,
        transport: Any,
        content: ContentContext | None = None,
    ) -> None:
        self.request = deepcopy(request)
        self.transport = transport
        self.lifecycle = Lifecycle(validator, include_staged=True)
        self.lifecycle.send(self.request)
        self.content = content
        self.prepared_content = None
        self.response = None
        self.result = None
        self._scope = None

    async def acquire(self) -> dict[str, Any] | None:
        if self.transport is None:
            raise RuntimeError("No transport configured")
        if self._scope is not None:
            raise RuntimeError("Invocation already has an active acquisition")
        with anyio.CancelScope() as scope:
            self._scope = scope
            try:
                if self.content is not None:
                    self.prepared_content = await self.content.prepare(
                        self.request, self.lifecycle.validator
                    )
                response = await self.transport.request(deepcopy(self.request))
                self.receive(response)
                return response
            except BaseException as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    self.lifecycle.cancel(self.request["id"])
                raise
            finally:
                self._scope = None
        return None

    def receive(self, response: dict[str, Any]) -> bool:
        accepted = self.lifecycle.receive(self.request, response)
        if accepted:
            self.response = deepcopy(response)
        return accepted

    def accept(self, *, fallback: bool = False) -> HookResult | None:
        if self.content is not None:
            raise RuntimeError(
                "Content-bound invocations require await accept_content()"
            )
        state = self.lifecycle.accept(self.request["id"], fallback=fallback)
        return self._publish(state, fallback)

    async def accept_content(self, *, fallback: bool = False) -> HookResult | None:
        if self.content is None:
            return self.accept(fallback=fallback)
        if fallback:
            return self._publish(
                self.lifecycle.accept(self.request["id"], fallback=True), True
            )
        if self._scope is not None:
            raise RuntimeError("Invocation already has an active operation")
        token = None
        with anyio.CancelScope() as scope:
            self._scope = scope
            try:
                if self.prepared_content is None:
                    self.prepared_content = await self.content.prepare(
                        self.request, self.lifecycle.validator
                    )
                prepared = self.lifecycle.prepare_accept(
                    self.request["id"], fallback=fallback, content=self.prepared_content
                )
                if prepared is None:
                    return None
                token, state = prepared
                state = await self.prepared_content.finalize(state)
                committed = self.lifecycle.commit_accept(
                    self.request["id"], token, state
                )
                return self._publish(committed, fallback)
            except BaseException as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    self.lifecycle.cancel(self.request["id"])
                elif token is not None:
                    self.lifecycle.abort_accept(self.request["id"], token)
                raise
            finally:
                self._scope = None
        return None

    def _publish(
        self, state: dict[str, Any] | None, fallback: bool
    ) -> HookResult | None:
        if state is None:
            return None
        event = deepcopy(state.get("event", self.request["params"]["event"]))
        if "tool" in event:
            event["tool"]["input"] = deepcopy(state["input"])
        state.pop("executed", None)
        self.result = HookResult(
            event, state, [] if fallback else [deepcopy(self.response)]
        )
        return self.result

    def cancel(self) -> bool:
        cancelled = self.lifecycle.cancel(self.request["id"])
        if self._scope is not None:
            self._scope.cancel()
        return cancelled

    def observe(
        self, subscription: str = "public", *, items: list[Any] | None = None
    ) -> dict[str, Any]:
        return self.lifecycle.observe(self.request, subscription, items=items)


def _matches(selector, event):
    return (
        selector == event
        or selector == "*"
        or (selector.endswith(".*") and event.startswith(selector[:-1]))
    )


def _narrows(value, maximum):
    if isinstance(value, dict):
        return isinstance(maximum, dict) and all(
            key in maximum and _narrows(item, maximum[key])
            for key, item in value.items()
        )
    if isinstance(value, list):
        return isinstance(maximum, list) and all(item in maximum for item in value)
    if isinstance(value, bool):
        return isinstance(maximum, bool) and (not value or maximum)
    if isinstance(value, (int, float)) and not isinstance(maximum, bool):
        return isinstance(maximum, (int, float)) and value <= maximum
    return value == maximum


_project = project_content


class Hooks(BoundaryMixin):
    def __init__(
        self,
        config: dict[str, Any],
        *,
        source: str,
        capabilities: dict[str, Any] | None = None,
        manifest: dict[str, Any] | None = None,
        transport: Any = None,
        resolve_credential: Any = None,
    ) -> None:
        self.validator = Validator()
        self._lineage = TaskLineage(self.validator)
        self.validator.validate("registration", config)
        if (
            not isinstance(source, str)
            or not source
            or not FormatChecker().conforms(source, "uri")
        ):
            raise ProtocolError("source must be an absolute URI")
        if manifest is not None:
            if capabilities is not None:
                raise ProtocolError("Supply manifest or capabilities, not both")
            self.validator.validate(
                "capabilities-response",
                {
                    "jsonrpc": "2.0",
                    "id": "configured-manifest",
                    "result": {
                        "protocolVersion": config["protocolVersion"],
                        "manifest": manifest,
                    },
                },
            )
            capabilities = {}
            for entry in manifest["events"]:
                name = entry["event"]
                if name in capabilities:
                    raise ProtocolError("Duplicate manifest event")
                capabilities[name] = {
                    key: deepcopy(value)
                    for key, value in entry.items()
                    if key != "event"
                }
        if not isinstance(capabilities, dict):
            raise ProtocolError("capabilities must map events to explicit modes")
        self.config = deepcopy(config)
        self.source = source
        self.capabilities = deepcopy(capabilities)
        ids = set()
        self._headers: dict[str, dict[str, str]] = {}
        for event, declaration in self.capabilities.items():
            modes = declaration.get("modes") if isinstance(declaration, dict) else None
            if (
                not isinstance(modes, list)
                or not modes
                or any(m not in ("intercept", "observe") for m in modes)
            ):
                raise ProtocolError("Every event requires explicit modes")
            if "intercept" in modes:
                if "capabilities" not in declaration:
                    raise ProtocolError("Interception requires explicit capabilities")
                self.validator.validate("capabilities", declaration["capabilities"])
        self._manifest = (
            deepcopy(manifest) if manifest is not None else self._derive_manifest()
        )
        self.validator.validate(
            "capabilities-response",
            {
                "jsonrpc": "2.0",
                "id": "configured-manifest",
                "result": {
                    "protocolVersion": config["protocolVersion"],
                    "manifest": self._manifest,
                },
            },
        )
        for backend in self.config["hooks"]:
            if backend["id"] in ids:
                raise ProtocolError("Duplicate backend ID")
            ids.add(backend["id"])
            if "authentication" in backend and transport is None:
                import os

                auth = backend["authentication"]
                if auth["type"] != "bearer":
                    raise ProtocolError(
                        "Authentication requires an injected authenticated transport"
                    )
                try:
                    token = (
                        os.environ.get(auth["tokenEnv"])
                        if "tokenEnv" in auth
                        else (
                            resolve_credential(auth["tokenRef"])
                            if resolve_credential is not None
                            else None
                        )
                    )
                except Exception:
                    raise ProtocolError(
                        "Cannot resolve configured credential"
                    ) from None
                if (
                    not isinstance(token, str)
                    or not token
                    or "\r" in token
                    or "\n" in token
                ):
                    raise ProtocolError("Cannot resolve configured credential")
                self._headers[backend["id"]] = {"Authorization": "Bearer " + token}
            for subscription in backend["subscriptions"]:
                for selector in subscription["events"]:
                    matched = [e for e in capabilities if _matches(selector, e)]
                    if not matched or any(
                        subscription["mode"] not in capabilities[e]["modes"]
                        for e in matched
                    ):
                        raise ProtocolError("Unsupported event or delivery mode")
        self._injected = transport
        self._transports = {}
        self._owned = []
        self._ready_lock = anyio.Lock()
        self._closed = False
        self._observations: list[dict[str, Any]] = []
        self._observation_diagnostics: deque[dict[str, Any]] = deque(maxlen=256)

    @property
    def manifest(self) -> dict[str, Any]:
        """Return a detached snapshot of the configured static host manifest."""
        return deepcopy(self._manifest)

    def _derive_manifest(self) -> dict[str, Any]:
        # The schema catalogue bounds coverage; omitted declarations never grant modes.
        schema = self.validator.validators["capabilities-response.schema.json"].schema
        shape = schema["allOf"][1]["properties"]["result"]["properties"]["manifest"]
        names = shape["properties"]["events"]["items"]["properties"]["event"]["enum"]
        result = {
            "events": [
                {
                    "event": name,
                    **(
                        deepcopy(grant)
                        if "intercept" in grant["modes"]
                        else {"modes": deepcopy(grant["modes"])}
                    ),
                }
                for name, grant in self.capabilities.items()
            ],
            "gaps": [
                {"path": "events." + name, "reason": "Event not declared by the host"}
                for name in names
                if name not in self.capabilities
            ],
            "transports": [],
            "authentication": [],
            "toolPaths": [],
            "contentCategories": [],
            "limits": {},
            "managedPolicy": {"scopes": [], "disableable": True},
            "correlationIdentityFields": ["event.source", "event.id"],
        }
        # An event grant map provides no evidence for these host-level facilities.
        result["gaps"].extend(
            {
                "path": name,
                "reason": "Not declared by the event capability map; supply a full manifest",
            }
            for name in (
                "transports",
                "authentication",
                "toolPaths",
                "contentCategories",
                "limits",
                "managedPolicy",
            )
        )
        return result

    async def __aenter__(self) -> Hooks:
        await self._ensure_ready()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def _ensure_ready(self):
        async with self._ready_lock:
            if self._closed:
                raise RuntimeError("Hooks is closed")
            if self._transports:
                return
            for backend in self.config["hooks"]:
                if self._injected is not None:
                    transport = (
                        self._injected[backend["id"]]
                        if isinstance(self._injected, dict)
                        else self._injected
                    )
                else:
                    config = backend["transport"]
                    if config["type"] == "stdio":
                        from .transports import StdioTransport

                        transport = StdioTransport(
                            config["command"],
                            config.get("args", []),
                            lifecycle=config["lifecycle"],
                            cwd=config.get("cwd"),
                        )
                    else:
                        from .transports.http import HTTPTransport

                        transport = HTTPTransport(
                            config["url"],
                            headers=self._headers.get(backend["id"]),
                            validator=self.validator,
                        )
                    self._owned.append(transport)
                self._transports[backend["id"]] = transport

    async def wait_observations(self) -> list[dict[str, Any]]:
        """Wait for scheduled deliveries; drain the latest 256 retained errors."""
        observations = list(self._observations)
        for observation in observations:
            await observation["done"].wait()
        diagnostics = deepcopy(list(self._observation_diagnostics))
        self._observation_diagnostics.clear()
        return diagnostics

    async def wait(self) -> list[dict[str, Any]]:
        return await self.wait_observations()

    async def aclose(self) -> None:
        with anyio.CancelScope(shield=True):
            self._closed = True
            for observation in self._observations:
                if observation["scope"] is not None:
                    observation["scope"].cancel()
            await self.wait_observations()
            async with self._ready_lock:
                for transport in self._owned:
                    await transport.aclose()
                self._owned.clear()

    def begin(
        self,
        request: dict[str, Any],
        *,
        transport: Any = None,
        content: ContentContext | None = None,
    ) -> PendingInvocation:
        """Begin a canonical request; use an explicit transport for manual acquisition."""
        if self._closed:
            raise RuntimeError("Hooks is closed")
        if transport is None and not isinstance(self._injected, dict):
            transport = self._injected
        self.validator.validate("intercept-request", request)
        event = request["params"]["event"]
        self._check_occurrence(event, "intercept", request["params"]["capabilities"])
        self._lineage.accept(event)
        return PendingInvocation(request, self.validator, transport, content)

    def _check_occurrence(
        self, event: dict[str, Any], mode: str, caps: dict[str, Any] | None = None
    ) -> None:
        if event["source"] != self.source:
            raise ProtocolError("Occurrence source conflicts with configured source")
        declaration = self.capabilities.get(event["type"])
        if declaration is None or mode not in declaration["modes"]:
            raise ProtocolError("Occurrence event or delivery mode was not advertised")
        if caps is not None and not _narrows(caps, declaration["capabilities"]):
            raise ProtocolError(
                "Occurrence capabilities may only narrow advertised capabilities"
            )

    async def exchange(
        self,
        request: dict[str, Any],
        *,
        transport: Any = None,
        backend_id: str | None = None,
        content: ContentContext | None = None,
    ) -> HookResult | None:
        """Exchange and settle a canonical request through the same lifecycle as dispatch."""
        await self._ensure_ready()
        if transport is None:
            if backend_id is None:
                if len(self._transports) != 1:
                    raise ValueError("backend_id is required with multiple backends")
                backend_id = next(iter(self._transports))
            transport = self._transports[backend_id]
        pending = self.begin(request, transport=transport, content=content)
        await pending.acquire()
        return (
            await pending.accept_content() if content is not None else pending.accept()
        )

    async def notify(
        self,
        notification: dict[str, Any],
        *,
        transport: Any = None,
        backend_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Deliver an exact canonical notification, without any effect authority.

        Unlike dispatch observations, this explicit delivery waits for completion.
        Receiver errors are diagnostics; malformed input/lineage fails before I/O.
        """
        await self._ensure_ready()
        note = deepcopy(notification)
        self.validator.validate("observe-notification", note)
        self._check_occurrence(note["params"]["event"], "observe")
        self._lineage.accept(note["params"]["event"])
        if transport is None:
            if backend_id is None:
                if len(self._transports) != 1:
                    raise ValueError("backend_id is required with multiple backends")
                backend_id = next(iter(self._transports))
            transport = self._transports[backend_id]
        result = HookResult(deepcopy(note["params"]["event"]), {})
        observation = self._schedule_observation(
            transport, note, result, backend_id or "injected"
        )
        try:
            await observation["done"].wait()
        except BaseException:
            observation["cancelled"] = True
            if observation["scope"] is not None:
                observation["scope"].cancel()
            with anyio.CancelScope(shield=True):
                await observation["done"].wait()
            raise
        return deepcopy(observation["diagnostics"])

    async def dispatch(
        self,
        event_name: str,
        input: dict[str, Any],
        *,
        initial_state: dict[str, Any] | None = None,
        capabilities: dict[str, Any] | None = None,
        event_id: str | None = None,
        content: ContentContext | None = None,
    ) -> HookResult:
        await self._ensure_ready()
        if event_name not in self.capabilities:
            raise ProtocolError("Event was not advertised")
        declaration = self.capabilities[event_name]
        caps = deepcopy(declaration.get("capabilities", {"effects": []}))
        if capabilities is not None:
            if not _narrows(capabilities, caps):
                raise ProtocolError(
                    "Occurrence capabilities may only narrow advertised capabilities"
                )
            caps = deepcopy(capabilities)
        event = deepcopy(input)
        if not isinstance(event, dict):
            raise TypeError("Event input must be a canonical event payload object")
        if event_name == "session.start":
            event["manifest"] = deepcopy(self._manifest)
        event.update(
            id=event_id or str(uuid4()),
            source=self.source,
            type=event_name,
            time=datetime.now(timezone.utc).isoformat(),
        )
        state = deepcopy(initial_state or {"permission": "none", "candidate": None})
        request = {
            "jsonrpc": "2.0",
            "id": event["id"],
            "method": "hooks/intercept",
            "params": {
                "protocolVersion": self.config["protocolVersion"],
                "event": event,
                "capabilities": caps,
                "state": state,
            },
        }
        empty = {
            "jsonrpc": "2.0",
            "id": event["id"],
            "result": {
                "protocolVersion": self.config["protocolVersion"],
                "effects": [],
            },
        }
        if "intercept" in declaration["modes"]:
            current = apply_response(
                request, empty, self.validator, include_staged=True
            )
        else:
            self.validator.validate(
                "observe-notification",
                {
                    "jsonrpc": "2.0",
                    "method": "hooks/observe",
                    "params": {
                        "protocolVersion": self.config["protocolVersion"],
                        "event": event,
                    },
                },
            )
            current = {
                "decision": "allow",
                "input": deepcopy(event.get("tool", {}).get("input", {})),
                "messages": [],
            }
        self._lineage.accept(event)
        result = HookResult(deepcopy(event), current)
        observers = []
        halted = state.get("permission") == "deny" or state.get("flow") == "stop"
        for backend in self.config["hooks"]:
            transport = self._transports[backend["id"]]
            for subscription in backend["subscriptions"]:
                if not any(_matches(s, event_name) for s in subscription["events"]):
                    continue
                # Filters are optional optimization hints. The host has not
                # supplied a recognized-kind taxonomy, so never infer one or
                # skip policy hooks for arbitrary future normalized kinds.
                if subscription["mode"] == "observe":
                    observers.append((backend, subscription, transport))
                    continue
                if halted:
                    # Uncalled subscriptions receive a one-way settled view,
                    # never an interception after the chain has stopped.
                    observers.append((backend, subscription, transport))
                    continue
                request["params"]["event"] = _project(
                    result.event,
                    subscription["content"],
                    subscription.get("includeNative", False),
                )
                request["params"]["state"] = deepcopy(state)
                try:
                    with anyio.fail_after(subscription["timeoutMs"] / 1000):
                        accepted = await self.exchange(
                            request, transport=transport, content=content
                        )
                    if accepted is None:
                        raise ProtocolError("Invocation cancelled before acceptance")
                    previous = result.event
                    result.event = merge_effective(
                        previous, request["params"]["event"], accepted.event
                    )
                    accepted.state["event"] = deepcopy(result.event)
                    result.accepted_responses.extend(accepted.accepted_responses)
                    messages = result.state.get("messages", []) + accepted.state.get(
                        "messages", []
                    )
                    result.state = accepted.state
                    result.state["messages"] = messages
                    state = {
                        key: deepcopy(accepted.state[key])
                        for key in ("permission", "candidate")
                    }
                    for key, target in (
                        ("flow", "flow"),
                        ("continuationInstructions", "instructions"),
                        ("injections", "injections"),
                    ):
                        if key in result.state:
                            state[target] = deepcopy(result.state[key])
                    if "continuationRemaining" in result.state:
                        caps["flow"]["remainingContinuations"] = result.state[
                            "continuationRemaining"
                        ]
                    halted = (
                        result.decision == "deny" or result.state.get("flow") == "stop"
                    )
                except Exception as exc:
                    result.diagnostics.append(
                        {
                            "backend": backend["id"],
                            "mode": "intercept",
                            "error": type(exc).__name__,
                        }
                    )
                    if (
                        subscription["failurePolicy"] == "fail-closed"
                        or subscription.get("scope") == "managed"
                        or subscription.get("disableable") is False
                    ):
                        state["permission"] = "deny"
                        result.state["decision"] = "deny"
                        result.state["permission"] = "deny"
                        result.state["executed"] = False
                        result.state.pop("result", None)
                        result.state.pop("authorization", None)
                        halted = True
        for backend, subscription, transport in observers:
            note = {
                "jsonrpc": "2.0",
                "method": "hooks/observe",
                "params": {
                    "protocolVersion": self.config["protocolVersion"],
                    "event": _project(
                        result.event,
                        subscription["content"],
                        subscription.get("includeNative", False),
                    ),
                },
            }
            self._schedule_observation(transport, note, result, backend["id"])
        # The legacy evaluator uses a synthetic execution flag for fixtures;
        # the public harness never executes the host operation.
        result.state.pop("executed", None)
        return result

    def _schedule_observation(
        self, transport: Any, note: dict[str, Any], result: HookResult, backend: str
    ) -> dict[str, Any]:
        observation = {"done": anyio.Event(), "scope": None, "diagnostics": []}
        self._observations.append(observation)
        # Bootstrap a supervisor without borrowing the calling task's cancel
        # stack. All task work, cancellation and joining use AnyIO. This permits
        # contextless auto-readiness and close from another task on both backends.
        import sniffio

        if sniffio.current_async_library() == "trio":
            import trio

            trio.lowlevel.spawn_system_task(
                self._notify, transport, note, result, backend, observation
            )
        else:
            import asyncio

            observation["task"] = asyncio.create_task(
                self._notify(transport, note, result, backend, observation)
            )
        return observation

    async def _notify(
        self,
        transport: Any,
        note: dict[str, Any],
        result: HookResult,
        backend: str,
        observation: dict[str, Any],
    ) -> None:
        try:
            with anyio.CancelScope() as scope:
                observation["scope"] = scope
                if self._closed or observation.get("cancelled", False):
                    return
                try:
                    self.validator.validate("observe-notification", note)
                    await transport.notify(note)
                except Exception as exc:
                    diagnostic = {
                        "backend": backend,
                        "mode": "observe",
                        "error": type(exc).__name__,
                    }
                    result.diagnostics.append(diagnostic)
                    observation["diagnostics"].append(diagnostic)
                    self._observation_diagnostics.append(diagnostic)
        finally:
            self._observations.remove(observation)
            observation["done"].set()
