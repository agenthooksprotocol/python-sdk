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
from .permission import Permission
from .diagnostics import Code
from ._diagnostics import (
    Diagnostic,
    ContentPreparationError,
    ContentPreparationTimeout,
    delivery_diagnostic,
)

from copy import deepcopy
from collections import deque
from contextlib import asynccontextmanager
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4
from weakref import WeakSet

import anyio
from jsonschema import FormatChecker

from .runtime import (
    OperationCancelledError,
    ProtocolError,
    Validator,
    apply_response,
    json_equal,
)
from .lifecycle import Lifecycle
from .lineage import TaskLineage
from ._boundaries import BoundaryMixin
from ._content import ContentContext, ContentSources, merge_effective, project_content
from .attachment import Attachment, AttachmentContents
from ._content import at, put

T = TypeVar("T")


class HooksClosedError(OperationCancelledError):
    """The harness closed before its operation could complete."""

    code = Code.CANCELLED


def _owned_operation(method):
    @wraps(method)
    async def run(self, *args, **kwargs):
        if method.__name__ == "dispatch":
            payload = args[1] if len(args) > 1 else kwargs.get("input")
            if isinstance(payload, dict) and not hasattr(payload, "content_sources"):
                from ._models import _normalize_owned_input
                from ._boundaries import CONTENT_SOURCE_SLOTS

                class HostInput(dict):
                    @property
                    def content_sources(self):
                        return self._content_sources

                    def to_wire(self):
                        return dict(self)

                name = args[0] if args else kwargs["event_name"]
                normalized = HostInput(payload)
                roots = {
                    path[0]: [path[0]]
                    for kind, path in CONTENT_SOURCE_SLOTS.values()
                    if kind == name
                }
                from .lifecycle import content_items
                from ._models import OwnedAttachment

                parts = list(content_items(dict(payload, type=name)))
                fresh = {
                    owner
                    for part in parts
                    if isinstance(part, dict)
                    for child in part.values()
                    for owner in [
                        child.source if isinstance(child, OwnedAttachment) else child
                    ]
                    if isinstance(owner, Attachment)
                    and not owner._claimed
                    and not owner._closed
                }

                try:
                    _normalize_owned_input(normalized, name, roots)
                except BaseException:
                    with anyio.CancelScope(shield=True):
                        for owner in fresh:
                            await owner.aclose()
                    raise
                payload = normalized
                if len(args) > 1:
                    args = (args[0], payload, *args[2:])
                else:
                    kwargs["input"] = payload
            bindings = getattr(payload, "content_sources", None)
            if bindings:
                try:
                    if kwargs.get("sources") is not None:
                        raise TypeError("Use input-bound sources or sources=, not both")
                    kwargs["sources"] = ContentSources(
                        bindings, uploads=kwargs.get("uploads")
                    )
                except BaseException:
                    with anyio.CancelScope(shield=True):
                        for source in set(bindings.values()):
                            if (
                                isinstance(source, Attachment)
                                and not source._claimed
                                and not source._closed
                            ):
                                await source.aclose()
                    raise
        sources = kwargs.get("sources")
        owned = (
            {
                slot: source
                for slot, source in sources.bindings.items()
                if isinstance(source, Attachment)
            }
            if sources is not None
            else {}
        )
        foreign = {
            source for source in owned.values() if source._claimed or source._closed
        }
        if foreign:
            # A rejected mixed submission still transfers its fresh resources.
            # Never close or mutate resources held by an earlier invocation.
            sources = ContentSources(
                {
                    slot: source
                    for slot, source in sources.bindings.items()
                    if source not in foreign
                }
            )
            owned = {
                slot: source for slot, source in owned.items() if source not in foreign
            }
        for source in owned.values():
            source._claimed = True
        published = False
        entered = False
        result = None
        try:
            async with self._operation():
                entered = True
                try:
                    if foreign:
                        raise ProtocolError("Attachment already transferred or closed")
                    if owned:
                        payload = args[1] if len(args) > 1 else kwargs.get("input")
                        wire = deepcopy(
                            payload.to_wire()
                            if hasattr(payload, "to_wire")
                            else payload
                        )
                        for slot in owned:
                            item = at(wire, sources._slots[slot][1])
                            if "body" in item and item["body"] != {
                                "ref": "ahp:owned:pending"
                            }:
                                raise ProtocolError(
                                    "Owned attachments require items without existing body references"
                                )
                            # Pending local identities never enter a wire request or result.
                            item.pop("body", None)
                            item["selection"] = "metadata"
                        if len(args) > 1:
                            args = (args[0], wire, *args[2:])
                        else:
                            kwargs["input"] = wire
                    result = await method(self, *args, **kwargs)
                    if owned:
                        effective = {}
                        for slot, source in sources.bindings.items():
                            if not isinstance(source, Attachment):
                                continue
                            path = sources._slots[slot][1]
                            try:
                                current = at(result.event, path)
                                original = sources._item_metadata[slot]
                            except (KeyError, IndexError, TypeError):
                                continue
                            if current.get("id") == original.get("id") and (
                                "body" not in current
                                or current["body"]["ref"] in sources._references
                            ):
                                effective[slot] = source
                        metadata = {
                            slot: deepcopy(at(result.event, sources._slots[slot][1]))
                            for slot in effective
                        }
                        if any(
                            "body" in item
                            and item["body"]["ref"] not in sources._references
                            for item in metadata.values()
                        ):
                            raise ProtocolError(
                                "Effective content no longer represents the owned attachment"
                            )
                        result.attachments._bindings.update(effective)
                        result.attachments._metadata.update(metadata)
                        sources.bindings = {
                            slot: source
                            for slot, source in sources.bindings.items()
                            if slot not in effective
                        }
                    if sources is not None:
                        with anyio.CancelScope(shield=True):
                            await sources.aclose()
                    await anyio.lowlevel.checkpoint()
                    published = True
                    return result
                finally:
                    # Join cleanup before the operation signals completion to close().
                    with anyio.CancelScope(shield=True):
                        if sources is not None:
                            await sources.aclose()
                        if not published and owned:
                            await AttachmentContents(owned).aclose()
                        if not published and isinstance(result, HookResult):
                            await result.aclose()
        finally:
            if not entered and sources is not None:
                with anyio.CancelScope(shield=True):
                    await sources.aclose()

    return run


@dataclass
class HookResult:
    """Raw committed wire state. Decoding never rolls back accepted effects."""

    event: dict[str, Any]
    state: dict[str, Any]
    accepted_responses: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    attachments: AttachmentContents = field(
        default_factory=lambda: AttachmentContents({})
    )

    async def aclose(self) -> None:
        await self.attachments.aclose()

    async def __aenter__(self) -> HookResult:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

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
    def permission(self) -> Permission:
        return Permission(self.state.get("permission", "none"))

    @property
    def interrupted(self) -> bool:
        return bool(self.state.get("interrupted", False))

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
        owner: Hooks | None = None,
    ) -> None:
        self._owner = owner
        self.request = deepcopy(request)
        self.transport = transport
        self.lifecycle = Lifecycle(validator, include_staged=True)
        self.lifecycle.send(self.request)
        self.content = content
        self._content_bound = content is not None
        self.prepared_content = None
        self.response = None
        self.result = None
        self._scope = None

    @asynccontextmanager
    async def _operation(self):
        if self._owner is None:
            yield
        else:
            async with self._owner._operation():
                yield

    def _retire_content(self):
        if self.prepared_content is not None:
            self.prepared_content.retire()
            self.prepared_content = None
        if self.request["id"] in self.lifecycle.terminal or (
            self._owner is not None and self._owner._closed
        ):
            # Bound callbacks can retain an entire caller-owned content store.
            # Detach them; never clear or otherwise mutate that shared store.
            self.content = None

    def _check_open(self):
        if self._owner is not None and self._owner._closed:
            raise HooksClosedError("Hooks is closed")

    @_owned_operation
    async def acquire(self) -> dict[str, Any] | None:
        if self.transport is None:
            raise RuntimeError("No transport configured")
        if self._scope is not None:
            raise RuntimeError("Invocation already has an active acquisition")
        with anyio.CancelScope() as scope:
            self._scope = scope
            try:
                if self.content is not None:
                    self.prepared_content = await self._prepare_content()
                response = await self.transport.request(deepcopy(self.request))
                if not self.receive(response):
                    if self.lifecycle.terminal.get(self.request["id"]) == "cancelled":
                        raise OperationCancelledError(
                            "Invocation cancelled before acceptance"
                        )
                    raise ProtocolError("Response was not admitted for this invocation")
                return response
            except BaseException as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    self.lifecycle.cancel(self.request["id"])
                self._retire_content()
                raise
            finally:
                self._scope = None
        return None

    def receive(self, response: dict[str, Any]) -> bool:
        self._check_open()
        accepted = self.lifecycle.receive(self.request, response)
        if accepted:
            self.response = deepcopy(response)
        return accepted

    def accept(self, *, fallback: bool = False) -> HookResult | None:
        self._check_open()
        if self._content_bound:
            raise RuntimeError(
                "Content-bound invocations require await accept_content()"
            )
        state = self.lifecycle.accept(self.request["id"], fallback=fallback)
        return self._publish(state, fallback)

    @_owned_operation
    async def accept_content(self, *, fallback: bool = False) -> HookResult | None:
        if not self._content_bound:
            return self.accept(fallback=fallback)
        if self._scope is not None:
            raise RuntimeError("Invocation already has an active operation")
        if self.request["id"] in self.lifecycle.terminal:
            self._retire_content()
            return None
        if fallback:
            try:
                return self._publish(
                    self.lifecycle.accept(self.request["id"], fallback=True), True
                )
            finally:
                self._retire_content()
        token = None
        with anyio.CancelScope() as scope:
            self._scope = scope
            try:
                if self.prepared_content is None:
                    self.prepared_content = await self._prepare_content()
                prepared = self.lifecycle.prepare_accept(
                    self.request["id"], fallback=fallback, content=self.prepared_content
                )
                if prepared is None:
                    return None
                token, state = prepared
                try:
                    state = await self.prepared_content.finalize(state)
                except OperationCancelledError:
                    raise
                except TimeoutError:
                    raise ContentPreparationTimeout(
                        "Selected content timed out"
                    ) from None
                except Exception as exc:
                    raise ContentPreparationError(
                        "Content finalization failed", cause=exc
                    ) from None
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
                self._retire_content()
        return None

    async def _prepare_content(self):
        try:
            return await self.content.prepare(self.request, self.lifecycle.validator)
        except OperationCancelledError:
            raise
        except TimeoutError:
            raise ContentPreparationTimeout("Selected content timed out") from None
        except Exception as exc:
            raise ContentPreparationError(
                "Content preparation failed", cause=exc
            ) from None

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
        if self.prepared_content is not None and not fallback:
            self.result.attachments = self.prepared_content.contents(event)
        return self.result

    def cancel(self) -> bool:
        cancelled = self.lifecycle.cancel(self.request["id"])
        if self._scope is not None:
            self._scope.cancel()
        else:
            self._retire_content()
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
        auth_provider: Any = None,
        max_concurrent_uploads: int = 8,
    ) -> None:
        if (
            isinstance(max_concurrent_uploads, bool)
            or not isinstance(max_concurrent_uploads, int)
            or max_concurrent_uploads <= 0
        ):
            raise ValueError("max_concurrent_uploads must be a positive integer")
        self.max_concurrent_uploads = max_concurrent_uploads
        self._upload_limiter = anyio.Semaphore(max_concurrent_uploads)
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
        self._pending: WeakSet[PendingInvocation] = WeakSet()
        self.config = deepcopy(config)
        self.source = source
        self.capabilities = {
            key: deepcopy(value.to_wire() if hasattr(value, "to_wire") else value)
            for key, value in capabilities.items()
        }
        from .auth import EnvironmentAuthProvider

        self._auth_provider = (
            auth_provider
            if auth_provider is not None
            else EnvironmentAuthProvider(resolve_credential=resolve_credential)
        )
        ids = set()
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
            for subscription in backend["subscriptions"]:
                for selector in subscription["events"]:
                    matched = [e for e in self.capabilities if _matches(selector, e)]
                    if not matched or any(
                        subscription["mode"] not in self.capabilities[e]["modes"]
                        for e in matched
                    ):
                        raise ProtocolError("Unsupported event or delivery mode")
        self._injected = transport
        self._transports = {}
        self._owned = []
        self._ready_lock = anyio.Lock()
        self._closed = False
        self._close_lock = anyio.Lock()
        self._operations: list[dict[str, Any]] = []
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
                        from .auth import AuthenticatedHTTPTransport

                        transport = AuthenticatedHTTPTransport(
                            config["url"],
                            backend=backend,
                            auth_provider=self._auth_provider,
                            validator=self.validator,
                        )
                    self._owned.append(transport)
                self._transports[backend["id"]] = transport

    async def wait_observations(self) -> list[dict[str, Any]]:
        """Drain retained observation errors; calls already own their deliveries."""
        observations = list(self._observations)
        for observation in observations:
            await observation["done"].wait()
        diagnostics = deepcopy(list(self._observation_diagnostics))
        self._observation_diagnostics.clear()
        return diagnostics

    async def wait(self) -> list[dict[str, Any]]:
        return await self.wait_observations()

    @asynccontextmanager
    async def _operation(self):
        if self._closed:
            raise HooksClosedError("Hooks is closed")
        operation = {"scope": anyio.CancelScope(), "done": anyio.Event()}
        self._operations.append(operation)
        try:
            with operation["scope"]:
                yield
            if operation["scope"].cancel_called:
                raise HooksClosedError("Hooks closed during operation")
        finally:
            self._operations.remove(operation)
            operation["done"].set()

    async def aclose(self) -> None:
        """Cancel and join owned calls; borrowed transports/providers stay open."""
        with anyio.CancelScope(shield=True):
            self._closed = True
            async with self._close_lock:
                operations = list(self._operations)
                for operation in operations:
                    operation["scope"].cancel()
                for operation in operations:
                    await operation["done"].wait()
                for pending in self._pending:
                    pending._retire_content()
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
        pending = PendingInvocation(
            request, self.validator, transport, content, owner=self
        )
        self._pending.add(pending)
        return pending

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

    @_owned_operation
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

    @_owned_operation
    async def notify(
        self,
        notification: dict[str, Any],
        *,
        transport: Any = None,
        backend_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Deliver an exact canonical notification, without any effect authority.

        Like dispatch observations, delivery is owned by this call.
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
        await self._notify(transport, note, result, backend_id or "injected")
        return deepcopy(result.diagnostics)

    @_owned_operation
    async def dispatch(
        self,
        event_name: str,
        input: dict[str, Any],
        *,
        initial_state: dict[str, Any] | None = None,
        capabilities: dict[str, Any] | None = None,
        event_id: str | None = None,
        content: ContentContext | None = None,
        sources: ContentSources | None = None,
        original_request: dict[str, Any] | None = None,
        uploads: dict[str, Any] | None = None,
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
        event = deepcopy(input.to_wire() if hasattr(input, "to_wire") else input)
        if not isinstance(event, dict):
            raise TypeError("Event input must be a canonical event payload object")
        from ._content import normalized_content_slots, normalized_values

        paths, _ = normalized_content_slots().get(event_name, ((), ()))
        for part in normalized_values(event, paths):
            if not isinstance(part, dict) or part.get("kind") != "text":
                continue
            if "id" not in part:
                if part.get("synthesized") is False:
                    raise ProtocolError(
                        "Missing text identity conflicts with synthesized=false"
                    )
                part.update(id=str(uuid4()), synthesized=True)
            part.setdefault("mediaType", "text/plain")
            part.setdefault("selection", "body")
        if event_name == "session.start":
            event["manifest"] = deepcopy(self._manifest)
        event.update(
            id=event_id if event_id is not None else event.get("id", str(uuid4())),
            source=self.source,
            type=event_name,
            time=event.get("time", datetime.now(timezone.utc).isoformat()),
        )
        if sources is not None:
            sources._remember(event)
        state = deepcopy(
            initial_state
            if initial_state is not None
            else {"permission": "none", "candidate": None}
        )
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
        preupload_failures = {}
        preupload_spent = {}

        async def preupload(backend, index, subscription):
            context = (backend["id"], index)
            started = anyio.current_time()
            try:
                with anyio.fail_after(
                    None
                    if subscription.get("timeoutMs") is None
                    else subscription["timeoutMs"] / 1000
                ):
                    await self._project_delivery(
                        event,
                        subscription,
                        backend["id"],
                        sources,
                        uploads,
                        delivery_context=context,
                    )
            except Exception as exc:
                # Failure is settled only when this subscription is delivered.
                preupload_failures[context] = exc
            finally:
                preupload_spent[context] = anyio.current_time() - started

        if sources is not None:
            async with anyio.create_task_group() as group:
                for backend in self.config["hooks"]:
                    for index, subscription in enumerate(backend["subscriptions"]):
                        if any(
                            _matches(pattern, event_name)
                            for pattern in subscription["events"]
                        ):
                            group.start_soon(preupload, backend, index, subscription)
        for backend in self.config["hooks"]:
            transport = self._transports[backend["id"]]
            for subscription_index, subscription in enumerate(backend["subscriptions"]):
                if not any(_matches(s, event_name) for s in subscription["events"]):
                    continue
                # Filters are optional optimization hints. The host has not
                # supplied a recognized-kind taxonomy, so never infer one or
                # skip policy hooks for arbitrary future normalized kinds.
                if subscription["mode"] == "observe":
                    observers.append(
                        (backend, subscription_index, subscription, transport)
                    )
                    continue
                if halted:
                    # Uncalled subscriptions receive a one-way settled view,
                    # never an interception after the chain has stopped.
                    observers.append(
                        (backend, subscription_index, subscription, transport)
                    )
                    continue
                request["params"]["state"] = deepcopy(state)
                stage = "content"
                try:
                    delivery_context = (backend["id"], subscription_index)
                    remaining = max(
                        0,
                        subscription["timeoutMs"] / 1000
                        - preupload_spent.get(delivery_context, 0),
                    )
                    with anyio.fail_after(remaining):
                        if delivery_context in preupload_failures:
                            raise preupload_failures[delivery_context]
                        request["params"]["event"] = await self._project_delivery(
                            result.event,
                            subscription,
                            backend["id"],
                            sources,
                            uploads,
                            delivery_context=delivery_context,
                        )
                        stage = "delivery"
                        delivery_content = (
                            sources.edit_context(
                                request["params"]["event"],
                                backend["id"],
                                uploads.get(backend["id"])
                                if uploads is not None
                                else None,
                                content,
                            )
                            if sources is not None
                            else content
                        )
                        if (
                            delivery_content is None
                            and event_name == "user.elicitation.request"
                        ):
                            delivery_content = ContentContext(
                                bindings={"request": ("elicitation", "request")},
                                principal=backend["id"],
                            )
                        if (
                            delivery_content is None
                            and event_name == "user.elicitation.result"
                            and original_request is not None
                        ):
                            delivery_content = ContentContext(
                                bindings={"content": ("elicitation", "result")},
                                principal=backend["id"],
                                original_request=original_request,
                            )
                        accepted = await self.exchange(
                            request, transport=transport, content=delivery_content
                        )
                    if accepted is None:
                        raise OperationCancelledError(
                            "Invocation cancelled before acceptance"
                        )
                    # Transfer effective owners, not references to a byte store.
                    retired = set()
                    replaced_paths = []
                    for slot, owner in accepted.attachments._bindings.items():
                        if sources is not None and slot in sources.bindings:
                            previous_owner = sources.bindings[slot]
                            sources.bindings[slot] = owner
                            if previous_owner is not owner:
                                retired.add(previous_owner)
                                replaced_paths.append(sources._slots[slot][1])
                            kind, path = sources._slots[slot]
                            item = at(accepted.event, path)
                            if "body" in item:
                                import hashlib

                                data = owner._snapshot
                                sources._references[item["body"]["ref"]] = (
                                    len(data),
                                    hashlib.sha256(data).hexdigest(),
                                )
                        previous_result_owner = result.attachments._bindings.get(slot)
                        if (
                            previous_result_owner is not None
                            and previous_result_owner is not owner
                        ):
                            retired.add(previous_result_owner)
                        result.attachments._bindings[slot] = owner
                    accepted.attachments._bindings.clear()
                    retired.difference_update(result.attachments._bindings.values())
                    if sources is not None:
                        retired.difference_update(sources.bindings.values())
                    with anyio.CancelScope(shield=True):
                        for owner in retired:
                            await owner.aclose()
                    previous = result.event
                    result.event = merge_effective(
                        previous, request["params"]["event"], accepted.event
                    )
                    # Projection is not an edit. Apply explicit target writes to
                    # the host value so replace also substitutes an identical
                    # metadata view, while merge preserves hidden existing parts.
                    from .runtime import _modification_paths

                    paths = _modification_paths(previous)
                    effects = (
                        (accepted.accepted_response or {})
                        .get("result", {})
                        .get("effects", [])
                    )
                    written_paths = set()
                    for effect in effects:
                        if effect["type"] != "modify":
                            continue
                        path = paths.get(effect["target"])
                        if path is None:
                            continue
                        value = deepcopy(effect["value"])
                        if effect["operation"] == "merge":
                            before = at(result.event, path)
                            # merge_effective already includes admitted additions;
                            # replay against the original host target exactly once.
                            if path not in written_paths:
                                before = at(previous, path)
                            value = (
                                before + value
                                if isinstance(before, list)
                                else {**before, **value}
                            )
                        put(result.event, path, value)
                        written_paths.add(path)
                    for path in replaced_paths:
                        put(result.event, path, deepcopy(at(accepted.event, path)))
                    if sources is not None:
                        retired_sources = sources._reconcile(result.event)
                        retired_sources.difference_update(
                            result.attachments._bindings.values()
                        )
                        with anyio.CancelScope(shield=True):
                            for source in retired_sources:
                                await source.aclose()
                    if not json_equal(previous, result.event) and not any(
                        effect["type"] == "return" for effect in effects
                    ):
                        accepted.state["candidate"] = None
                        if accepted.state["permission"] == "allow":
                            accepted.state["permission"] = "none"
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
                except OperationCancelledError:
                    raise
                except Exception as exc:
                    closed = (
                        subscription["failurePolicy"] == "fail-closed"
                        or subscription.get("scope") == "managed"
                        or subscription.get("disableable") is False
                    )
                    result.diagnostics.append(
                        delivery_diagnostic(
                            exc,
                            backend=backend["id"],
                            subscription=subscription_index,
                            mode="intercept",
                            stage=stage,
                            failure_policy=subscription["failurePolicy"],
                            synthetic_denial=closed,
                        )
                    )
                    if closed:
                        state["permission"] = "deny"
                        result.state["decision"] = "deny"
                        result.state["permission"] = "deny"
                        result.state["executed"] = False
                        result.state.pop("result", None)
                        result.state.pop("authorization", None)
                        halted = True
        for backend, subscription_index, subscription, transport in observers:
            await self._notify(
                transport,
                {
                    "jsonrpc": "2.0",
                    "method": "hooks/observe",
                    "params": {
                        "protocolVersion": self.config["protocolVersion"],
                        "event": result.event,
                    },
                },
                result,
                backend["id"],
                timeout_ms=subscription.get("timeoutMs"),
                subscription=subscription_index,
                selection=subscription,
                sources=sources,
                uploads=uploads,
                preparation_error=preupload_failures.get(
                    (backend["id"], subscription_index)
                ),
                preparation_spent=preupload_spent.get(
                    (backend["id"], subscription_index), 0
                ),
            )
        # The legacy evaluator uses a synthetic execution flag for fixtures;
        # the public harness never executes the host operation.
        result.state.pop("executed", None)
        return result

    async def _notify(
        self,
        transport: Any,
        note: dict[str, Any],
        result: HookResult,
        backend: str,
        *,
        timeout_ms: int | None = None,
        subscription: int | None = None,
        selection: dict[str, Any] | None = None,
        sources: ContentSources | None = None,
        uploads: dict[str, Any] | None = None,
        preparation_error: Exception | None = None,
        preparation_spent: float = 0,
    ) -> None:
        # No private task/runtime: host task groups own concurrency and budgets.
        await anyio.lowlevel.checkpoint()
        stage = "content" if selection is not None else "delivery"
        try:
            with anyio.fail_after(
                None
                if timeout_ms is None
                else max(0, timeout_ms / 1000 - preparation_spent)
            ):
                if preparation_error is not None:
                    raise preparation_error
                note = deepcopy(note)
                if selection is not None:
                    note["params"]["event"] = await self._project_delivery(
                        note["params"]["event"],
                        selection,
                        backend,
                        sources,
                        uploads,
                        delivery_context=(backend, subscription),
                    )
                stage = "delivery"
                self.validator.validate("observe-notification", note)
                await transport.notify(note)
        except OperationCancelledError:
            raise
        except Exception as exc:
            diagnostic = delivery_diagnostic(
                exc,
                backend=backend,
                subscription=subscription,
                mode="observe",
                stage=stage,
            )
            result.diagnostics.append(diagnostic)
            self._observation_diagnostics.append(diagnostic)

    async def _project_delivery(
        self, event, subscription, backend, sources, uploads, *, delivery_context=None
    ):
        if sources is None:
            return _project(
                event, subscription["content"], subscription.get("includeNative", False)
            )

        try:
            return await sources.project(
                event,
                subscription["content"],
                backend=backend,
                upload=uploads.get(backend) if uploads is not None else None,
                validator=self.validator,
                include_native=subscription.get("includeNative", False),
                delivery_context=delivery_context,
                upload_limiter=self._upload_limiter,
            )
        except OperationCancelledError:
            raise
        except TimeoutError:
            raise
        except Exception as exc:
            raise ContentPreparationError(
                "Selected content preparation failed", cause=exc
            ) from None
