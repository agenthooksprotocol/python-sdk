"""Schema-owned inline projection and invocation-owned binary attachments."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from urllib.parse import urljoin
import hashlib
import json
import math
import re
import sys

import anyio
from typing import Any, TYPE_CHECKING

from .runtime import OperationCancelledError, ProtocolError, _json_equal

if TYPE_CHECKING:
    from .attachment import Attachment
    from .generated import ContentUploadReceipt

Reference = dict[str, Any]
Resolver = Callable[[Reference], Awaitable[bytes]]
Uploader = Callable[[bytes], Awaitable["ContentUploadReceipt"]]


def at(value: Any, path: tuple[str | int, ...]) -> Any:
    for component in path:
        value = value[component]
    return value


def put(value: Any, path: tuple[str | int, ...], replacement: Any) -> None:
    if not path:
        raise ProtocolError("Content binding requires an explicit nonempty path")
    at(value, path[:-1])[path[-1]] = replacement


@lru_cache(maxsize=1)
def normalized_content_slots():
    """Derive immutable part/message paths from bundled canonical schema refs.

    Source slots exclude inline-only text fields. Projection and lineage must
    include those fields, without examining opaque native or application JSON.
    """
    schemas = {
        schema["$id"]: schema
        for schema in json.loads(Path(__file__).with_name("schemas.json").read_text())
    }
    root = next(
        schema for uri, schema in schemas.items() if uri.endswith("/event.schema.json")
    )

    def resolve(reference, base):
        uri = urljoin(base, reference)
        document, _, fragment = uri.partition("#")
        schema = schemas[document]
        for component in fragment.split("/")[1:]:
            key = component.replace("~1", "/").replace("~0", "~")
            schema = schema[int(key)] if isinstance(schema, list) else schema[key]
        return schema, document, fragment

    def event_name(schema, base, seen=frozenset()):
        if not isinstance(schema, dict):
            return None
        name = schema.get("properties", {}).get("type", {}).get("const")
        if isinstance(name, str):
            return name
        reference = schema.get("$ref")
        if reference is not None and urljoin(base, reference) not in seen:
            child, document, _ = resolve(reference, base)
            name = event_name(child, document, seen | {urljoin(base, reference)})
            if name is not None:
                return name
        for composition in ("allOf", "oneOf", "anyOf"):
            for child in schema.get(composition, []):
                name = event_name(child, base, seen)
                if name is not None:
                    return name
        return None

    slots = {}
    for event_schema in root["oneOf"]:
        parts, messages = set(), set()

        def collect(schema, base, path=(), seen=frozenset()):
            if not isinstance(schema, dict):
                return
            reference = schema.get("$ref")
            if reference is not None:
                uri = urljoin(base, reference)
                if uri in seen:
                    return
                child, document, fragment = resolve(reference, base)
                if document.endswith("/content-item.schema.json"):
                    if fragment in ("", "/$defs/textPart"):
                        parts.add(path)
                        return
                    if fragment == "/$defs/textParts":
                        parts.add(path + ("*",))
                        return
                    if fragment in ("/$defs/message", "/$defs/modelVisibleItem"):
                        messages.add(path)
                        parts.add(path + ("parts", "*"))
                        return
                    if fragment == "/$defs/messages":
                        messages.add(path + ("*",))
                        parts.add(path + ("*", "parts", "*"))
                        return
                collect(child, document, path, seen | {uri})
            for composition in ("allOf", "oneOf", "anyOf"):
                for child in schema.get(composition, []):
                    collect(child, base, path, seen)
            for key, child in schema.get("properties", {}).items():
                collect(child, base, path + (key,), seen)
            if isinstance(schema.get("items"), dict):
                collect(schema["items"], base, path + ("*",), seen)

        collect(event_schema, root["$id"])
        slots[event_name(event_schema, root["$id"])] = (
            tuple(sorted(parts)),
            tuple(sorted(messages)),
        )
    return slots


def normalized_values(value, paths):
    """Yield schema-owned values without searching native/application objects."""

    def visit(node, path):
        if not path:
            yield node
        elif path[0] == "*" and isinstance(node, list):
            for child in node:
                yield from visit(child, path[1:])
        elif isinstance(node, dict) and path[0] in node:
            yield from visit(node[path[0]], path[1:])

    for path in paths:
        yield from visit(value, path)


def project_content(
    event: dict[str, Any], selection: dict[str, str], include_native: bool = False
) -> dict[str, Any]:
    """Project descriptors at every normalized depth, never arbitrary host JSON."""

    def descriptor(value: dict[str, Any]) -> dict[str, Any]:
        item = deepcopy(value)
        media = item["mediaType"]
        category = item.get("category") or (
            "text"
            if item["kind"] == "text"
            else "images"
            if media.startswith("image/")
            else "audio"
            if media.startswith("audio/")
            else "video"
            if media.startswith("video/")
            else "files"
        )
        rank = {"omit": 0, "metadata": 1, "body": 2}
        mode = min(
            (selection.get(category, selection["default"]), item["selection"]),
            key=rank.__getitem__,
        )
        if mode != "body":
            for key in ("text", "body", "gap"):
                item.pop(key, None)
            item["selection"] = mode
        return item

    def visit(value: Any, path: tuple[str | int, ...]) -> None:
        if not path:
            return
        head, *tail = path
        if head == "*":
            if isinstance(value, list):
                for index, child in enumerate(value):
                    if tail:
                        visit(child, tuple(tail))
                    else:
                        value[index] = descriptor(child)
        elif isinstance(value, dict) and head in value:
            if tail:
                visit(value[head], tuple(tail))
            else:
                value[head] = descriptor(value[head])

    # Only generated schema-owned slots are traversed. Opaque native/application
    # dictionaries can resemble parts without becoming projection targets.
    if all(key in event for key in ("id", "kind", "mediaType", "selection")):
        return descriptor(event)
    projected = deepcopy(event)
    paths, _ = normalized_content_slots().get(event.get("type"), ((), ()))
    for path in paths:
        visit(projected, path)
    if not include_native:
        projected.pop("native", None)
    return projected


def merge_effective(original: Any, view: Any, effective: Any) -> Any:
    """Restore projection-only differences in schema-owned content slots.

    Application values and opaque extra bags are whole values: never infer
    message/part identity from an arbitrary list containing an id field.
    """
    parts, messages = normalized_content_slots().get(effective["type"], ((), ()))
    owned_paths = parts + messages

    def merge(before, projected, admitted, path=()):
        if _json_equal(projected, admitted):
            return deepcopy(before)
        owned = any(
            len(path) <= len(slot)
            and all(
                expected == "*" or actual == expected
                for actual, expected in zip(path, slot)
            )
            for slot in owned_paths
        )
        if not owned:
            return deepcopy(admitted)
        if (
            isinstance(before, dict)
            and isinstance(projected, dict)
            and isinstance(admitted, dict)
        ):
            merged = deepcopy(before)
            for key in projected.keys() - admitted.keys():
                merged.pop(key, None)
            for key, value in admitted.items():
                merged[key] = (
                    merge(before[key], projected[key], value, path + (key,))
                    if key in before and key in projected
                    else deepcopy(value)
                )
            return merged
        if (
            isinstance(before, list)
            and isinstance(projected, list)
            and isinstance(admitted, list)
        ):
            identities = {
                item["id"]: (before[index], item)
                for index, item in enumerate(projected)
                if index < len(before)
            }
            return [
                merge(*identities[item["id"]], item, path + (index,))
                if item["id"] in identities
                else deepcopy(item)
                for index, item in enumerate(admitted)
            ]
        return deepcopy(admitted)

    return merge(original, view, effective)


class ContentContext:
    """Trusted inline elicitation correlation for one or more calls.

    Result contexts supply the original canonical request and authenticated
    principal. Text is parsed directly; preparation never reads or uploads bytes.
    """

    def __init__(
        self,
        *,
        resolve: Resolver | None = None,
        upload: Uploader | None = None,
        bindings: Mapping[str, tuple[str | int, ...]],
        principal: str,
        original_request: dict[str, Any] | None = None,
        attachments: Mapping[str, Attachment] | None = None,
    ) -> None:
        if not principal or not isinstance(principal, str):
            raise ProtocolError("Authenticated content principal is required")
        if any(
            not path
            or not all(
                isinstance(k, (str, int)) and not isinstance(k, bool) for k in path
            )
            for path in bindings.values()
        ):
            raise ProtocolError("Explicit nonempty content paths are required")
        self.resolve = resolve
        self.upload = upload
        self.bindings = {key: tuple(path) for key, path in bindings.items()}
        self.principal = principal
        self.original_request = deepcopy(original_request)
        self.attachments = dict(attachments or {})
        self._identities: dict[str, tuple[int, str]] = {}

    async def prepare(self, request: dict[str, Any], validator: Any) -> PreparedContent:
        prepared = PreparedContent(self, request, validator)
        try:
            await prepared.load()
        except BaseException:
            prepared.retire()
            raise
        return prepared


class PreparedContent:
    """Selected inline MCP text; no byte snapshots, reads, or uploads."""

    def __init__(
        self, context: ContentContext, request: dict[str, Any], validator: Any
    ) -> None:
        self.context = context
        self.request = deepcopy(request)
        self.validator = validator
        self.targets = (
            {"content"}
            if request["params"]["event"]["type"] == "user.elicitation.result"
            else set()
        )

    async def load(self) -> None:
        from ._elicitation import read_selected, validate_correlation

        event = self.request["params"]["event"]
        if not event["type"].startswith("user.elicitation."):
            raise ProtocolError("Inline context requires an elicitation boundary")
        expected = (
            {"request": ("elicitation", "request")}
            if event["type"].endswith(".request")
            else {"content": ("elicitation", "result")}
        )
        if self.context.bindings != expected:
            raise ProtocolError("Content targets must explicitly match this boundary")
        if event["type"].endswith(".result"):
            if self.context.original_request is None:
                raise ProtocolError(
                    "Elicitation result requires its original request snapshot"
                )
            validate_correlation(self.context.original_request, self.request)
        stage = "request" if event["type"].endswith(".request") else "result"
        read_selected(event["elicitation"], stage, None, self.validator.validate)

    def retire(self) -> None:
        pass

    def contents(self, event: dict[str, Any]):
        from .attachment import AttachmentContents

        return AttachmentContents({})

    def stage(
        self,
        request: dict[str, Any],
        effects: list[dict[str, Any]],
        validate_result=None,
    ) -> dict[str, Any]:
        from ._elicitation import apply_effects

        event = request["params"]["event"]
        body_effects = [
            effect
            for effect in effects
            if effect["type"] in ("return", "deny", "modify")
        ]
        if not body_effects:
            return {"changed": False, "updates": [], "values": {}}
        original = (
            request
            if event["type"].endswith(".request")
            else self.context.original_request
        )
        result = None if event["type"].endswith(".request") else request
        binding = apply_effects(
            original,
            result,
            None,
            self.validator.validate,
            self.context.principal,
            body_effects,
            validate_result=validate_result,
        )
        updates = (
            [{"target": "content", "value": binding["result"]}]
            if result is not None
            else []
        )
        values = {
            **binding,
            "content" if result is not None else "candidate": binding["result"],
        }
        return {"changed": bool(updates), "updates": updates, "values": values}

    async def finalize(self, state: dict[str, Any]) -> dict[str, Any]:
        state = deepcopy(state)
        for update in state.pop("_content_updates", []):
            from . import _models, generated

            item = state["event"].elicitation.result
            if not isinstance(item, _models.TextBodyPart):
                raise ProtocolError("MCP result requires selected inline text")
            item["text"] = generated._encode_json(update["value"])
            state["event"].elicitation["action"] = update["value"].action
        check = deepcopy(self.request)
        check["params"]["event"] = state["event"]
        self.validator.validate("intercept-request", check)
        return state


class OwnedContentSource:
    """Owned async read(size)/receive(max_bytes) stream with bounded snapshots.

    Construction transfers ownership but performs no I/O. Close even unused
    sources. Async aclose is required. Native deadline/cancellation scopes cover
    processing; safety cleanup is shielded and bounded to one second.
    """

    def __init__(
        self,
        stream: Any,
        *,
        max_bytes: int = 4 * 1024 * 1024,
        timeout: float = 30.0,
        expected_size: int | None = None,
        expected_sha256: str | None = None,
    ) -> None:
        if not callable(getattr(stream, "aclose", None)) or not (
            callable(getattr(stream, "read", None))
            or callable(getattr(stream, "receive", None))
        ):
            raise TypeError("source requires async read/receive and aclose")
        self.stream = stream
        self._initialize(max_bytes, timeout, expected_size, expected_sha256)

    def _initialize(self, max_bytes, timeout, expected_size=None, expected_sha256=None):
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 0
        ):
            raise ValueError("max_bytes must be a nonnegative integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (float, int))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be finite and positive")
        if expected_size is not None and (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or expected_size > max_bytes
        ):
            raise ValueError("expected_size must fit max_bytes")
        if expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        ):
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.expected_size = expected_size
        self.expected_sha256 = expected_sha256
        self._snapshot: bytes | None = None
        self._failed = False
        self._closed = False
        self._stream_closed = False
        self._close_done = anyio.Event()
        self._pending = False
        self._cancelled = False
        self._error: BaseException | None = None
        self._waiters = 0
        self._materialized = anyio.Event()
        self._worker: Any = None
        self._scope: Any = None

    async def _close_stream(self) -> None:
        if self._stream_closed:
            with anyio.move_on_after(1, shield=True):
                await self._close_done.wait()
            return
        self._stream_closed = True
        try:
            with anyio.move_on_after(1, shield=True):
                await self._release_source()
        finally:
            # A closed reader can still retain its complete input buffer.
            self.stream = None
            self._close_done.set()

    async def _release_source(self):
        await self.stream.aclose()

    async def _read_source(self):
        chunks = bytearray()
        reader = getattr(self.stream, "read", None) or self.stream.receive
        while True:
            amount = min(65536, self.max_bytes - len(chunks) + 1)
            try:
                part = await reader(amount)
            except anyio.EndOfStream:
                break
            if not isinstance(part, bytes):
                raise ProtocolError("Owned content source must yield bytes")
            if not part:
                break
            if len(part) > amount or len(chunks) + len(part) > self.max_bytes:
                raise ProtocolError("Owned content exceeds configured limit")
            chunks.extend(part)
            await anyio.lowlevel.checkpoint()
        return bytes(chunks)

    async def _materialize(self) -> None:
        # The source owns this single pending worker, independently of readers.
        # Last-waiter cancellation and aclose cancel its scope and join completion.
        try:
            with self._scope:
                with anyio.fail_after(self.timeout):
                    data = await self._read_source()
                    if not isinstance(data, bytes):
                        raise ProtocolError("Owned content source must produce bytes")
                    if len(data) > self.max_bytes:
                        raise ProtocolError("Owned content exceeds max_bytes")
                    if self.expected_size is not None and self.expected_size != len(
                        data
                    ):
                        raise ProtocolError("Owned content size expectation mismatch")
                    if (
                        self.expected_sha256 is not None
                        and self.expected_sha256 != hashlib.sha256(data).hexdigest()
                    ):
                        raise ProtocolError("Owned content digest expectation mismatch")
                    if not self._closed:
                        self._snapshot = data
            if self._snapshot is None:
                self._cancelled = True
                self._error = OperationCancelledError(
                    "Owned content preparation cancelled"
                )
        except BaseException:
            self._failed = True
            self._error = sys.exception()
            self._snapshot = None
        finally:
            try:
                await self._close_stream()
            except BaseException as exc:
                if self._error is None:
                    self._failed = True
                    self._error = exc
                    self._snapshot = None
            finally:
                # Terminal state retains the error, not the worker's read frame
                # or a second reference to rejected bytes.
                data = None
                if self._error is not None:
                    self._error.__traceback__ = None
                self._scope = None
                self._pending = False
                self._worker = None
                self._materialized.set()

    def _start_materialization(self) -> None:
        import sniffio

        # AnyIO task groups are lexically owned by one reader's cancel scope.
        # Use backend scheduling only for this owner-tracked worker; its bounded
        # lifetime is joined by the last departing reader or explicit owner close.
        # Never retain completed tasks or transfer worker ownership to a waiter.
        backend = sniffio.current_async_library()
        self._scope = anyio.CancelScope(shield=True)
        self._pending = True
        try:
            if backend == "asyncio":
                import asyncio

                self._worker = asyncio.create_task(
                    self._materialize(), name="ahp-owned-materialization"
                )
            elif backend == "trio":
                from contextvars import copy_context
                import trio

                self._worker = trio.lowlevel.spawn_system_task(
                    self._materialize,
                    name="ahp-owned-materialization",
                    context=copy_context(),
                )
            else:
                raise ProtocolError("Unsupported owned materialization backend")
        except BaseException:
            self._pending = False
            self._scope = None
            raise

    def _leave_waiter(self) -> bool:
        self._waiters -= 1
        if self._waiters == 0 and self._pending:
            self._scope.cancel()
            return True
        return False

    async def snapshot(self) -> bytes:
        if self._closed:
            raise ProtocolError("Owned content source is closed")
        if not self._pending:
            if self._error is not None:
                raise self._error
            if self._snapshot is not None:
                return self._snapshot

        # Registration and departure are atomic between asynchronous checkpoints.
        self._waiters += 1
        try:
            if not self._pending:
                self._start_materialization()
            await self._materialized.wait()
        finally:
            if self._leave_waiter():
                # Only the last waiter joins safety cleanup; cancelled readers
                # with surviving consumers return promptly and release permits.
                with anyio.CancelScope(shield=True):
                    await self._materialized.wait()
        if self._closed:
            raise OperationCancelledError(
                "Owned content source closed during preparation"
            )
        if self._error is not None:
            raise self._error
        assert self._snapshot is not None
        return self._snapshot

    async def aclose(self) -> None:
        self._closed = True
        self._snapshot = None
        if self._pending:
            self._scope.cancel()
            with anyio.CancelScope(shield=True):
                await self._materialized.wait()
        else:
            await self._close_stream()
        self._error = None

    async def __aenter__(self) -> OwnedContentSource:
        if self._closed:
            raise ProtocolError("Owned content source is closed")
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()


class ContentSources:
    """Single-operation sources bound to named SDK content slots.

    Host events carry metadata-only items. Each project call requires its own
    authorized destination uploader, and allocates references independently.
    Slots are SDK adapters, not generated wire fields. Close in operation finally.
    """

    def __init__(
        self,
        bindings: Mapping[str, OwnedContentSource],
        *,
        uploads: Mapping[str, Uploader] | None = None,
    ) -> None:
        # Generated from shared schema metadata; no private parallel slot list.
        from ._boundaries import CONTENT_SOURCE_SLOTS

        self._slots: dict[str, tuple[str, tuple[str | int, ...]]] = {}
        for binding, source in bindings.items():
            if not isinstance(binding, str) or not isinstance(
                source, OwnedContentSource
            ):
                raise ValueError(
                    "Content bindings require generated slot names and owned sources"
                )
            match = re.fullmatch(r"([^\[\]]+)((?:\[(?:0|[1-9][0-9]*)\])*)", binding)
            if match is None or match[1] not in CONTENT_SOURCE_SLOTS:
                raise ValueError("Unknown generated content source slot")
            kind, template = CONTENT_SOURCE_SLOTS[match[1]]
            indices = [int(value) for value in re.findall(r"\[([0-9]+)\]", match[2])]
            if len(indices) != template.count("*"):
                raise ValueError(
                    "Content source slot requires one index per array component"
                )
            values = iter(indices)
            path = tuple(
                next(values) if component == "*" else component
                for component in template
            )
            self._slots[binding] = (kind, path)
        self.bindings = dict(bindings)
        self.uploads = dict(uploads or {})
        if any(
            not isinstance(key, str) or not key or not callable(value)
            for key, value in self.uploads.items()
        ):
            raise ValueError(
                "Uploads must map exact backend IDs to async upload callbacks"
            )
        self._closed = False
        self._references: dict[str, tuple[int, str]] = {}
        self._item_metadata: dict[str, dict[str, Any]] = {}
        self._receipts = {}
        self._receipt_locks = {}
        self._close_done = anyio.Event()

    def _remember(self, event):
        for slot in self.bindings:
            if slot in self._item_metadata:
                continue
            kind, path = self._slots[slot]
            if event.get("type") != kind:
                raise ProtocolError("Content source slot does not match event boundary")
            try:
                self._item_metadata[slot] = deepcopy(at(event, path))
            except (KeyError, IndexError, TypeError) as exc:
                raise ProtocolError("Bound content source item is absent") from exc

    def _reconcile(self, event):
        """Follow stable part identities across admitted message-list edits."""
        from ._boundaries import CONTENT_SOURCE_SLOTS

        candidates = {}

        def visit(node, path, concrete=(), indices=()):
            if not path:
                yield concrete, indices, node
            elif path[0] == "*" and isinstance(node, list):
                for index, child in enumerate(node):
                    yield from visit(
                        child, path[1:], concrete + (index,), indices + (index,)
                    )
            elif isinstance(node, dict) and path[0] in node:
                yield from visit(
                    node[path[0]], path[1:], concrete + (path[0],), indices
                )

        for name, (kind, template) in CONTENT_SOURCE_SLOTS.items():
            if kind != event["type"]:
                continue
            for path, indices, item in visit(event, template):
                slot = name + "".join(f"[{index}]" for index in indices)
                candidates.setdefault(item["id"], []).append((slot, kind, path, item))
        bindings, slots, metadata = {}, {}, {}
        previous = set(self.bindings.values())
        for old_slot, source in self.bindings.items():
            original = self._item_metadata[old_slot]
            for slot, kind, path, item in candidates.get(original["id"], []):
                if item.get("kind") != original.get("kind") or item.get(
                    "mediaType"
                ) != original.get("mediaType"):
                    continue
                if "body" in item and item["body"]["ref"] not in self._references:
                    continue
                if slot in bindings and bindings[slot] is not source:
                    raise ProtocolError(
                        "Logical content part has conflicting source owners"
                    )
                bindings[slot], slots[slot], metadata[slot] = (
                    source,
                    (kind, path),
                    original,
                )
        self.bindings, self._slots, self._item_metadata = bindings, slots, metadata
        return previous - set(bindings.values())

    def edit_context(self, event, backend, upload, context):
        # Binary owners are independent of inline text/JSON settlement.
        return context

    async def project(
        self,
        event: dict[str, Any],
        selection: dict[str, str],
        *,
        upload: Uploader | None = None,
        backend: str | None = None,
        validator: Any,
        include_native: bool = False,
        delivery_context: Any = None,
        upload_limiter: Any = None,
    ) -> dict[str, Any]:
        if self._closed:
            raise ProtocolError("Content sources are closed")
        self._remember(event)
        view = project_content(event, selection, include_native)
        selected_items = []
        context = delivery_context if delivery_context is not None else backend
        if context is None:
            # Unscoped standalone projections are distinct deliveries.
            context = object()
        for slot, source in self.bindings.items():
            kind, path = self._slots[slot]
            if event.get("type") != kind:
                raise ProtocolError("Content source slot does not match event boundary")
            try:
                original = at(event, path)
                item = at(view, path)
            except (KeyError, IndexError, TypeError) as exc:
                raise ProtocolError("Bound content source item is absent") from exc
            validator.validate("content-item", original)
            # A settled replacement or advanced caller-supplied reference is
            # not the owned source. Never overwrite it with the original bytes.
            reference = original.get("body")
            if (
                reference is not None
                and reference["ref"] not in self._references
                and reference["ref"] != "ahp:owned:pending"
            ):
                continue
            available = deepcopy(original)
            available["selection"] = "body"
            selected = project_content(available, selection, True)
            if selected["selection"] != "body" or original["selection"] == "omit":
                continue
            selected_items.append((source, original, item))

        async def prepare(source, original, item):
            key = (context, source)
            lock = self._receipt_locks.setdefault(key, anyio.Lock())
            async with lock:
                reference = self._receipts.get(key)
                if reference is None:
                    uploader = (
                        upload if upload is not None else self.uploads.get(backend)
                    )
                    if uploader is None:
                        raise ProtocolError(
                            "Selected content requires an authorized backend upload callback"
                        )

                    async def transfer():
                        data = await source.snapshot()
                        digest = hashlib.sha256(data).hexdigest()
                        if any(
                            key in original and original[key] != value
                            for key, value in (("size", len(data)), ("sha256", digest))
                        ):
                            raise ProtocolError(
                                "Content source metadata disagrees with actual bytes"
                            )
                        receipt = await uploader(data)
                        validator.validate("content-upload-receipt", receipt)
                        identity = (len(data), digest)
                        if (receipt["size"], receipt["sha256"]) != identity:
                            raise ProtocolError(
                                "Uploaded descriptor does not match source bytes"
                            )
                        known = self._references.get(receipt["ref"])
                        if known is not None and known != identity:
                            raise ProtocolError("Immutable content reference changed")
                        self._references[receipt["ref"]] = identity
                        return deepcopy(receipt)

                    if upload_limiter is None:
                        reference = await transfer()
                    else:
                        async with upload_limiter:
                            reference = await transfer()
                    # Publish only fully confirmed receipts, never bytes or tasks.
                    self._receipts[key] = reference
            item.pop("gap", None)
            item.update(selection="body", body={"ref": reference["ref"]})
            item.pop("size", None)
            item.pop("sha256", None)
            validator.validate("content-item", item)

        try:
            async with anyio.create_task_group() as group:
                for source, original, item in selected_items:
                    group.start_soon(prepare, source, original, item)
        except ExceptionGroup as exc:
            raise exc.exceptions[0] from None
        return view

    async def aclose(self) -> None:
        if self._closed:
            with anyio.move_on_after(1, shield=True):
                await self._close_done.wait()
            return
        self._closed = True
        try:
            with anyio.CancelScope(shield=True):
                async with anyio.create_task_group() as group:
                    for source in set(self.bindings.values()):
                        group.start_soon(source.aclose)
        finally:
            self._references.clear()
            self._item_metadata.clear()
            self._receipts.clear()
            self._receipt_locks.clear()
            self.bindings.clear()
            self.uploads.clear()
            self._close_done.set()

    async def __aenter__(self) -> ContentSources:
        if self._closed:
            raise ProtocolError("Content sources are closed")
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()
