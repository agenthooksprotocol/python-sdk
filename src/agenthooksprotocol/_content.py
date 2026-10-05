"""Explicit, trusted asynchronous bindings for immutable normalized content.

Resolvers and uploaders are transport/storage adapters, not domain validators.
Bodies never appear inline in wire events, and no primary payload is inferred.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
import hashlib
import json
from typing import Any

from .runtime import ProtocolError, json_equal

Reference = dict[str, Any]
Resolver = Callable[[Reference], Awaitable[bytes]]
Uploader = Callable[[bytes], Awaitable[Reference]]


def at(value: Any, path: tuple[str | int, ...]) -> Any:
    for component in path:
        value = value[component]
    return value


def put(value: Any, path: tuple[str | int, ...], replacement: Any) -> None:
    if not path:
        raise ProtocolError("Content binding requires an explicit nonempty path")
    at(value, path[:-1])[path[-1]] = replacement


def project_content(
    event: dict[str, Any], selection: dict[str, str], include_native: bool = False
) -> dict[str, Any]:
    """Project descriptors at every normalized depth, never arbitrary host JSON."""

    def walk(value: Any) -> Any:
        if isinstance(value, list):
            return [walk(item) for item in value]
        if not isinstance(value, dict):
            return deepcopy(value)
        if all(key in value for key in ("id", "kind", "mediaType", "selection")):
            item = deepcopy(value)
            media = item["mediaType"]
            category = (
                "reasoning"
                if item["kind"] == "reasoning"
                else item.get("category")
                or (
                    "text"
                    if media.startswith("text/")
                    else "images"
                    if media.startswith("image/")
                    else "audio"
                    if media.startswith("audio/")
                    else "video"
                    if media.startswith("video/")
                    else "files"
                )
            )
            wanted = selection.get(category, selection["default"])
            # A selection is a ceiling, never permission to restore absent bytes.
            rank = {"omit": 0, "metadata": 1, "body": 2}
            mode = min((wanted, item["selection"]), key=rank.__getitem__)
            if mode != "body":
                item.pop("body", None)
                item.pop("gap", None)
                item["selection"] = mode
            return item
        return {
            key: deepcopy(item)
            if key in ("input", "native", "extensions")
            else walk(item)
            for key, item in value.items()
        }

    projected = walk(event)
    if not include_native:
        projected.pop("native", None)
    return projected


def merge_effective(original: Any, view: Any, effective: Any) -> Any:
    """Apply an admitted view delta without turning projection into a host edit."""
    if json_equal(view, effective):
        return deepcopy(original)
    if (
        isinstance(original, dict)
        and isinstance(view, dict)
        and isinstance(effective, dict)
    ):
        merged = deepcopy(original)
        for key in view.keys() - effective.keys():
            merged.pop(key, None)
        for key, value in effective.items():
            merged[key] = (
                merge_effective(original[key], view[key], value)
                if key in original and key in view
                else deepcopy(value)
            )
        return merged
    return deepcopy(effective)


class ContentContext:
    """Explicit body bindings for one or more calls.

    ``bindings`` maps effect targets to descriptor paths in the event. MCP
    request binds ``request``; result binds ``content`` and supplies an immutable
    ``original_request`` wire snapshot. Compaction binds ``instructions`` or
    ``summary``. ``principal`` is trusted transport identity, never event data.
    A fresh prepared context is made per invocation, safe for concurrent calls.
    """

    def __init__(
        self,
        *,
        resolve: Resolver,
        upload: Uploader,
        bindings: Mapping[str, tuple[str | int, ...]],
        principal: str,
        original_request: dict[str, Any] | None = None,
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
        self._identities: dict[str, tuple[int, str]] = {}

    async def prepare(self, request: dict[str, Any], validator: Any) -> PreparedContent:
        prepared = PreparedContent(self, request, validator)
        await prepared.load()
        return prepared


class PreparedContent:
    def __init__(
        self, context: ContentContext, request: dict[str, Any], validator: Any
    ) -> None:
        self.context = context
        self.request = deepcopy(request)
        self.validator = validator
        self.raw: dict[str, bytes] = {}
        self.items: dict[str, dict[str, Any]] = {}
        self.selected: dict[str, bytes] = {}
        self.targets = set(context.bindings) - {"request"}

    async def _read(self, item: dict[str, Any]) -> bytes | None:
        self.validator.validate("content-item", item)
        if item["selection"] != "body":
            return None
        if "body" not in item:
            raise ProtocolError("Selected content body is unavailable")
        reference = item["body"]
        if any(
            key in item and item[key] != reference[key] for key in ("size", "sha256")
        ):
            raise ProtocolError("Content metadata disagrees with body descriptor")
        data = await self.context.resolve(deepcopy(reference))
        if (
            not isinstance(data, bytes)
            or len(data) != reference["size"]
            or hashlib.sha256(data).hexdigest() != reference["sha256"]
        ):
            raise ProtocolError("Resolved content does not match immutable descriptor")
        identity = (reference["size"], reference["sha256"])
        known = self.context._identities.get(reference["ref"])
        if known is not None and known != identity:
            raise ProtocolError("Immutable content reference changed")
        self.context._identities[reference["ref"]] = identity
        old = self.raw.get(reference["ref"])
        if old is not None and old != data:
            raise ProtocolError("Immutable content reference changed")
        self.raw[reference["ref"]] = data
        return data

    async def load(self) -> None:
        event = self.request["params"]["event"]
        kind = event["type"]
        expected = {
            "user.elicitation.request": {"request": ("elicitation", "request")},
            "user.elicitation.result": {"content": ("elicitation", "result")},
            "context.compact.before": {"instructions": ("instructions",)},
            "context.compact.after": {"summary": ("summary",)},
        }.get(kind)
        if expected is None or self.context.bindings != expected:
            raise ProtocolError("Content targets must explicitly match this boundary")
        if kind == "user.elicitation.result":
            from .elicitation import validate_correlation

            original = self.context.original_request
            if original is None:
                raise ProtocolError(
                    "Elicitation result requires its original request snapshot"
                )
            self.validator.validate("intercept-request", original)
            validate_correlation(original, self.request)
            # The original snapshot is not a way to override current selection.
            item = at(event, self.context.bindings["content"])
            if item.get("selection") == "body":
                await self._read(original["params"]["event"]["elicitation"]["request"])
        for target, path in self.context.bindings.items():
            try:
                item = at(event, path)
            except (KeyError, IndexError, TypeError) as exc:
                raise ProtocolError("Bound content descriptor is absent") from exc
            self.items[target] = deepcopy(item)
            data = await self._read(item)
            if data is not None:
                self.selected[target] = data

    def _resolve(self, reference: dict[str, Any]) -> bytes:
        try:
            return self.raw[reference["ref"]]
        except KeyError as exc:
            raise ProtocolError("Content was not selected and resolved") from exc

    def stage(
        self, request: dict[str, Any], effects: list[dict[str, Any]]
    ) -> dict[str, Any]:
        event = request["params"]["event"]
        kind = event["type"]
        updates: list[dict[str, Any]] = []
        values: dict[str, Any] = {}
        changed = False
        if kind.startswith("user.elicitation."):
            from .elicitation import apply_effects, read_selected, validate_exchange

            original = (
                request if kind.endswith(".request") else self.context.original_request
            )
            result = None if kind.endswith(".request") else request
            body_effects = [
                effect
                for effect in effects
                if effect["type"] in ("return", "deny", "modify")
            ]
            if body_effects:
                if not self.selected:
                    raise ProtocolError("Elicitation effects require selected bodies")
                binding = apply_effects(
                    original,
                    result,
                    self._resolve,
                    self.validator.validate,
                    self.context.principal,
                    body_effects,
                )
                answer = binding["result"]
                encoded = json.dumps(
                    answer, allow_nan=False, ensure_ascii=False, separators=(",", ":")
                ).encode()
                target = "candidate" if result is None else "content"
                values[target] = deepcopy(answer)
                changed = result is not None and not json_equal(
                    json.loads(self.selected["content"]), answer
                )
                if result is None or changed:
                    updates.append({"target": target, "data": encoded})
                values["provenance"] = binding["provenance"]
                values["externalCompletion"] = False
            elif self.selected:
                if result is None:
                    values["request"] = read_selected(
                        event["elicitation"],
                        "request",
                        self._resolve,
                        self.validator.validate,
                    )
                else:
                    binding = validate_exchange(
                        original,
                        result,
                        self._resolve,
                        self.validator.validate,
                        self.context.principal,
                    )
                    values["content"] = binding.get("result")
                    values["externalCompletion"] = False
        else:
            from .compaction import validate_text_effects

            boundary = "before" if kind.endswith(".before") else "after"
            validate_text_effects(
                boundary, effects, request["params"]["capabilities"], self.validator
            )
            for target, raw in self.selected.items():
                if not self.items[target]["mediaType"].startswith("text/"):
                    raise ProtocolError("Compaction requires selected UTF-8 text")
                values[target] = raw.decode("utf-8", errors="strict")
            for effect in effects:
                if effect["type"] == "modify":
                    target = effect["target"]
                    if target not in self.selected:
                        raise ProtocolError(
                            "Compaction modification requires selected content"
                        )
                    values[target] = effect["value"]
                elif effect["type"] == "return":
                    if "instructions" not in self.selected:
                        raise ProtocolError(
                            "Supplied compaction summary requires selected instructions"
                        )
                    values["candidate"] = effect["value"]
            for target, value in values.items():
                data = value.encode("utf-8")
                if target == "candidate" or data != self.selected[target]:
                    updates.append({"target": target, "data": data})
                    changed = changed or target != "candidate"
        return {"changed": changed, "updates": updates, "values": values}

    async def finalize(self, state: dict[str, Any]) -> dict[str, Any]:
        state = deepcopy(state)
        updates = state.pop("_content_updates", [])
        references = {}
        used = set(self.raw)
        for update in updates:
            data = update["data"]
            reference = await self.context.upload(data)
            self.validator.validate("content-reference", reference)
            if (
                reference["size"] != len(data)
                or reference["sha256"] != hashlib.sha256(data).hexdigest()
            ):
                raise ProtocolError(
                    "Uploaded descriptor does not match replacement bytes"
                )
            if reference["ref"] in used or reference["ref"] in self.context._identities:
                raise ProtocolError(
                    "Modified content requires a new immutable reference"
                )
            used.add(reference["ref"])
            self.context._identities[reference["ref"]] = (
                reference["size"],
                reference["sha256"],
            )
            target = update["target"]
            references[target] = deepcopy(reference)
            if target == "candidate" and state.get("candidate") is not None:
                state["candidate"].setdefault("provenance", {}).update(
                    authenticatedSource=self.context.principal,
                    contentReference=deepcopy(reference),
                )
            if target != "candidate":
                item = deepcopy(self.items[target])
                item.pop("gap", None)
                item.update(selection="body", body=deepcopy(reference))
                if "size" in item:
                    item["size"] = len(data)
                if "sha256" in item:
                    item["sha256"] = reference["sha256"]
                put(state["event"], self.context.bindings[target], item)
        candidate_ref = (
            (state.get("candidate") or {}).get("provenance", {}).get("contentReference")
        )
        if isinstance(candidate_ref, dict) and self.context._identities.get(
            candidate_ref.get("ref")
        ) == (candidate_ref.get("size"), candidate_ref.get("sha256")):
            references.setdefault("candidate", deepcopy(candidate_ref))
        if references:
            state["content_references"] = references
        check = deepcopy(self.request)
        check["params"]["event"] = state["event"]
        self.validator.validate("intercept-request", check)
        return state
