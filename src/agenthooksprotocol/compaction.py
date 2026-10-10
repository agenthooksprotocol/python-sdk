"""Serial host-side compaction interception. Text replacement is opt-in.

Hooks get detached snapshots and return draft effect arrays. Responses stage
privately. Only `applied` permits downstream use. Text is carried as canonical inline text-part lists. No LLM is required.
"""

from copy import deepcopy
from threading import Thread
from .runtime import Validator


def compaction_capabilities(boundary, observe_only=False):
    if boundary not in ("before", "after"):
        raise ValueError("unknown boundary")
    if observe_only:
        return {"effects": [], "modify": {}}
    return {
        "effects": ["modify", "message"]
        + (["return", "deny"] if boundary == "before" else []),
        "modify": {
            "instructions" if boundary == "before" else "summary": {
                "replace": True,
                "merge": True,
            }
        },
    }


def text_parts(text, item_id="text-1"):
    """Serialize host convenience text, never a hook effect value."""
    return [
        {
            "id": item_id,
            "kind": "text",
            "mediaType": "text/plain",
            "selection": "body",
            "text": text,
        }
    ]


def validate_text_parts(value, validator):
    if not isinstance(value, list):
        raise ValueError("Compaction text must be a text-part list")
    for part in value:
        validator.validate("content-item", part)
        if (
            part.get("kind") != "text"
            or part.get("mediaType") != "text/plain"
            or part.get("selection") != "body"
            or "text" not in part
        ):
            raise ValueError("Compaction requires selected inline text")


def validate_text_effects(boundary, effects, capabilities, validator):
    """Admit complete canonical responses before staging any changes."""
    target = "instructions" if boundary == "before" else "summary"
    for effect in effects:
        validator.validate("effect", effect)
        kind = effect["type"]
        if kind not in capabilities["effects"] or kind not in (
            ("modify", "return", "deny", "message")
            if boundary == "before"
            else ("modify", "message")
        ):
            raise ValueError("Unsupported compaction effect")
        if kind == "modify":
            operation = effect["operation"]
            if (
                effect["target"] != target
                or operation not in ("replace", "merge")
                or capabilities.get("modify", {}).get(target, {}).get(operation)
                is not True
            ):
                raise ValueError("Compaction modification requires granted operation")
            validate_text_parts(effect["value"], validator)
        if kind == "return":
            validate_text_parts(effect["value"], validator)
        if kind == "deny" and not effect.get("reason"):
            raise ValueError("Compaction denial requires a reason")


def run_compaction(
    instructions,
    before=(),
    after=(),
    *,
    generate=None,
    item_id="summary-1",
    observe_only=False,
):
    """Hooks are (supplier, fail-open|fail-closed, callback) tuples.

    Return binds to final instructions in its response; later effective input
    changes invalidate it. Observe-only after callbacks are detached daemon-thread
    notifications of settled state; return values and failures are ignored.
    """
    if not isinstance(item_id, str) or not item_id:
        raise ValueError("instructions and nonempty item ID required")
    validator = Validator()
    if isinstance(instructions, str):
        instructions = text_parts(instructions, "instructions")
    validate_text_parts(instructions, validator)
    before, after = list(before), list(after)
    for supplier, policy, callback in before + after:
        if (
            not isinstance(supplier, str)
            or not supplier
            or policy not in ("fail-open", "fail-closed")
            or not callable(callback)
        ):
            raise ValueError("invalid hook configuration")
    state = {
        "instructions": deepcopy(instructions),
        "candidate": None,
        "summary": None,
        "messages": [],
        "denied": False,
    }
    seen, failures = [], []

    def pipeline(boundary, hooks):
        nonlocal state
        caps = compaction_capabilities(boundary, observe_only and boundary == "after")
        for supplier, policy, callback in hooks:
            snapshot = dict(deepcopy(state), boundary=boundary, capabilities=caps)
            seen.append(deepcopy(snapshot))
            try:
                effects = callback(deepcopy(snapshot))
                if not isinstance(effects, list):
                    raise ValueError("effects must be an array")
                validate_text_effects(boundary, effects, caps, validator)
                staged = deepcopy(state)
                for effect in effects:
                    if effect["type"] == "modify":
                        target = effect["target"]
                        value = deepcopy(effect["value"])
                        staged[target] = (
                            staged[target] + value
                            if effect["operation"] == "merge"
                            else value
                        )
                if staged["instructions"] != state["instructions"]:
                    staged["candidate"] = None
                for effect in effects:
                    if effect["type"] == "return":
                        staged["candidate"] = {
                            "value": deepcopy(effect["value"]),
                            "supplier": supplier,
                        }
                    elif effect["type"] == "deny":
                        staged["denied"] = True
                    elif effect["type"] == "message":
                        staged["messages"].append(effect["text"])
                state = staged
            except Exception:
                failures.append({"boundary": boundary, "supplier": supplier})
                if policy == "fail-closed" and not (
                    observe_only and boundary == "after"
                ):
                    return False
            if state["denied"]:
                return False
        return True

    generated, applied, provenance = False, False, None
    if pipeline("before", before):
        candidate = state["candidate"]
        if candidate is not None:
            body = deepcopy(candidate["value"])
            provenance = {"kind": "supplied", "supplier": candidate["supplier"]}
        else:
            body = (
                generate
                or (
                    lambda value: text_parts(
                        "summary:" + "".join(part["text"] for part in value), item_id
                    )
                )
            )(state["instructions"])
            if isinstance(body, str):
                body = text_parts(body, item_id)
            validate_text_parts(body, validator)
            generated = True
            provenance = {"kind": "generated"}
        state["summary"] = deepcopy(body)
        applied = True if observe_only else pipeline("after", after)
    result = dict(
        state,
        seen=seen,
        failures=failures,
        generated=generated,
        provenance=provenance,
        applied=applied,
    )
    if observe_only and applied:
        # Settlement is complete. Detached notifications have no effect authority
        # and never mutate result/diagnostics, even after the caller returns.
        deliveries = []
        for _, _, callback in after:
            snapshot = dict(
                deepcopy(state),
                boundary="after",
                applied=True,
                generated=generated,
                provenance=deepcopy(provenance),
                capabilities=compaction_capabilities("after", True),
            )
            seen.append(deepcopy(snapshot))
            deliveries.append((callback, snapshot))

        def notify(callback, snapshot):
            try:
                callback(snapshot)  # Return values are deliberately ignored.
            except BaseException:
                pass  # Best effort, including callback SystemExit/cancellation.

        for callback, snapshot in deliveries:
            try:
                Thread(target=notify, args=(callback, snapshot), daemon=True).start()
            except RuntimeError:
                pass  # Scheduler failure cannot reopen settlement.
    return result
