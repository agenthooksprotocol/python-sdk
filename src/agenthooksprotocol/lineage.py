"""Source-scoped lineage validation independent of subscription projection."""

from threading import RLock
from .runtime import ProtocolError, _json_equal


class TaskLineage:
    def __init__(self, validator, *, producer=False):
        self.validator = validator
        self.producer = producer
        self.parents = {}
        self.identities = {}
        self.roles = {}
        self.owners = {}
        self.lock = RLock()

    def accept(self, event):
        self.validator.validate(
            "observe-notification",
            {
                "jsonrpc": "2.0",
                "method": "hooks/observe",
                "params": {"protocolVersion": "draft", "event": event},
            },
        )
        kind = event["type"]
        task = event.get("task", {})
        identity = (kind, task.get("id"), task.get("operation"))
        if kind in ("task.change.after", "workspace.change.after"):
            payload = (
                event["task"] if kind == "task.change.after" else event["workspace"]
            )
            if payload.get("operation") != "remove" and "prior" in payload:
                if all(
                    k in payload["prior"] and _json_equal(v, payload["prior"][k])
                    for k, v in payload["change"].items()
                ):
                    raise ProtocolError("After event must report an actual change")
        key = (event["source"], event["id"])
        parent = (
            (event["source"], event["parentEventId"])
            if "parentEventId" in event
            else None
        )
        with self.lock:
            roles, owners = dict(self.roles), dict(self.owners)

            from ._content import normalized_content_slots, normalized_values

            _, message_paths = normalized_content_slots().get(kind, ((), ()))
            for message in normalized_values(event, message_paths):
                message_key = (event["source"], message["id"])
                if message_key in roles and roles[message_key] != message["role"]:
                    raise ProtocolError("Logical message changed role")
                roles[message_key] = message["role"]
                for part in message["parts"]:
                    part_key = (event["source"], part["id"])
                    if part_key in owners and owners[part_key] != message_key:
                        raise ProtocolError("Logical content part changed owner")
                    if part_key in roles and roles[part_key] != message["role"]:
                        raise ProtocolError("Logical content part changed role")
                    owners[part_key] = message_key
                    roles[part_key] = message["role"]
            for item_key, owner in owners.items():
                if owner in roles and roles[item_key] != roles[owner]:
                    raise ProtocolError("Content child role disagrees with owner")
                if self.producer and owner not in roles:
                    raise ProtocolError("Producer content owner is not known")
                cursor, seen_items = owner, {item_key}
                while cursor is not None:
                    if cursor in seen_items:
                        raise ProtocolError("Cyclic content ownership")
                    seen_items.add(cursor)
                    cursor = owners.get(cursor)
            if key in self.parents:
                if self.parents[key] != parent or self.identities[key] != identity:
                    raise ProtocolError("Logical event changed its parent")
                self.roles, self.owners = roles, owners
                return
            if self.producer and parent is not None and parent not in self.parents:
                raise ProtocolError("Producer parent is not known")
            cursor = parent
            seen = {key}
            while cursor is not None:
                if cursor in seen:
                    raise ProtocolError("Cyclic event lineage")
                seen.add(cursor)
                cursor = self.parents.get(cursor)

            def check_pair(before, after):
                if (
                    before[0] == "task.change.before"
                    and after[0] == "task.change.after"
                    and before[1:] != after[1:]
                ):
                    raise ProtocolError("Known task before/after identity mismatch")

            if parent in self.identities:
                check_pair(self.identities[parent], identity)
            for child, child_parent in self.parents.items():
                if child_parent == key:
                    check_pair(identity, self.identities[child])
            self.parents[key] = parent
            self.identities[key] = identity
            self.roles, self.owners = roles, owners
