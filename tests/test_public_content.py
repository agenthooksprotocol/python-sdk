"""Public content-bound settlement on asyncio and Trio, including negative cases."""

from copy import deepcopy
import hashlib
import json
import unittest
from uuid import uuid4

import anyio

from agenthooksprotocol import Hooks
from agenthooksprotocol._content import ContentContext


class Store:
    def __init__(self):
        self.bodies = {}
        self.reads = []
        self.writes = []

    def add(self, value, media="application/json", role=None):
        data = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        reference = self.reference(data)
        self.bodies[reference["ref"]] = data
        item = {
            "id": str(uuid4()),
            "kind": "content",
            "mediaType": media,
            "selection": "body",
            "body": {"ref": reference["ref"]},
        }
        if role is not None:
            item["role"] = role
        return item

    def reference(self, data):
        return {
            "ref": "urn:blob:" + str(uuid4()),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    async def resolve(self, reference):
        self.reads.append(deepcopy(reference))
        return self.bodies[reference["ref"]]

    async def upload(self, data):
        reference = self.reference(data)
        self.bodies[reference["ref"]] = data
        self.writes.append(reference)
        return reference


class Replies:
    def __init__(self, *effects):
        self.effects = list(effects)
        self.requests = []

    async def request(self, request):
        self.requests.append(deepcopy(request))
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"protocolVersion": "draft", "effects": self.effects.pop(0)},
        }

    async def notify(self, message):
        pass


def hooks_for(event, caps, transport, *, count=1, selection="body"):
    config = {
        "protocolVersion": "draft",
        "hooks": [
            {
                "id": "org.example.content",
                "transport": {"type": "http", "url": "https://hook.invalid"},
                "subscriptions": [
                    {
                        "events": [event],
                        "mode": "intercept",
                        "timeoutMs": 1000,
                        "failurePolicy": "fail-closed",
                        "content": {"default": selection},
                    }
                    for _ in range(count)
                ],
            }
        ],
    }
    return Hooks(
        config,
        source="urn:test",
        capabilities={event: {"modes": ["intercept"], "capabilities": caps}},
        transport=transport,
    )


def wire(name, ident, payload, caps):
    return {
        "jsonrpc": "2.0",
        "id": ident,
        "method": "hooks/intercept",
        "params": {
            "protocolVersion": "draft",
            "capabilities": caps,
            "event": {
                "id": ident,
                "source": "urn:test",
                "type": name,
                "time": "2026-01-01T00:00:00Z",
                "session": {"id": "session"},
                **payload,
            },
        },
    }


def elicitation(store):
    body = {
        "mode": "form",
        "message": "Answer",
        "requestedSchema": {
            "type": "object",
            "properties": {"ok": {"type": "boolean", "default": True}},
            "required": ["ok"],
        },
    }
    req_caps = {"effects": ["return", "deny"], "elicitation": {"form": {}}}
    res_caps = {
        "effects": ["modify"],
        "modify": {"content": {"replace": True, "merge": True}},
        "elicitation": {"form": {}},
    }
    request = wire(
        "user.elicitation.request",
        "original",
        {
            "elicitation": {
                "mode": "form",
                "server": "example",
                "request": store.add(body),
            }
        },
        req_caps,
    )
    result = wire(
        "user.elicitation.result",
        "answer",
        {
            "parentEventId": "original",
            "elicitation": {
                "mode": "form",
                "server": "example",
                "action": "accept",
                "result": store.add({"action": "accept", "content": {"ok": False}}),
            },
        },
        res_caps,
    )
    return request, result


def modify(target, value):
    return {"type": "modify", "target": target, "operation": "replace", "value": value}


class PublicContentTests(unittest.TestCase):
    def run_async(self, fn):
        for backend in ("asyncio", "trio"):
            with self.subTest(backend=backend):
                anyio.run(fn, backend=backend)

    def test_elicitation_messages_do_not_require_selected_bodies(self):
        async def run():
            for selection in ("body", "metadata", "omit"):
                store = Store()
                request, _ = elicitation(store)
                caps = {"effects": ["message"]}
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings={"request": ("elicitation", "request")},
                    principal="hook",
                )
                transport = Replies([{"type": "message", "text": "audit"}])
                async with hooks_for(
                    "user.elicitation.request", caps, transport, selection=selection
                ) as hooks:
                    result = await hooks.user_elicitation_request(
                        request["params"]["event"], content=context
                    )
                self.assertEqual(result.diagnostics, [])
                self.assertEqual(result.state["messages"], ["audit"])
                self.assertEqual(len(result.accepted_responses), 1)
                self.assertEqual(store.writes, [])
                if selection != "body":
                    self.assertEqual(store.reads, [])

        self.run_async(run)

    def test_elicitation_messages_and_body_effects_settle_as_one_batch(self):
        async def run():
            for stage in ("request", "result", "invalid"):
                store = Store()
                request, result = elicitation(store)
                original = request if stage != "result" else result
                caps = deepcopy(original["params"]["capabilities"])
                caps["effects"].append("message")
                if stage == "result":
                    effect = modify("content", {"ok": True})
                    bindings = {"content": ("elicitation", "result")}
                else:
                    effect = {
                        "type": "return",
                        "value": {
                            "action": "accept",
                            "content": {} if stage == "invalid" else {"ok": True},
                        },
                    }
                    bindings = {"request": ("elicitation", "request")}
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings=bindings,
                    principal="hook",
                    original_request=request if stage == "result" else None,
                )
                transport = Replies([{"type": "message", "text": "audit"}, effect])
                async with hooks_for(
                    original["params"]["event"]["type"], caps, transport
                ) as hooks:
                    settled = await hooks.dispatch(
                        original["params"]["event"]["type"],
                        original["params"]["event"],
                        content=context,
                    )
                if stage == "invalid":
                    self.assertEqual(settled.state["messages"], [])
                    self.assertEqual(settled.accepted_responses, [])
                    self.assertEqual(store.writes, [])
                else:
                    self.assertEqual(settled.diagnostics, [])
                    self.assertEqual(settled.state["messages"], ["audit"])
                    self.assertEqual(len(settled.accepted_responses), 1)
                    self.assertEqual(len(store.writes), 1)

        self.run_async(run)

    def test_elicitation_result_uses_original_snapshot_and_new_immutable_body(self):
        async def run():
            store = Store()
            request, result = elicitation(store)
            context = ContentContext(
                resolve=store.resolve,
                upload=store.upload,
                bindings={"content": ("elicitation", "result")},
                principal="authenticated-hook",
                original_request=request,
            )
            transport = Replies([modify("content", {"ok": True})])
            async with hooks_for(
                "user.elicitation.result", result["params"]["capabilities"], transport
            ) as hooks:
                settled = await hooks.user_elicitation_result(
                    result["params"]["event"], event_id="answer", content=context
                )
            self.assertEqual(settled.diagnostics, [])
            self.assertEqual(
                settled.state["content"]["content"],
                {"action": "accept", "content": {"ok": True}},
            )
            reference = settled.event["elicitation"]["result"]["body"]
            self.assertNotEqual(
                reference, result["params"]["event"]["elicitation"]["result"]["body"]
            )
            self.assertEqual(
                json.loads(store.bodies[reference["ref"]])["content"], {"ok": True}
            )
            self.assertEqual(len(store.writes), 1)
            self.assertFalse(settled.state["content"]["externalCompletion"])

        self.run_async(run)

    def test_elicitation_request_return_validates_answer_without_inserting_defaults(
        self,
    ):
        async def run():
            for answer, valid in (
                ({"action": "accept", "content": {"ok": True}}, True),
                ({"action": "accept", "content": {}}, False),
            ):
                store = Store()
                request, _ = elicitation(store)
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings={"request": ("elicitation", "request")},
                    principal="hook",
                )
                transport = Replies([{"type": "return", "value": answer}])
                async with hooks_for(
                    "user.elicitation.request",
                    request["params"]["capabilities"],
                    transport,
                ) as hooks:
                    settled = await hooks.user_elicitation_request(
                        request["params"]["event"], content=context
                    )
                self.assertEqual(bool(settled.accepted_responses), valid)
                self.assertEqual(len(store.writes), int(valid))
                if valid:
                    self.assertEqual(settled.candidate["value"], answer)
                    self.assertIn("candidate", settled.state["content_references"])
                else:
                    self.assertEqual(settled.decision, "deny")

        self.run_async(run)

    def test_elicitation_mode_and_original_correlation_are_not_invented(self):
        async def run():
            for bad_mode in (False, True):
                store = Store()
                request, result = elicitation(store)
                if bad_mode:
                    result["params"]["capabilities"]["elicitation"] = {}
                else:
                    result["params"]["event"]["parentEventId"] = "wrong"
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings={"content": ("elicitation", "result")},
                    principal="hook",
                    original_request=request,
                )
                async with hooks_for(
                    "user.elicitation.result",
                    result["params"]["capabilities"],
                    Replies([modify("content", {"ok": True})]),
                ) as hooks:
                    settled = await hooks.user_elicitation_result(
                        result["params"]["event"], content=context
                    )
                self.assertEqual(settled.decision, "deny")
                self.assertEqual(store.writes, [])
                if not bad_mode:
                    self.assertEqual(store.reads, [])

        self.run_async(run)

    def test_nested_metadata_and_omit_never_resolve_or_upload(self):
        async def run():
            for selection in ("metadata", "omit"):
                store = Store()
                request, result = elicitation(store)
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings={"content": ("elicitation", "result")},
                    principal="hook",
                    original_request=request,
                )
                transport = Replies([])
                async with hooks_for(
                    "user.elicitation.result",
                    result["params"]["capabilities"],
                    transport,
                    selection=selection,
                ) as hooks:
                    settled = await hooks.user_elicitation_result(
                        result["params"]["event"], content=context
                    )
                self.assertEqual(settled.diagnostics, [])
                self.assertEqual(store.reads, [])
                self.assertEqual(store.writes, [])
                view = transport.requests[0]["params"]["event"]["elicitation"]["result"]
                self.assertEqual(view["selection"], selection)
                self.assertNotIn("body", view)
                self.assertEqual(
                    settled.event["elicitation"]["result"],
                    result["params"]["event"]["elicitation"]["result"],
                )

        self.run_async(run)

    def test_compaction_serial_changed_instructions_invalidate_supplied_summary(self):
        async def run():
            store = Store()
            payload = {
                "trigger": "manual",
                "items": [],
                "instructions": store.add("old", "text/plain"),
            }
            caps = {
                "effects": ["modify", "return", "deny", "message"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            context = ContentContext(
                resolve=store.resolve,
                upload=store.upload,
                bindings={"instructions": ("instructions",)},
                principal="hook",
            )
            transport = Replies(
                [{"type": "return", "value": "supplied"}],
                [modify("instructions", "new")],
                [],
            )
            async with hooks_for(
                "context.compact.before", caps, transport, count=3
            ) as hooks:
                settled = await hooks.context_compact_before(payload, content=context)
            self.assertEqual(settled.diagnostics, [])
            self.assertIsNone(settled.candidate)
            self.assertEqual(settled.state["content"]["instructions"], "new")
            self.assertEqual(
                store.bodies[settled.event["instructions"]["body"]["ref"]], b"new"
            )
            self.assertEqual(len(store.writes), 2)
            self.assertEqual(
                transport.requests[2]["params"]["event"]["instructions"],
                settled.event["instructions"],
            )

        self.run_async(run)

    def test_compaction_after_replaces_text_not_descriptor_or_primary_input(self):
        async def run():
            store = Store()
            payload = {
                "summary": store.add("generated", "text/plain", "assistant"),
                "removed": [],
                "execution": {"status": "executed"},
            }
            caps = {
                "effects": ["modify", "message"],
                "modify": {"summary": {"replace": True, "merge": False}},
            }
            context = ContentContext(
                resolve=store.resolve,
                upload=store.upload,
                bindings={"summary": ("summary",)},
                principal="hook",
            )
            async with hooks_for(
                "context.compact.after", caps, Replies([modify("summary", "redacted")])
            ) as hooks:
                settled = await hooks.context_compact_after(payload, content=context)
            self.assertEqual(settled.diagnostics, [])
            self.assertEqual(settled.state["content"]["summary"], "redacted")
            self.assertEqual(settled.input, {})
            self.assertEqual(settled.event["summary"]["id"], payload["summary"]["id"])
            self.assertEqual(
                store.bodies[settled.event["summary"]["body"]["ref"]], b"redacted"
            )

        self.run_async(run)

    def test_atomic_invalid_batch_and_upload_failure_publish_nothing(self):
        async def run():
            for failure in ("invalid", "upload"):
                store = Store()
                payload = {
                    "trigger": "manual",
                    "items": [],
                    "instructions": store.add("old", "text/plain"),
                }
                caps = {
                    "effects": ["modify", "return"],
                    "modify": {"instructions": {"replace": True, "merge": False}},
                }

                async def broken(data):
                    raise OSError("receiver unavailable")

                context = ContentContext(
                    resolve=store.resolve,
                    upload=broken if failure == "upload" else store.upload,
                    bindings={"instructions": ("instructions",)},
                    principal="hook",
                )
                effects = [modify("instructions", "new")]
                if failure == "invalid":
                    effects.append({"type": "return", "value": 123})
                async with hooks_for(
                    "context.compact.before", caps, Replies(effects)
                ) as hooks:
                    pending = hooks.begin(
                        wire("context.compact.before", "compact", payload, caps),
                        content=context,
                    )
                    await pending.acquire()
                    with self.assertRaises((ValueError, OSError)):
                        await pending.accept_content()
                    self.assertEqual(pending.lifecycle.states, {})
                    self.assertIsNone(pending.result)
                self.assertEqual(store.writes, [])

        self.run_async(run)

    def test_resolver_identity_is_derived_from_actual_bytes(self):
        from agenthooksprotocol._content import PreparedContent
        from agenthooksprotocol.runtime import ProtocolError, Validator

        async def run():
            store = Store()
            item = store.add("original", "text/plain")
            context = ContentContext(
                resolve=store.resolve,
                upload=store.upload,
                bindings={"instructions": ("instructions",)},
                principal="hook",
            )
            prepared = PreparedContent(context, {}, Validator())
            self.assertEqual(await prepared._read(item), b"original")
            self.assertEqual(store.reads, [{"ref": item["body"]["ref"]}])
            store.bodies[item["body"]["ref"]] = b"changed"
            with self.assertRaises(ProtocolError):
                await PreparedContent(context, {}, Validator())._read(item)

        self.run_async(run)

    def test_unavailable_bytes_and_reused_upload_reference_fail_closed(self):
        async def run():
            for failure in ("corrupt", "reused", "metadata"):
                store = Store()
                item = store.add("old", "text/plain")
                payload = {"trigger": "manual", "items": [], "instructions": item}
                caps = {
                    "effects": ["modify"],
                    "modify": {"instructions": {"replace": True, "merge": False}},
                }

                async def corrupt(reference):
                    # A trusted resolver must reject unavailable/corrupt storage.
                    raise ValueError("Stored content unavailable")

                async def reused(data):
                    return {
                        **item["body"],
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }

                context = ContentContext(
                    resolve=corrupt if failure == "corrupt" else store.resolve,
                    upload=reused if failure == "reused" else store.upload,
                    bindings={"instructions": ("instructions",)},
                    principal="hook",
                )
                async with hooks_for(
                    "context.compact.before",
                    caps,
                    Replies([modify("instructions", "new")]),
                    selection="metadata" if failure == "metadata" else "body",
                ) as hooks:
                    result = await hooks.context_compact_before(
                        payload, content=context
                    )
                self.assertEqual(result.decision, "deny")
                self.assertEqual(result.accepted_responses, [])
                self.assertEqual(result.event, {**result.event, "instructions": item})
                self.assertEqual(store.writes, [])
                if failure == "metadata":
                    self.assertEqual(store.reads, [])

        self.run_async(run)

    def test_url_mode_rejects_form_content_and_conflicting_terminal_effects(self):
        async def run():
            for scenario in ("url", "conflict"):
                store = Store()
                request, _ = elicitation(store)
                if scenario == "url":
                    request["params"]["event"]["elicitation"]["mode"] = "url"
                    request["params"]["event"]["elicitation"]["request"] = store.add(
                        {
                            "mode": "url",
                            "message": "Visit",
                            "url": "https://example.test/verify",
                            "elicitationId": "external",
                        }
                    )
                    request["params"]["capabilities"]["elicitation"] = {"url": {}}
                effects = [
                    {
                        "type": "return",
                        "value": {"action": "accept", "content": {"ok": True}},
                    }
                ]
                if scenario == "conflict":
                    effects.append({"type": "deny", "reason": "conflict"})
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings={"request": ("elicitation", "request")},
                    principal="hook",
                )
                async with hooks_for(
                    "user.elicitation.request",
                    request["params"]["capabilities"],
                    Replies(effects),
                ) as hooks:
                    result = await hooks.user_elicitation_request(
                        request["params"]["event"], content=context
                    )
                self.assertEqual(result.decision, "deny")
                self.assertEqual(result.accepted_responses, [])
                self.assertEqual(store.writes, [])

        self.run_async(run)

    def test_same_response_modification_then_supply_binds_candidate_to_final_text(self):
        async def run():
            store = Store()
            payload = {
                "trigger": "manual",
                "items": [],
                "instructions": store.add("old", "text/plain"),
            }
            caps = {
                "effects": ["modify", "return"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            context = ContentContext(
                resolve=store.resolve,
                upload=store.upload,
                bindings={"instructions": ("instructions",)},
                principal="hook",
            )
            transport = Replies(
                [
                    {"type": "return", "value": "summary-for-final"},
                    modify("instructions", "final"),
                ],
                [],
            )
            async with hooks_for(
                "context.compact.before", caps, transport, count=2
            ) as hooks:
                result = await hooks.context_compact_before(payload, content=context)
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(result.candidate["value"], "summary-for-final")
            self.assertEqual(result.content["instructions"], "final")
            self.assertEqual(
                store.bodies[result.content_references["candidate"]["ref"]],
                b"summary-for-final",
            )

        self.run_async(run)

    def test_reasoning_selection_cannot_be_overridden_by_category(self):
        async def run():
            store = Store()
            request, result = elicitation(store)
            item = result["params"]["event"]["elicitation"]["result"]
            item.update(kind="reasoning", category="files")
            caps = result["params"]["capabilities"]
            transport = Replies([])
            hooks = hooks_for("user.elicitation.result", caps, transport)
            hooks.config["hooks"][0]["subscriptions"][0]["content"]["reasoning"] = (
                "omit"
            )
            context = ContentContext(
                resolve=store.resolve,
                upload=store.upload,
                bindings={"content": ("elicitation", "result")},
                principal="hook",
                original_request=request,
            )
            async with hooks:
                settled = await hooks.user_elicitation_result(
                    result["params"]["event"], content=context
                )
            self.assertEqual(settled.diagnostics, [])
            self.assertEqual(store.reads, [])
            self.assertEqual(
                transport.requests[0]["params"]["event"]["elicitation"]["result"][
                    "selection"
                ],
                "omit",
            )

        self.run_async(run)

    def test_cancel_during_upload_cannot_commit(self):
        async def run():
            store = Store()
            started, release = anyio.Event(), anyio.Event()

            async def held(data):
                started.set()
                await release.wait()
                return await store.upload(data)

            payload = {
                "trigger": "manual",
                "items": [],
                "instructions": store.add("old", "text/plain"),
            }
            caps = {
                "effects": ["modify"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            context = ContentContext(
                resolve=store.resolve,
                upload=held,
                bindings={"instructions": ("instructions",)},
                principal="hook",
            )
            async with hooks_for(
                "context.compact.before", caps, Replies([modify("instructions", "new")])
            ) as hooks:
                pending = hooks.begin(
                    wire("context.compact.before", "compact", payload, caps),
                    content=context,
                )
                await pending.acquire()
                async with anyio.create_task_group() as group:

                    async def accept():
                        self.assertIsNone(await pending.accept_content())

                    group.start_soon(accept)
                    await started.wait()
                    pending.cancel()
                    release.set()
                self.assertEqual(pending.lifecycle.states, {})
                self.assertIsNone(pending.result)

        self.run_async(run)
