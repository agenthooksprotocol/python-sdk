"""Public content-bound settlement on asyncio and Trio, including negative cases."""

from copy import deepcopy
import json
import unittest
from uuid import uuid4

from jsonschema.exceptions import ValidationError

import anyio

from agenthooksprotocol import Hooks
from agenthooksprotocol._content import ContentContext


def text_parts(value):
    return [
        {
            "id": str(uuid4()),
            "kind": "text",
            "mediaType": "text/plain",
            "selection": "body",
            "text": value,
        }
    ]


class Store:
    """Inline fixture factory; callbacks must never be needed for text."""

    def __init__(self):
        self.reads = []
        self.writes = []

    def add(self, value, media="application/json", role=None):
        item = text_parts(value if isinstance(value, str) else json.dumps(value))[0]
        if role is not None:
            item["role"] = role
        return item

    async def resolve(self, reference):
        self.reads.append(deepcopy(reference))
        raise AssertionError("Inline text must not resolve storage")

    async def upload(self, data):
        self.writes.append(data)
        raise AssertionError("Inline text must not upload storage")


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
    if target in ("instructions", "summary") and isinstance(value, str):
        value = text_parts(value)
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
                    self.assertEqual(store.reads, [])
                else:
                    self.assertEqual(settled.diagnostics, [])
                    self.assertEqual(settled.state["messages"], ["audit"])
                    self.assertEqual(len(settled.accepted_responses), 1)
                    self.assertEqual(store.writes, [])
                    self.assertEqual(store.reads, [])

        self.run_async(run)

    def test_elicitation_result_uses_original_snapshot_and_new_inline_text(self):
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
            part = settled.event["elicitation"]["result"]
            self.assertEqual(part["kind"], "text")
            self.assertNotIn("body", part)
            self.assertEqual(json.loads(part["text"])["content"], {"ok": True})
            self.assertEqual(
                result["params"]["event"]["elicitation"]["result"]["text"],
                json.dumps({"action": "accept", "content": {"ok": False}}),
            )
            self.assertEqual(store.writes, [])
            self.assertEqual(store.reads, [])
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
                self.assertEqual(store.writes, [])
                self.assertEqual(store.reads, [])
                if valid:
                    self.assertEqual(settled.candidate["value"], answer)
                    self.assertNotIn("content_references", settled.state)
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
                self.assertNotIn("text", view)
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
                "instructions": text_parts("old"),
            }
            caps = {
                "effects": ["modify", "return", "deny", "message"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            transport = Replies(
                [{"type": "return", "value": text_parts("supplied")}],
                [modify("instructions", "new")],
                [],
            )
            async with hooks_for(
                "context.compact.before", caps, transport, count=3
            ) as hooks:
                settled = await hooks.context_compact_before(payload)
            self.assertEqual(settled.diagnostics, [])
            self.assertIsNone(settled.candidate)
            self.assertEqual(settled.event["instructions"][0]["text"], "new")
            self.assertEqual(store.reads, [])
            self.assertEqual(store.writes, [])
            self.assertEqual(
                transport.requests[2]["params"]["event"]["instructions"],
                settled.event["instructions"],
            )

        self.run_async(run)

    def test_compaction_after_replaces_text_not_descriptor_or_primary_input(self):
        async def run():
            store = Store()
            payload = {
                "summary": text_parts("generated"),
                "removed": [],
                "execution": {"status": "executed"},
            }
            caps = {
                "effects": ["modify", "message"],
                "modify": {"summary": {"replace": True, "merge": False}},
            }
            async with hooks_for(
                "context.compact.after", caps, Replies([modify("summary", "redacted")])
            ) as hooks:
                settled = await hooks.context_compact_after(payload)
            self.assertEqual(settled.diagnostics, [])
            self.assertEqual(settled.event["summary"][0]["text"], "redacted")
            self.assertEqual(settled.input, {})
            self.assertEqual(store.reads, [])
            self.assertEqual(store.writes, [])

        self.run_async(run)

    def test_atomic_invalid_batch_and_unused_upload_publish_inline_only(self):
        async def run():
            for failure in ("invalid", "unused-upload"):
                store = Store()
                request, _ = elicitation(store)
                caps = request["params"]["capabilities"]
                caps["effects"].append("message")
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings={"request": ("elicitation", "request")},
                    principal="hook",
                )
                answer = {
                    "action": "accept",
                    "content": {} if failure == "invalid" else {"ok": True},
                }
                effects = [
                    {"type": "message", "text": "audit"},
                    {"type": "return", "value": answer},
                ]
                async with hooks_for(
                    "user.elicitation.request", caps, Replies(effects)
                ) as hooks:
                    pending = hooks.begin(request, content=context)
                    await pending.acquire()
                    if failure == "invalid":
                        with self.assertRaises(ValidationError):
                            await pending.accept_content()
                        self.assertEqual(pending.lifecycle.states, {})
                        self.assertIsNone(pending.result)
                    else:
                        settled = await pending.accept_content()
                        self.assertEqual(settled.candidate["value"], answer)
                        self.assertEqual(settled.state["messages"], ["audit"])
                self.assertEqual(store.reads, [])
                self.assertEqual(store.writes, [])

        self.run_async(run)

    def test_prepared_inline_content_has_immutable_request_without_snapshot_owners(
        self,
    ):
        from agenthooksprotocol._content import PreparedContent
        from agenthooksprotocol.runtime import Validator

        async def run():
            store = Store()
            request, _ = elicitation(store)
            context = ContentContext(
                bindings={"request": ("elicitation", "request")}, principal="hook"
            )
            prepared = PreparedContent(context, request, Validator())
            original = deepcopy(request)
            request["params"]["event"]["elicitation"]["request"]["text"] = "changed"
            await prepared.load()
            self.assertEqual(prepared.request, original)
            self.assertFalse(hasattr(prepared, "_read"))
            self.assertFalse(hasattr(prepared, "owners"))
            self.assertEqual(store.reads, [])
            self.assertEqual(store.writes, [])

        self.run_async(run)

    def test_invalid_inline_json_and_unselected_text_fail_closed(self):
        async def run():
            for failure in (
                "invalid-json",
                "duplicate-key",
                "nonfinite",
                "metadata",
                "omit",
            ):
                store = Store()
                request, _ = elicitation(store)
                part = request["params"]["event"]["elicitation"]["request"]
                if failure == "invalid-json":
                    part["text"] = "not JSON"
                elif failure == "duplicate-key":
                    part["text"] = '{"mode":"form","mode":"url"}'
                elif failure == "nonfinite":
                    part["text"] = '{"mode":"form","message":NaN}'
                context = ContentContext(
                    resolve=store.resolve,
                    upload=store.upload,
                    bindings={"request": ("elicitation", "request")},
                    principal="hook",
                )
                caps = request["params"]["capabilities"]
                effects = [
                    {
                        "type": "return",
                        "value": {"action": "accept", "content": {"ok": True}},
                    }
                ]
                async with hooks_for(
                    "user.elicitation.request",
                    caps,
                    Replies(effects),
                    selection=failure if failure in ("metadata", "omit") else "body",
                ) as hooks:
                    result = await hooks.user_elicitation_request(
                        request["params"]["event"], content=context
                    )
                self.assertEqual(result.decision, "deny")
                self.assertEqual(result.accepted_responses, [])
                self.assertEqual(result.event["elicitation"]["request"], part)
                self.assertEqual(store.reads, [])
                self.assertEqual(store.writes, [])

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
                self.assertEqual(store.reads, [])

        self.run_async(run)

    def test_same_response_modification_then_supply_binds_candidate_to_final_text(self):
        async def run():
            store = Store()
            payload = {
                "trigger": "manual",
                "items": [],
                "instructions": text_parts("old"),
            }
            caps = {
                "effects": ["modify", "return"],
                "modify": {"instructions": {"replace": True, "merge": False}},
            }
            transport = Replies(
                [
                    {"type": "return", "value": text_parts("summary-for-final")},
                    modify("instructions", "final"),
                ],
                [],
            )
            async with hooks_for(
                "context.compact.before", caps, transport, count=2
            ) as hooks:
                result = await hooks.context_compact_before(payload)
            self.assertEqual(result.diagnostics, [])
            self.assertEqual(result.candidate["value"][0]["text"], "summary-for-final")
            self.assertEqual(result.event["instructions"][0]["text"], "final")
            self.assertEqual(store.reads, [])
            self.assertEqual(store.writes, [])

        self.run_async(run)

    def test_reasoning_selection_cannot_be_overridden_by_category(self):
        from agenthooksprotocol._content import project_content

        item = {
            "id": "reasoning",
            "kind": "text",
            "category": "reasoning",
            "mediaType": "text/plain",
            "selection": "body",
            "text": "private",
        }
        projected = project_content(item, {"default": "body", "reasoning": "omit"})
        self.assertEqual(projected["selection"], "omit")
        self.assertNotIn("text", projected)
        self.assertEqual(item["text"], "private")

    def test_normal_result_boundary_accepts_canonical_original_request_snapshot(self):
        async def run():
            store = Store()
            request, result = elicitation(store)
            caps = result["params"]["capabilities"]
            async with hooks_for(
                "user.elicitation.result",
                caps,
                Replies([modify("content", {"ok": True})]),
            ) as hooks:
                settled = await hooks.user_elicitation_result(
                    result["params"]["event"],
                    original_request=request,
                )
            self.assertEqual(settled.diagnostics, [])
            self.assertEqual(
                json.loads(settled.event["elicitation"]["result"]["text"]),
                {"action": "accept", "content": {"ok": True}},
            )
            self.assertEqual(store.reads, [])
            self.assertEqual(store.writes, [])

        self.run_async(run)

    def test_cancel_during_inline_finalization_cannot_commit(self):
        from unittest.mock import patch
        from agenthooksprotocol._content import PreparedContent

        async def run():
            store = Store()
            request, _ = elicitation(store)
            context = ContentContext(
                resolve=store.resolve,
                upload=store.upload,
                bindings={"request": ("elicitation", "request")},
                principal="hook",
            )
            effects = [
                {
                    "type": "return",
                    "value": {"action": "accept", "content": {"ok": True}},
                }
            ]
            started, release = anyio.Event(), anyio.Event()
            finalize = PreparedContent.finalize

            async def held(prepared, state):
                started.set()
                await release.wait()
                return await finalize(prepared, state)

            async with hooks_for(
                "user.elicitation.request",
                request["params"]["capabilities"],
                Replies(effects),
            ) as hooks:
                pending = hooks.begin(request, content=context)
                await pending.acquire()
                with patch.object(PreparedContent, "finalize", held):
                    async with anyio.create_task_group() as group:

                        async def accept():
                            self.assertIsNone(await pending.accept_content())

                        group.start_soon(accept)
                        await started.wait()
                        pending.cancel()
                        release.set()
                self.assertEqual(pending.lifecycle.states, {})
                self.assertIsNone(pending.result)
                self.assertEqual(store.reads, [])
                self.assertEqual(store.writes, [])

        self.run_async(run)
