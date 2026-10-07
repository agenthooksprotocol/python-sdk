"""Regression coverage for integration-discovered protocol boundaries."""

from copy import deepcopy
import json
import hashlib
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
import unittest
from unittest.mock import Mock, patch

from agenthooksprotocol.elicitation import apply_effects, validate_exchange
from agenthooksprotocol.lifecycle_client import Transport
from agenthooksprotocol.lifecycle_server import Server, MALICIOUS
from agenthooksprotocol.runtime import Validator, ProtocolError


class IntegrationEdgeTests(unittest.TestCase):
    def exchange(self):
        request_body = {
            "mode": "form",
            "message": "Answer",
            "requestedSchema": {"type": "object", "properties": {}},
        }
        result_body = {"action": "accept", "content": {}}
        bodies = {}
        envelopes = []
        for stage, body in (("request", request_body), ("result", result_body)):
            ident = "elicitation:" + stage
            raw = json.dumps(body).encode()
            reference = {
                "ref": "urn:" + ident,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            bodies[reference["ref"]] = raw
            meta = {
                "mode": "form",
                "server": "example",
                stage: {
                    "id": ident + ":item",
                    "kind": "elicitation." + stage,
                    "mediaType": "application/json",
                    "selection": "body",
                    "body": reference,
                },
            }
            event = {
                "id": ident,
                "source": "urn:test",
                "time": "2026-01-01T00:00:00Z",
                "type": "user.elicitation." + stage,
                "session": {"id": "session"},
                "elicitation": meta,
            }
            if stage == "result":
                event["parentEventId"] = "elicitation:request"
                meta["action"] = "accept"
            envelopes.append(
                {
                    "jsonrpc": "2.0",
                    "id": ident,
                    "method": "hooks/intercept",
                    "params": {
                        "protocolVersion": "draft",
                        "event": event,
                        "capabilities": {
                            "effects": ["return", "deny"]
                            if stage == "request"
                            else ["modify"],
                            "elicitation": {"form": {}},
                            "modify": {"content": {"replace": True, "merge": False}},
                        },
                    },
                }
            )
        envelopes[0]["params"]["capabilities"].pop("modify")
        return *envelopes, lambda ref: bodies[ref["ref"]]

    def test_effects_require_explicit_boundary_mode(self):
        directory = (
            Path(__file__).resolve().parents[2] / "agent-hooks-protocol/schema/draft"
        )
        schemas = {
            p.stem.removesuffix(".schema"): json.loads(p.read_text())
            for p in directory.glob("*.schema.json")
        }
        registry = Registry().with_resources(
            (s["$id"], Resource.from_contents(s)) for s in schemas.values()
        )

        def validate(name, value):
            if name == "form-answer":
                Draft202012Validator(
                    value["schema"], format_checker=FormatChecker()
                ).validate(value["value"])
                return
            name, _, fragment = name.partition("#")
            schema = (
                schemas[name]
                if not fragment
                else {"$ref": schemas[name]["$id"] + "#/$defs/" + fragment}
            )
            Draft202012Validator(
                schema, registry=registry, format_checker=FormatChecker()
            ).validate(value)

        for phase, effect in (
            ("request", {"type": "return", "value": {"action": "decline"}}),
            ("request", {"type": "deny", "reason": "policy"}),
            (
                "result",
                {
                    "type": "modify",
                    "target": "content",
                    "operation": "replace",
                    "value": {},
                },
            ),
        ):
            for grant in (None, {}, {"url": {}}, {"form": {}}):
                with self.subTest(phase=phase, effect=effect["type"], grant=grant):
                    request, result, resolve = self.exchange()
                    caps = (request if phase == "request" else result)["params"][
                        "capabilities"
                    ]
                    caps.pop("elicitation")
                    if grant is not None:
                        caps["elicitation"] = grant
                    original = deepcopy((request, result))

                    def apply():
                        return apply_effects(
                            request,
                            None if phase == "request" else result,
                            resolve,
                            validate,
                            "hook",
                            [effect],
                        )

                    if grant == {"form": {}}:
                        apply()
                    else:
                        with self.assertRaisesRegex(ValueError, "mode not registered"):
                            apply()
                        with self.assertRaisesRegex(ValueError, "mode not registered"):
                            validate_exchange(
                                request, result, resolve, validate, "hook", effect
                            )
                    self.assertEqual((request, result), original)

    def test_http_notifications_accept_204_and_diagnose_effects(self):
        transport = Transport.__new__(Transport)
        transport.process = None
        transport.references = {}
        transport.config = {"endpoint": "http://localhost/intercept"}
        transport.headers = {}
        transport.context = None
        transport.pool = Mock()
        transport.confirmed = Mock()
        notification = {"jsonrpc": "2.0", "method": "hooks/observe", "params": {}}
        try:
            for method in (transport.notify, transport.observe):
                with patch(
                    "agenthooksprotocol.lifecycle_client.http", return_value=(204, None)
                ):
                    self.assertIsNone(method(notification))
                # The transport reports an illicit acknowledgement. Hooks.notify
                # contains this as a diagnostic, never as effects or a rollback.
                with patch(
                    "agenthooksprotocol.lifecycle_client.http",
                    return_value=(200, MALICIOUS),
                ):
                    with self.assertRaisesRegex(ProtocolError, "acknowledgement"):
                        method(notification)
                with patch(
                    "agenthooksprotocol.lifecycle_client.http",
                    return_value=(500, None),
                ):
                    with self.assertRaises(ProtocolError):
                        method(notification)
        finally:
            transport.close()

    def test_only_named_malicious_observer_responds(self):
        server = Server.__new__(Server)
        server.config = {}
        server.content = Mock()
        server.lineage = Mock()
        server.event_scope = "test"
        server.sequences = {}
        server.record = Mock()
        server.validator = Validator()
        server.malicious_observers = {"settled-observer-effects-ignored:a"}
        for ident in (
            "ordinary",
            "observation-chain-deny",
            "settled-observer-effects-ignored:a",
        ):
            from test_interop import request as tool_request

            event = tool_request()["params"]["event"]
            event["id"] = ident
            note = {
                "jsonrpc": "2.0",
                "method": "hooks/observe",
                "params": {"protocolVersion": "draft", "event": event},
            }
            self.assertEqual(
                server.protocol(note),
                MALICIOUS if ident in server.malicious_observers else None,
            )
