"""Ref-only wire content, verified upload receipts, and shared Event consumers."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import get_type_hints
import unittest

from agenthooksprotocol import _models as models, generated
from agenthooksprotocol.content import reference
from agenthooksprotocol.runtime import ProtocolError, Validator
from test_interop import request


def event_identity(event: models.Event) -> tuple[str, str]:
    """One consumer for actual intercept and observation request events."""
    return event["id"], event["type"]


class ContentReceiptTests(unittest.TestCase):
    def setUp(self):
        self.validator = Validator()
        self.receipt = {
            "ref": "urn:stored:one",
            "size": 3,
            "sha256": hashlib.sha256(b"abc").hexdigest(),
        }
        self.item = {
            "id": "one",
            "kind": "text",
            "mediaType": "text/plain",
            "selection": "body",
            "body": {"ref": self.receipt["ref"]},
        }

    def test_receipt_is_confirmation_not_event_reference(self):
        self.validator.validate("content-upload-receipt", self.receipt)
        self.assertEqual(reference(self.receipt), self.item["body"])
        self.assertEqual(set(self.receipt), {"ref", "size", "sha256"})
        self.validator.validate("content-reference", self.item["body"])
        self.assertTrue(generated.parse_content_reference(self.item["body"])["ok"])
        for key, metadata in (
            (key, value)
            for key in ("size", "sha256")
            for value in (self.receipt[key], None)
        ):
            invalid = {**self.item["body"], key: metadata}
            with self.subTest(key=key, metadata=metadata):
                with self.assertRaises(ProtocolError):
                    self.validator.validate("content-reference", invalid)
                self.assertFalse(generated.parse_content_reference(invalid)["ok"])
        with self.assertRaises(ProtocolError):
            reference(self.item["body"])

    def test_body_metadata_rejected_at_structural_and_canonical_boundaries(self):
        self.validator.validate("content-item", self.item)
        for key, metadata in (
            (key, value)
            for key in ("size", "sha256")
            for value in (self.receipt[key], None)
        ):
            invalid = {**self.item, key: metadata}
            with self.subTest(key=key, metadata=metadata):
                with self.assertRaises(ProtocolError):
                    self.validator.validate("content-item", invalid)
                self.assertFalse(generated.parse_content_item(invalid)["ok"])
                req = request()
                req["params"]["event"]["items"] = [invalid]
                note = {
                    "jsonrpc": "2.0",
                    "method": "hooks/observe",
                    "params": {
                        "protocolVersion": "draft",
                        "event": deepcopy(req["params"]["event"]),
                    },
                }
                for kind, value, parse in (
                    ("intercept-request", req, generated.parse_intercept_request),
                    (
                        "observe-notification",
                        note,
                        generated.parse_observe_notification,
                    ),
                ):
                    with self.assertRaises(ProtocolError):
                        self.validator.validate(kind, value)
                    self.assertFalse(parse(value)["ok"])

    def test_metadata_selection_retains_disclosure(self):
        item = {key: value for key, value in self.item.items() if key != "body"}
        item.update(selection="metadata", size=3, sha256=self.receipt["sha256"])
        self.validator.validate("content-item", item)
        self.assertTrue(generated.parse_content_item(item)["ok"])

    def test_actual_requests_expose_the_same_shared_event(self):
        req = request()
        intercept = models.InterceptRequest(
            id=req["id"],
            params=models.InterceptRequestParams(
                protocol_version="draft",
                capabilities=req["params"]["capabilities"],
                event=req["params"]["event"],
            ),
        )
        observation = models.ObserveNotification(
            params=models.ObserveNotificationParams(
                protocol_version="draft",
                event=intercept.params.event,
            ),
        )
        for kind, envelope, parse in (
            ("intercept-request", intercept, generated.parse_intercept_request),
            ("observe-notification", observation, generated.parse_observe_notification),
        ):
            self.validator.validate(kind, envelope)
            self.assertTrue(parse(envelope)["ok"])
            self.assertEqual(
                event_identity(envelope.params.event),
                (req["params"]["event"]["id"], "tool.before"),
            )
        for params in (models.InterceptRequestParams, models.ObserveNotificationParams):
            self.assertIs(get_type_hints(params.__init__)["event"], models.Event)

    def test_shared_event_does_not_widen_intercept_known_event_subset(self):
        event = models.SessionEndEvent(
            id="ended",
            source="urn:test",
            time="2026-01-01T00:00:00Z",
            session=models.Session(id="session"),
            outcome="completed",
            reason="done",
        )
        note = models.ObserveNotification(
            params=models.ObserveNotificationParams(
                protocol_version="draft",
                event=event,
            )
        )
        self.validator.validate("observe-notification", note)
        self.assertTrue(generated.parse_observe_notification(note)["ok"])
        self.assertEqual(event_identity(note.params.event), ("ended", "session.end"))
        with self.assertRaises(ValueError):
            models.InterceptRequestParams(
                protocol_version="draft", capabilities={"effects": []}, event=event,
            )
        # Native dictionary construction is outside the SDK decode contract;
        # parsing must still reject this malformed known event subset.
        req = {
            "jsonrpc": "2.0", "id": "ended", "method": "hooks/intercept",
            "params": {"protocolVersion": "draft", "capabilities": {"effects": []}, "event": event},
        }
        with self.assertRaises(ProtocolError):
            self.validator.validate("intercept-request", req)
        self.assertFalse(generated.parse_intercept_request(req)["ok"])
