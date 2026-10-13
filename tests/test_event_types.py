"""One catalogue-derived event identifier across the public SDK."""

from agenthooksprotocol import event as protocol_event
from typing import get_args, get_overloads, get_type_hints
import unittest
from unittest.mock import patch

from agenthooksprotocol import EventType, Hooks
from agenthooksprotocol.event import EventType as EventModuleType
from agenthooksprotocol._interop_hooks import _hooks_for_wire
from agenthooksprotocol.runtime import ProtocolError
from test_public_hooks import config
from typecheck_event_types import main


class EventTypeTests(unittest.TestCase):
    def test_public_annotations_share_the_generated_event_type(self):
        self.assertIs(EventType, EventModuleType)
        self.assertEqual(len(get_args(EventType)), 32)
        self.assertIs(get_type_hints(Hooks.subscribes)["event"], EventType)
        methods = get_overloads(Hooks.dispatch) + [Hooks.dispatch]
        self.assertEqual(len(methods), 9)
        for method in methods:
            self.assertIs(get_type_hints(method)["event_name"], EventType)

    def test_private_external_wire_boundary_checks_names_before_narrowing(self):
        with patch.object(
            Hooks, "_configure", side_effect=AssertionError("unchecked event")
        ):
            with self.assertRaisesRegex(
                ProtocolError, "Unknown canonical fixture event"
            ):
                _hooks_for_wire(
                    config(),
                    source="urn:test",
                    harness=protocol_event.Harness(name="test-host", version="1"),
                    declarations={"unknown.event": {"modes": ["observe"]}},
                    transport=None,
                )

    def test_external_static_consumers(self):
        main()
