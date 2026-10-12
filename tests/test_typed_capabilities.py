"""The public host-authoring surface is typed, frozen, and serialization-free."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
import unittest
from unittest.mock import patch

from agenthooksprotocol import Hooks, capability
from agenthooksprotocol.runtime import Validator
from test_public_hooks import config


def tool_capabilities():
    return capability.HostCapabilities(
        tool_before=capability.ToolBeforeCapabilities(
            intercept=capability.ToolBeforeIntercept(
                deny=True,
                modify_input=capability.Modify.REPLACE_AND_MERGE,
                inject_context=capability.InjectContext(
                    deliver_at=(capability.Delivery.NEXT_TURN,)
                ),
            ),
            observe=True,
        )
    )


class TypedCapabilityTests(unittest.TestCase):
    def test_constructor_transfers_wire_containers_without_json_or_transport(self):
        declared = tool_capabilities()
        expected = declared.to_wire()
        # Schema loading is intentionally separate from capability transfer.
        validator = Validator()
        with (
            patch.object(validator, "validate", wraps=validator.validate) as validate,
            patch("agenthooksprotocol._hooks.Validator", return_value=validator),
            patch.object(json, "loads", side_effect=AssertionError("JSON hydration")),
            patch.object(
                Hooks, "_ensure_ready", side_effect=AssertionError("transport")
            ),
        ):
            hooks = Hooks(config(), source="urn:typed", capabilities=declared)
        self.assertEqual(
            [call.args[0] for call in validate.call_args_list], ["registration"]
        )
        self.assertEqual(hooks.capabilities, expected)
        hooks.capabilities["tool.before"]["capabilities"]["effects"].clear()
        self.assertEqual(declared.to_wire(), expected)

    def test_declarations_are_frozen_keyword_only_and_return_fresh_containers(self):
        declared = tool_capabilities()
        first = declared.to_wire()
        expected = deepcopy(first)
        first["tool.before"]["modes"].clear()
        first["tool.before"]["capabilities"]["modify"]["input"]["replace"] = False
        first["tool.before"]["capabilities"]["inject"]["context"]["deliverAt"].clear()
        self.assertEqual(declared.to_wire(), expected)
        with self.assertRaises(FrozenInstanceError):
            declared.tool_before = None
        with self.assertRaises(FrozenInstanceError):
            declared.tool_before.intercept.deny = False
        with self.assertRaises(TypeError):
            capability.ToolBeforeIntercept(True)
        with self.assertRaises(TypeError):
            capability.HostCapabilities(declared.tool_before)

    def test_observe_is_valid_for_both_phase_and_session_start_events(self):
        declared = capability.HostCapabilities(
            tool_before=capability.ToolBeforeCapabilities(observe=True),
            session_start=capability.SessionStartCapabilities(observe=True),
        )
        self.assertEqual(
            declared.to_wire(),
            {
                "tool.before": {"modes": ["observe"]},
                "session.start": {"modes": ["observe"]},
            },
        )
        hooks = Hooks(config(mode="observe"), source="urn:typed", capabilities=declared)
        self.assertEqual(hooks.capabilities, declared.to_wire())

    def test_observation_only_events_have_their_own_declaration_type(self):
        self.assertFalse(hasattr(capability, "Observe"))
        host = capability.HostCapabilities(
            session_end=capability.SessionEndCapabilities(observe=True),
            file_changed=capability.FileChangedCapabilities(observe=True),
        )
        self.assertEqual(
            host.to_wire(),
            {
                "file.changed": {"modes": ["observe"]},
                "session.end": {"modes": ["observe"]},
            },
        )
        for create in (
            lambda: capability.SessionEndCapabilities(),
            lambda: capability.SessionEndCapabilities(observe=False),
            lambda: capability.HostCapabilities(
                session_end=capability.FileChangedCapabilities(observe=True)
            ),
        ):
            with (
                self.subTest(create=create),
                self.assertRaises((TypeError, ValueError)),
            ):
                create()

    def test_elicitation_only_interception_is_a_real_grant(self):
        declared = capability.HostCapabilities(
            tool_before=capability.ToolBeforeCapabilities(
                intercept=capability.ToolBeforeIntercept(
                    elicitation=capability.Elicitation.FORM_AND_URL
                )
            )
        )
        self.assertEqual(
            declared.to_wire()["tool.before"],
            {
                "modes": ["intercept"],
                "capabilities": {"effects": [], "elicitation": {"form": {}, "url": {}}},
            },
        )
        Hooks(config(), source="urn:typed", capabilities=declared)

    def test_empty_interception_and_empty_declaration_are_rejected_immediately(self):
        for create in (
            lambda: capability.ToolBeforeIntercept(),
            lambda: capability.ToolBeforeIntercept(deny=False),
            lambda: capability.ToolBeforeCapabilities(),
        ):
            with self.subTest(create=create), self.assertRaises(ValueError):
                create()

    def test_wrong_fields_values_and_event_types_are_rejected_immediately(self):
        for create in (
            lambda: capability.ToolBeforeIntercept(
                modify_summary=capability.Modify.REPLACE
            ),
            lambda: capability.ToolBeforeIntercept(deny=1),
            lambda: capability.ToolBeforeCapabilities(observe="yes"),
            lambda: capability.ToolBeforeIntercept(modify_input="replace"),
            lambda: capability.ToolBeforeIntercept(elicitation="form"),
            lambda: capability.HostCapabilities(
                unknown_event=capability.ToolBeforeCapabilities(observe=True)
            ),
            lambda: capability.HostCapabilities(tool_before={"modes": ["observe"]}),
            lambda: capability.HostCapabilities(
                tool_before=capability.ToolAfterCapabilities(
                    intercept=capability.ToolAfterIntercept(message=True)
                )
            ),
            lambda: capability.ToolBeforeCapabilities(
                intercept=capability.ToolAfterIntercept(message=True)
            ),
            lambda: capability.ToolBeforeIntercept(
                flow=capability.FlowContinue(
                    remaining_continuations=1, continuation_count=0
                )
            ),
        ):
            with self.subTest(create=create), self.assertRaises(TypeError):
                create()

    def test_dictionary_constructor_has_no_compatibility_path(self):
        with self.assertRaises(TypeError):
            Hooks(
                config(), source="urn:typed", capabilities=tool_capabilities().to_wire()
            )
        with self.assertRaises(TypeError):
            Hooks(config(), source="urn:typed", capabilities={})
        with self.assertRaises(TypeError):
            Hooks(config(), source="urn:typed")
