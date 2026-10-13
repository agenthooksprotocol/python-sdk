"""External public consumer coverage for synchronous static interest."""

from agenthooksprotocol import event as protocol_event
from agenthooksprotocol import capability

from copy import deepcopy
import unittest
from unittest.mock import patch

from agenthooksprotocol import Hooks
from test_public_hooks import capabilities, config


class SubscriptionInterestTests(unittest.TestCase):
    def test_static_interest(self):
        for mode in ("intercept", "observe"):
            for selector in ("tool.before", "tool.*", "*"):
                for filtered in (False, True):
                    with self.subTest(mode=mode, selector=selector, filtered=filtered):
                        registration = config(mode=mode)
                        subscription = registration["hooks"][0]["subscriptions"][0]
                        subscription["events"] = [selector]
                        if filtered:
                            subscription["filters"] = {
                                "toolKinds": ["shell"],
                                "paths": ["not-the-path"],
                            }
                        hooks = Hooks(
                            registration,
                            source="urn:test",
                            harness=protocol_event.Harness(
                                name="test-host", version="1"
                            ),
                            capabilities=capabilities(),
                        )
                        before = deepcopy((hooks.config, hooks.capabilities))
                        with (
                            patch.object(
                                hooks,
                                "_ensure_ready",
                                side_effect=AssertionError("transport"),
                            ),
                            patch.object(
                                hooks,
                                "_project_delivery",
                                side_effect=AssertionError("input preparation"),
                            ),
                            patch.object(
                                hooks.validator,
                                "validate",
                                side_effect=AssertionError("input validation"),
                            ),
                        ):
                            for _ in range(2):
                                self.assertIs(hooks.subscribes("tool.before"), True)
                                self.assertIs(hooks.subscribes("tool.after"), False)
                                self.assertIs(hooks.subscribes("unknown.event"), False)
                                self.assertIs(hooks.subscribes(""), False)
                        self.assertEqual((hooks.config, hooks.capabilities), before)

    def test_no_subscribers_and_unrelated_selectors(self):
        declarations = capability.HostCapabilities(
            tool_before=capabilities().tool_before,
            tool_after=capability.ToolAfterCapabilities(observe=True),
        )
        registration = config(mode="observe")
        registration["hooks"][0]["subscriptions"][0]["events"] = ["tool.after"]
        hooks = Hooks(
            registration,
            source="urn:test",
            harness=protocol_event.Harness(name="test-host", version="1"),
            capabilities=declarations,
        )
        self.assertIs(hooks.subscribes("tool.before"), False)
        self.assertIs(hooks.subscribes("tool.after"), True)
        self.assertIs(hooks.subscribes("unknown.event"), False)
