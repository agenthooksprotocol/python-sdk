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


def model_capabilities():
    return capability.HostCapabilities(
        tool_before=capabilities().tool_before,
        model_request_before=capability.ModelRequestBeforeCapabilities(observe=True),
        model_response_after=capability.ModelResponseAfterCapabilities(
            intercept=capability.ModelResponseAfterIntercept(message=True),
            observe=True,
        ),
    )


def subscription(events, mode):
    result = {"events": events, "mode": mode, "content": {"default": "metadata"}}
    if mode == "intercept":
        result.update(timeoutMs=1000, failurePolicy="fail-open")
    return result


def hooks_for(subscriptions, declarations):
    registration = config()
    registration["hooks"][0]["subscriptions"] = subscriptions
    return Hooks(
        registration,
        source="urn:test",
        harness=protocol_event.Harness(name="test-host", version="1"),
        capabilities=declarations,
    )


class InterceptInterestTests(unittest.TestCase):
    def test_intercept_only(self):
        for selector in ("tool.before", "tool.*", "*"):
            with self.subTest(selector=selector):
                hooks = hooks_for(
                    [subscription([selector], "intercept")], capabilities()
                )
                before = deepcopy((hooks.config, hooks.capabilities))
                with (
                    patch.object(
                        hooks, "_ensure_ready", side_effect=AssertionError("transport")
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
                        self.assertIs(hooks.intercepts("tool.before"), True)
                        self.assertIs(hooks.intercepts("tool.after"), False)
                        self.assertIs(hooks.intercepts("unknown.event"), False)
                        self.assertIs(hooks.intercepts(""), False)
                self.assertEqual((hooks.config, hooks.capabilities), before)

    def test_observe_only(self):
        for selector in ("tool.before", "tool.*", "*"):
            with self.subTest(selector=selector):
                hooks = hooks_for([subscription([selector], "observe")], capabilities())
                self.assertIs(hooks.subscribes("tool.before"), True)
                self.assertIs(hooks.intercepts("tool.before"), False)

    def test_intercept_and_observe(self):
        hooks = hooks_for(
            [
                subscription(["model.*"], "observe"),
                subscription(["model.response.after"], "intercept"),
            ],
            model_capabilities(),
        )
        self.assertIs(hooks.intercepts("model.response.after"), True)
        self.assertIs(hooks.subscribes("model.request.before"), True)
        self.assertIs(hooks.intercepts("model.request.before"), False)
        self.assertIs(hooks.intercepts("tool.before"), False)

    def test_prefix_selector(self):
        declarations = capability.HostCapabilities(
            model_response_after=model_capabilities().model_response_after
        )
        hooks = hooks_for([subscription(["model.*"], "intercept")], declarations)
        self.assertIs(hooks.intercepts("model.response.after"), True)
        self.assertIs(hooks.intercepts("model.request.before"), False)
        self.assertIs(hooks.intercepts("tool.before"), False)

    def test_event_without_intercept_grant(self):
        hooks = hooks_for(
            [
                subscription(["tool.before"], "intercept"),
                subscription(["model.request.before"], "observe"),
            ],
            model_capabilities(),
        )
        self.assertIs(hooks.intercepts("tool.before"), True)
        self.assertIs(hooks.subscribes("model.request.before"), True)
        self.assertIs(hooks.intercepts("model.request.before"), False)
