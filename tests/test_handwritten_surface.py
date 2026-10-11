"""Handwritten public APIs must not retain compatibility-only adapters."""

import inspect
import unittest

from agenthooksprotocol import HookResult, Hooks, content
import agenthooksprotocol as ahp
from agenthooksprotocol.server import asgi


class HandwrittenSurfaceTests(unittest.TestCase):
    def test_consumer_outcomes_have_one_authoritative_typed_surface(self):
        removed = (
            "state",
            "effective_input",
            "raw_event",
            "settled_event",
            "raw_candidate",
            "schema_candidate",
            "decoded_input",
            "decoded_candidate",
            "decoded_result",
            "accepted_response",
            "raw_accepted_response",
            "raw_accepted_responses",
            "decoded_accepted_responses",
            "decode_input",
            "decode_content",
            "content",
            "content_references",
        )
        for name in removed:
            with self.subTest(name=name):
                self.assertFalse(hasattr(HookResult, name))
                self.assertNotIn(name, inspect.signature(HookResult).parameters)
        self.assertFalse(hasattr(Hooks, "wait"))
        self.assertNotIn("SchemaCandidate", ahp.__all__)
        self.assertFalse(hasattr(ahp, "SchemaCandidate"))
        self.assertEqual(ahp.wire.__name__, "agenthooksprotocol.wire")

    def test_generated_compatibility_names_are_absent(self):
        from agenthooksprotocol import effect, diagnostics
        from agenthooksprotocol._models import content as content_models

        for name in (
            "modify_summary",
            "modify_instructions",
            "flow_continue",
            "inject_context_append",
            "modify_request",
            "modify_response",
            "modify_content",
            "modify",
            "return_",
            "flow_stop",
            "modify_output",
            "modify_prompt",
            "deny",
            "allow",
            "ask",
            "message",
            "return_tool",
            "return_messages",
            "return_text",
            "return_elicit_result",
            "continue_flow",
            "stop_flow",
            "inject",
            "Return",
        ):
            with self.subTest(module="effect", name=name):
                self.assertFalse(hasattr(effect, name))
        self.assertFalse(hasattr(diagnostics, "DiagnosticCode"))
        for name in ("Receipt", "UploadReceipt", "Reference", "Selection", "Upload"):
            with self.subTest(module="content_models", name=name):
                self.assertFalse(hasattr(content_models, name))
        self.assertFalse(hasattr(content.ContentSources, "edit_context"))

    def test_content_has_no_synchronous_fixture_transport_api(self):
        for name in ("upload", "receive", "NoRedirect"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(content, name))

    def test_asgi_has_one_constructor(self):
        self.assertTrue(callable(asgi.App))
        self.assertFalse(hasattr(asgi, "app"))

    def test_inline_context_rejects_unused_binary_adapters(self):
        parameters = inspect.signature(content.ContentContext).parameters
        for name in ("resolve", "upload", "attachments"):
            with self.subTest(name=name):
                self.assertNotIn(name, parameters)
                with self.assertRaises(TypeError):
                    content.ContentContext(
                        bindings={"request": ("elicitation", "request")},
                        principal="org.example.hook",
                        **{name: None},
                    )


if __name__ == "__main__":
    unittest.main()
