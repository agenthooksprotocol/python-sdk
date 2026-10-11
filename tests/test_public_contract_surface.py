"""Public import and annotation gates; no SDK implementation imports required."""

import importlib.util
from pathlib import Path
from typing import get_type_hints
import unittest

import agenthooksprotocol as ahp
from agenthooksprotocol import codec
from agenthooksprotocol.integrations import pydantic


class PublicContractSurfaceTests(unittest.TestCase):
    def test_explicit_exports_exclude_implementation_helpers_and_dependencies(self):
        for module, expected in (
            (codec, {"Codec", "IdentityCodec", "ValueCodecs", "Candidate"}),
            (pydantic, {"PydanticCodec", "PydanticFormContract"}),
        ):
            namespace = {}
            exec("from " + module.__name__ + " import *", namespace)
            exported = {key for key in namespace if not key.startswith("_")}
            self.assertEqual(exported, expected)
            self.assertNotIn("decode_preserving", module.__all__)
            self.assertNotIn("TypeAdapter", module.__all__)
            self.assertNotIn("Validator", module.__all__)
        self.assertNotIn("FormResultCodec", pydantic.__all__)
        self.assertNotIn("decode_preserving", ahp.__all__)
        self.assertNotIn("FormResultCodec", ahp.__all__)

    def test_internal_helpers_are_not_public_module_attributes(self):
        from agenthooksprotocol import runtime, lifecycle, content
        from agenthooksprotocol.server import hooks

        for module, names in (
            (
                runtime,
                (
                    "response_effects",
                    "json_equal",
                    "apply_response",
                    "validate_intercept_response",
                ),
            ),
            (hooks, ("encode", "error")),
            (lifecycle, ("content_items", "dispatch_observations")),
        ):
            for name in names:
                self.assertFalse(hasattr(module, name), (module.__name__, name))
        for name in ("TypedCandidate", "AdmissionContracts", "OwnedAttachment"):
            self.assertFalse(hasattr(ahp, name), name)
        self.assertTrue(hasattr(runtime, "Validator"))
        self.assertTrue(hasattr(hooks, "Engine"))
        self.assertTrue(hasattr(content, "OwnedAttachment"))
        self.assertIs(
            ahp.Candidate,
            __import__("agenthooksprotocol.contract", fromlist=["Candidate"]).Candidate,
        )
        self.assertIs(ahp.wire.InterceptRequest, ahp.generated.InterceptRequest)

    def test_new_public_type_hints_resolve_without_injected_names(self):
        for method in (
            ahp.Hooks.dispatch,
            ahp.HookResult.decoded_input.fget,
            ahp.HookResult.decoded_candidate.fget,
            pydantic.PydanticFormContract.request,
            pydantic.PydanticFormContract.result_codec,
            pydantic.PydanticFormContract.decode_result,
        ):
            with self.subTest(method=method.__qualname__):
                self.assertTrue(get_type_hints(method))

    def test_generated_named_boundary_type_hints_resolve(self):
        self.assertTrue(get_type_hints(ahp.Hooks.tool_before))

    def test_public_consumer_example_imports(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "value_codecs.py"
        spec = importlib.util.spec_from_file_location(
            "declared_contract_consumer", path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            module.form_request["requestedSchema"]["properties"]["approved"]["type"],
            "boolean",
        )
        self.assertTrue(get_type_hints(module.intercept_tool))
