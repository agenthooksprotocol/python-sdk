"""Exported wire constructors share structural validation with Parse."""

import unittest
import json
from pathlib import Path

import agenthooksprotocol as ahp
from decimal import Decimal

from agenthooksprotocol import ContentReference, ContentUploadReceipt, ExecutionEventMcpConnectionHttp
from agenthooksprotocol import capability, effect, state
from agenthooksprotocol.generated import parse_content_reference


class StructuralFacadeTests(unittest.TestCase):
    def test_from_dict_hydrates_nested_models(self):
        raw = {"transport": "http", "gaps": [{"path": "url", "reason": "unavailable"}]}
        decoded = ExecutionEventMcpConnectionHttp.from_dict(raw)
        self.assertEqual(decoded.gaps[0].reason, "unavailable")
        self.assertEqual(decoded.gaps[0].path, "url")
        self.assertEqual(decoded, raw)
        caps = capability.Capabilities.from_dict({"effects": ["modify"], "modify": {"input": {"replace": True, "merge": False}}})
        self.assertTrue(caps.modify.input.replace)

    def test_family_support_is_not_authorization(self):
        self.assertIs(capability.EffectName, effect.EffectName)
        for cls in (capability.Capabilities, capability.InterceptRequestParamsCapabilities):
            caps = cls.from_dict({
                "effects": ["deny", "vendor.custom"],
                "modify": {"input": {"replace": True, "merge": False}},
            })
            self.assertTrue(caps.supports(capability.EffectName.DENY))
            self.assertTrue(caps.supports("vendor.custom"))
            self.assertFalse(caps.supports(capability.EffectName.MODIFY))
            self.assertFalse(cls(effects=[]).supports(capability.EffectName.DENY))

    def test_candidate_presence(self):
        for candidate in (None, {"value": None}, {"value": 0}):
            raw = {"permission": "allow", "candidate": candidate}
            self.assertEqual(state.State.from_dict(raw), raw)
        for raw in ({"permission": "allow"}, {"permission": "allow", "candidate": {}}):
            with self.assertRaises(ValueError):
                state.State.from_dict(raw)
        with self.assertRaises(ValueError):
            state.State(permission=42, candidate=None)

    def test_constructor_literals_and_required_wire_fields(self):
        with self.assertRaises(ValueError):
            effect.Deny(reason="blocked", type="allow")
        with self.assertRaises(ValueError):
            effect.Deny.from_dict({"reason": "blocked"})
        with self.assertRaises(ValueError):
            ContentUploadReceipt(ref="opaque", size="invalid", sha256="a" * 64)

    def test_diagnostics_extensions_and_exact_numbers(self):
        value = {"ref": "opaque", "extension": Decimal("1.000000000000000000001")}
        decoded = ContentReference.from_dict(value)
        self.assertEqual(decoded, value)
        self.assertEqual(parse_content_reference(decoded), parse_content_reference(value))
        for bad in ({"ref": "opaque", "size": None}, {"ref": 7}):
            with self.assertRaises(ValueError) as raised:
                ContentReference.from_dict(bad)
            self.assertEqual(raised.exception.result, parse_content_reference(bad))
        for bad_number in (float("nan"), float("inf"), Decimal("NaN")):
            with self.assertRaises(ValueError):
                ContentReference(ref="opaque", future=bad_number)


class SharedStructuralMatrixTests(unittest.TestCase):
    def test_public_models_and_parsers_match_expected_contract(self):
        cases = json.loads(Path(__file__).with_name("structural-acceptance.json").read_text())["cases"]
        for entry in cases:
            with self.subTest(entry["id"]):
                model_name = "".join(word.title() for word in entry["root"].split("_"))
                model = getattr(ahp, model_name)
                parse = getattr(ahp.generated, "parse_" + entry["root"])
                parsed = parse(entry["value"])
                self.assertEqual(parsed["ok"], entry["accepted"])
                self.assertEqual(any(d["severity"] == "warning" for d in parsed["diagnostics"]), entry["warning"])
                self.assertEqual(parsed["raw"], entry["value"])
                if entry["accepted"]:
                    decoded = model.from_dict(entry["value"])
                    self.assertEqual(decoded, entry["value"])
                    self.assertEqual(parsed["value"], decoded)
                else:
                    with self.assertRaises(ValueError):
                        model.from_dict(entry["value"])
