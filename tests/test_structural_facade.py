"""Exported wire constructors share structural validation with Parse."""

import unittest
import typing
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

    def test_all_generated_effect_array_queries_are_sound(self):
        families, payloads = set(), set()
        for name in ahp._models.__all__:
            cls = getattr(ahp._models, name)
            if isinstance(cls, type) and issubclass(cls, dict) and isinstance(getattr(cls, "effects", None), property):
                annotation = typing.get_type_hints(cls.effects.fget)["return"]
                (families if annotation == list[str] else payloads).add(cls)
        self.assertGreaterEqual(len(families), 21)
        self.assertTrue(payloads)
        self.assertTrue(all(hasattr(cls, "supports") for cls in families))
        self.assertTrue(all(not hasattr(cls, "supports") for cls in payloads))

    def test_all_exported_capability_models_support_family_queries(self):
        classes = {value for value in vars(capability).values()
                   if isinstance(value, type) and issubclass(value, dict) and hasattr(value, "effects")}
        self.assertGreaterEqual(len(classes), 20)
        for cls in classes:
            with self.subTest(cls.__name__):
                for caps in (cls(effects=["deny", "vendor.custom"]),
                             cls.from_dict({"effects": ["deny", "vendor.custom"]})):
                    self.assertTrue(caps.supports(capability.EffectName.DENY))
                    self.assertTrue(caps.supports("vendor.custom"))
                    self.assertFalse(caps.supports(capability.EffectName.MODIFY))
                self.assertFalse(cls(effects=[]).supports(capability.EffectName.DENY))
        self.assertTrue(capability.ToolBeforeCapabilities(effects=["deny"]).supports(capability.EffectName.DENY))
        self.assertFalse(hasattr(ahp.InterceptDenyResponseResult, "supports"))

    def test_constructors_hydrate_nested_mapping_values(self):
        caps = capability.Capabilities(effects=["modify"], modify={})
        self.assertIsNone(caps.modify.input)
        self.assertIsInstance(caps.modify, ahp.CapabilitiesModify)
        connection = ExecutionEventMcpConnectionHttp(
            transport="http", gaps=[{"path": "url", "reason": "unavailable"}],
        )
        self.assertEqual(connection.gaps[0].reason, "unavailable")
        reused = ExecutionEventMcpConnectionHttp(transport="http", gaps=connection.gaps)
        self.assertIs(reused.gaps, connection.gaps)
        self.assertIs(reused.gaps[0], connection.gaps[0])
        mcp = ahp.ExecutionEventMcp(connection=dict(connection), provenance="runtime",
                                    server={"id": "server"}, tool_name="read")
        self.assertEqual(mcp.connection.gaps[0].reason, "unavailable")
        self.assertEqual(mcp.server.id, "server")

    def test_constructor_wire_alias_collisions_are_explicit(self):
        facts = {"connection": {"transport": "http", "url": "https://example.test"},
                 "provenance": "runtime", "server": {"id": "server"}}
        for duplicate in ("snake", "camel"):
            with self.assertRaisesRegex(TypeError, "Duplicate assignment"):
                ahp.ExecutionEventMcp(**facts, tool_name="snake", toolName=duplicate)
        custom = ahp.ExecutionEventMcpConnectionCustomTransport
        self.assertEqual(custom(transport="vendor.pipe", address="pipe", addressForm="opaque").address_form, "opaque")
        for duplicate in ("opaque", "other"):
            with self.assertRaisesRegex(TypeError, "Duplicate assignment"):
                custom(transport="vendor.pipe", address_form="opaque", addressForm=duplicate)
        self.assertEqual(ahp.Registration(hooks=[], protocolVersion="draft").protocol_version, "draft")
        with self.assertRaises(ValueError):
            ahp.Registration(hooks=[], protocolVersion="future")
        with self.assertRaisesRegex(TypeError, "Duplicate assignment"):
            ahp.Registration(hooks=[], protocol_version="draft", protocolVersion="draft")
        # A raw wire mapping has distinct keys, not constructor keyword aliases.
        raw = {**facts, "toolName": "camel", "tool_name": "extension"}
        self.assertEqual(ahp.ExecutionEventMcp.from_dict(raw), raw)

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
