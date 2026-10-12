"""Exported wire constructors share structural validation with Parse."""

import unittest
import typing
import json
from pathlib import Path

import agenthooksprotocol as ahp
from decimal import Decimal

from agenthooksprotocol import (
    ContentReference,
    ContentUploadReceipt,
    ExecutionEventMcpConnectionHttp,
)
from agenthooksprotocol import capability, effect, state
from agenthooksprotocol._models import capability as wire_capability
from agenthooksprotocol.generated import parse_content_reference


class StructuralFacadeTests(unittest.TestCase):
    def test_from_dict_hydrates_nested_models(self):
        raw = {"transport": "http", "gaps": [{"path": "url", "reason": "unavailable"}]}
        decoded = ExecutionEventMcpConnectionHttp.from_dict(raw)
        self.assertEqual(decoded.gaps[0].reason, "unavailable")
        self.assertEqual(decoded.gaps[0].path, "url")
        self.assertEqual(decoded, raw)
        caps = wire_capability.Capabilities.from_dict(
            {
                "effects": ["modify"],
                "modify": {"input": {"replace": True, "merge": False}},
            }
        )
        self.assertTrue(caps.modify.input.replace)

    def test_all_generated_effect_array_queries_are_sound(self):
        families, payloads = set(), set()
        for name in ahp._models.__all__:
            cls = getattr(ahp._models, name)
            if (
                isinstance(cls, type)
                and issubclass(cls, dict)
                and isinstance(getattr(cls, "effects", None), property)
            ):
                annotation = typing.get_type_hints(cls.effects.fget)["return"]
                (families if annotation == list[str] else payloads).add(cls)
        self.assertGreaterEqual(len(families), 21)
        self.assertTrue(payloads)
        self.assertTrue(all(hasattr(cls, "supports") for cls in families))
        self.assertTrue(all(not hasattr(cls, "supports") for cls in payloads))

    def test_all_exported_capability_models_support_family_queries(self):
        classes = {
            value
            for value in vars(wire_capability).values()
            if isinstance(value, type)
            and issubclass(value, dict)
            and hasattr(value, "effects")
        }
        self.assertGreaterEqual(len(classes), 20)
        for cls in classes:
            with self.subTest(cls.__name__):
                for caps in (
                    cls(effects=["deny", "vendor.custom"]),
                    cls.from_dict({"effects": ["deny", "vendor.custom"]}),
                ):
                    self.assertTrue(caps.supports(capability.EffectName.DENY))
                    self.assertTrue(caps.supports("vendor.custom"))
                    self.assertFalse(caps.supports(capability.EffectName.MODIFY))
                self.assertFalse(cls(effects=[]).supports(capability.EffectName.DENY))
        self.assertTrue(
            wire_capability.ToolBeforeCapabilities(effects=["deny"]).supports(
                capability.EffectName.DENY
            )
        )
        self.assertFalse(hasattr(ahp.InterceptDenyResponseResult, "supports"))

    def test_constructors_require_typed_nested_values(self):
        with self.assertRaises(TypeError):
            wire_capability.Capabilities(effects=["modify"], modify={})
        caps = wire_capability.Capabilities(
            effects=["modify"], modify=ahp.CapabilitiesModify()
        )
        self.assertIsNone(caps.modify.input)
        self.assertIsInstance(caps.modify, ahp.CapabilitiesModify)
        with self.assertRaises(TypeError):
            ExecutionEventMcpConnectionHttp(
                transport="http",
                gaps=[{"path": "url", "reason": "unavailable"}],
            )
        connection = ExecutionEventMcpConnectionHttp(
            transport="http",
            gaps=[
                ahp.ExecutionEventMcpConnectionHttpGapsItem(
                    path="url",
                    reason="unavailable",
                )
            ],
        )
        self.assertEqual(connection.gaps[0].reason, "unavailable")
        reused = ExecutionEventMcpConnectionHttp(transport="http", gaps=connection.gaps)
        self.assertIs(reused.gaps, connection.gaps)
        self.assertIs(reused.gaps[0], connection.gaps[0])
        server = ahp.ExecutionEventMcpServer(id="server")
        with self.assertRaises(TypeError):
            ahp.ExecutionEventMcp(
                connection=dict(connection),
                provenance="runtime",
                server=server,
                tool_name="read",
            )
        with self.assertRaises(TypeError):
            ahp.ExecutionEventMcp(
                connection=connection,
                provenance="runtime",
                server={"id": "server"},
                tool_name="read",
            )
        mcp = ahp.ExecutionEventMcp(
            connection=connection, provenance="runtime", server=server, tool_name="read"
        )
        self.assertIs(mcp.connection, connection)
        self.assertIs(mcp.server, server)

    def test_constructor_wire_keyword_aliases_are_rejected(self):
        facts = {
            "connection": ahp.ExecutionEventMcpConnectionHttp(
                transport="http", url="https://example.test"
            ),
            "provenance": "runtime",
            "server": ahp.ExecutionEventMcpServer(id="server"),
        }
        for keywords in (
            {"toolName": "camel"},
            {"tool_name": "snake", "toolName": "camel"},
        ):
            with self.subTest(keywords=keywords), self.assertRaises(TypeError):
                ahp.ExecutionEventMcp(**facts, **keywords)
        custom = ahp.ExecutionEventMcpConnectionCustomTransport
        self.assertEqual(
            custom(
                transport="vendor.pipe", address="pipe", address_form="opaque"
            ).address_form,
            "opaque",
        )
        for keywords in (
            {"addressForm": "opaque"},
            {"address_form": "opaque", "addressForm": "opaque"},
        ):
            with self.subTest(keywords=keywords), self.assertRaises(TypeError):
                custom(transport="vendor.pipe", **keywords)
        self.assertEqual(
            ahp.Registration(hooks=[], protocol_version="draft").protocol_version,
            "draft",
        )
        with self.assertRaises(ValueError):
            ahp.Registration(hooks=[], protocol_version="future")
        for keywords in (
            {"protocolVersion": "draft"},
            {"protocol_version": "draft", "protocolVersion": "draft"},
        ):
            with self.subTest(keywords=keywords), self.assertRaises(TypeError):
                ahp.Registration(hooks=[], **keywords)
        # Wire-key decoding remains explicit and retains distinct extension keys.
        raw = {
            "connection": dict(facts["connection"]),
            "provenance": "runtime",
            "server": dict(facts["server"]),
            "toolName": "camel",
            "tool_name": "extension",
        }
        self.assertEqual(ahp.ExecutionEventMcp.from_dict(raw), raw)
        self.assertEqual(
            custom.from_dict(
                {"transport": "vendor.pipe", "address": "pipe", "addressForm": "opaque"}
            ).address_form,
            "opaque",
        )
        self.assertEqual(
            ahp.Registration.from_dict(
                {"hooks": [], "protocolVersion": "draft"}
            ).protocol_version,
            "draft",
        )

    def test_family_support_is_not_authorization(self):
        self.assertIs(capability.EffectName, effect.EffectName)
        for cls in (
            wire_capability.Capabilities,
            wire_capability.InterceptRequestParamsCapabilities,
        ):
            caps = cls.from_dict(
                {
                    "effects": ["deny", "vendor.custom"],
                    "modify": {"input": {"replace": True, "merge": False}},
                }
            )
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
        self.assertEqual(
            parse_content_reference(decoded), parse_content_reference(value)
        )
        for bad in ({"ref": "opaque", "size": None}, {"ref": 7}):
            with self.assertRaises(ValueError) as raised:
                ContentReference.from_dict(bad)
            self.assertEqual(raised.exception.result, parse_content_reference(bad))
        for bad_number in (float("nan"), float("inf"), Decimal("NaN")):
            with self.assertRaises(ValueError):
                ContentReference(ref="opaque", future=bad_number)


class SharedStructuralMatrixTests(unittest.TestCase):
    def test_public_models_and_parsers_match_expected_contract(self):
        cases = json.loads(
            Path(__file__).with_name("structural-acceptance.json").read_text()
        )["cases"]
        for entry in cases:
            with self.subTest(entry["id"]):
                model_name = "".join(word.title() for word in entry["root"].split("_"))
                model = getattr(ahp, model_name)
                parse = getattr(ahp.generated, "parse_" + entry["root"])
                parsed = parse(entry["value"])
                self.assertEqual(parsed["ok"], entry["accepted"])
                self.assertEqual(
                    any(d["severity"] == "warning" for d in parsed["diagnostics"]),
                    entry["warning"],
                )
                self.assertEqual(parsed["raw"], entry["value"])
                if entry["accepted"]:
                    decoded = model.from_dict(entry["value"])
                    self.assertEqual(decoded, entry["value"])
                    self.assertEqual(parsed["value"], decoded)
                else:
                    with self.assertRaises(ValueError):
                        model.from_dict(entry["value"])
