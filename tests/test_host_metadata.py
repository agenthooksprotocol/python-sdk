"""Metadata cannot grant authority and uses canonical manifest validation."""

from dataclasses import FrozenInstanceError
import unittest

from agenthooksprotocol import HostManifestMetadata
from agenthooksprotocol._models import (
    StaticCapabilityManifestGapsItem,
    StaticCapabilityManifestLimits,
    StaticCapabilityManifestManagedPolicy,
)


class HostMetadataTests(unittest.TestCase):
    def test_absent_and_explicit_empty_are_distinct(self):
        self.assertEqual(HostManifestMetadata().to_wire(), {})
        self.assertEqual(
            HostManifestMetadata(
                transports=(),
                authentication=(),
                tool_paths=(),
                content_categories=(),
                correlation_identity_fields=(),
                gaps=(),
                limits=StaticCapabilityManifestLimits(),
            ).to_wire(),
            {
                "transports": [],
                "authentication": [],
                "toolPaths": [],
                "contentCategories": [],
                "correlationIdentityFields": [],
                "gaps": [],
                "limits": {},
            },
        )

    def test_metadata_is_keyword_only_and_frozen(self):
        with self.assertRaises(TypeError):
            HostManifestMetadata(())
        metadata = HostManifestMetadata()
        with self.assertRaises(FrozenInstanceError):
            metadata.transports = ()
        with self.assertRaises(TypeError):
            metadata.additional_properties["opaque"] = {}

    def test_known_fields_and_event_grants_cannot_be_smuggled(self):
        for name in (
            "events",
            "gaps",
            "transports",
            "authentication",
            "toolPaths",
            "contentCategories",
            "limits",
            "managedPolicy",
            "correlationIdentityFields",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                HostManifestMetadata(additional_properties={name: []})
        with self.assertRaises(TypeError):
            HostManifestMetadata(events=())

    def test_inputs_and_wire_results_are_detached(self):
        extras = {"opaque": {"nested": ["original"]}}
        limits = StaticCapabilityManifestLimits(max_timeout_ms=100)
        policy = StaticCapabilityManifestManagedPolicy(
            disableable=True, scopes=["user"]
        )
        gap = StaticCapabilityManifestGapsItem(path="opaque", reason="Not supplied")
        metadata = HostManifestMetadata(
            limits=limits,
            managed_policy=policy,
            gaps=(gap,),
            additional_properties=extras,
        )
        expected = metadata.to_wire()
        extras["opaque"]["nested"].append("mutation")
        limits["maxTimeoutMs"] = 200
        policy["scopes"].append("project")
        gap["reason"] = "mutation"
        self.assertEqual(metadata.to_wire(), expected)
        wire = metadata.to_wire()
        wire["opaque"]["nested"].clear()
        wire["limits"].clear()
        wire["managedPolicy"]["scopes"].clear()
        wire["gaps"][0]["reason"] = "wire mutation"
        self.assertEqual(metadata.to_wire(), expected)

    def test_typed_fields_require_canonical_models_and_collections(self):
        for kwargs in (
            {"limits": {}},
            {"managed_policy": {}},
            {"gaps": ({"path": "x", "reason": "y"},)},
            {"transports": ["in_process"]},
            {"tool_paths": (1,)},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                HostManifestMetadata(**kwargs)

    def test_canonical_validation_rejects_invalid_metadata(self):
        limits = StaticCapabilityManifestLimits()
        limits["maxTimeoutMs"] = -1
        with self.assertRaises(ValueError):
            HostManifestMetadata(limits=limits)

    def test_all_metadata_fields_have_canonical_wire_names(self):
        metadata = HostManifestMetadata(
            transports=("in_process",),
            authentication=(),
            tool_paths=("tool.name",),
            content_categories=("text",),
            correlation_identity_fields=("event.source", "event.id"),
            limits=StaticCapabilityManifestLimits(max_timeout_ms=100),
            managed_policy=StaticCapabilityManifestManagedPolicy(
                disableable=True, scopes=[]
            ),
            gaps=(
                StaticCapabilityManifestGapsItem(
                    path="events.other", reason="Unsupported"
                ),
            ),
            additional_properties={"opaque": {"enabled": True}},
        )
        wire = metadata.to_wire()
        self.assertNotIn("events", wire)
        self.assertEqual(wire["toolPaths"], ["tool.name"])
        self.assertEqual(wire["contentCategories"], ["text"])
        self.assertEqual(wire["limits"], {"maxTimeoutMs": 100})
        self.assertEqual(wire["opaque"], {"enabled": True})
