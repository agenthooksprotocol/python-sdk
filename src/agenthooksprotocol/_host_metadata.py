"""Typed host facts that cannot grant event authority."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ._models import (
    StaticCapabilityManifestGapsItem,
    StaticCapabilityManifestLimits,
    StaticCapabilityManifestManagedPolicy,
)


_KNOWN_FIELDS = frozenset(
    {
        "events",
        "gaps",
        "transports",
        "authentication",
        "toolPaths",
        "contentCategories",
        "limits",
        "managedPolicy",
        "correlationIdentityFields",
    }
)
_COLLECTION_FIELDS = {
    "transports": "transports",
    "authentication": "authentication",
    "tool_paths": "toolPaths",
    "content_categories": "contentCategories",
    "correlation_identity_fields": "correlationIdentityFields",
}


@dataclass(frozen=True, kw_only=True, slots=True)
class HostManifestMetadata:
    """Metadata only; event grants come exclusively from HostCapabilities.

    None leaves a field undeclared so Hooks can report an honest gap. Explicit
    empty collections declare that the host supplies no such facilities. Inputs
    are snapshotted and each wire representation is independently detached.
    """

    transports: tuple[str, ...] | None = None
    authentication: tuple[str, ...] | None = None
    tool_paths: tuple[str, ...] | None = None
    content_categories: tuple[str, ...] | None = None
    limits: StaticCapabilityManifestLimits | None = None
    managed_policy: StaticCapabilityManifestManagedPolicy | None = None
    correlation_identity_fields: tuple[str, ...] | None = None
    gaps: tuple[StaticCapabilityManifestGapsItem, ...] | None = None
    additional_properties: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.additional_properties, Mapping):
            raise TypeError("additional_properties must be a mapping")
        for key in self.additional_properties:
            if not isinstance(key, str):
                raise TypeError("additional_properties keys must be strings")
            if key in _KNOWN_FIELDS:
                raise ValueError(f"additional_properties cannot override {key}")
        for name in _COLLECTION_FIELDS:
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, tuple)
                or not all(isinstance(item, str) for item in value)
            ):
                raise TypeError(f"{name} must be a tuple of strings")
        if self.gaps is not None and (
            not isinstance(self.gaps, tuple)
            or not all(
                isinstance(item, StaticCapabilityManifestGapsItem) for item in self.gaps
            )
        ):
            raise TypeError("gaps must be a tuple of StaticCapabilityManifestGapsItem")
        for name, model in (
            ("limits", StaticCapabilityManifestLimits),
            ("managed_policy", StaticCapabilityManifestManagedPolicy),
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, model):
                raise TypeError(f"{name} requires {model.__name__}")
            object.__setattr__(self, name, deepcopy(value))
        object.__setattr__(self, "gaps", deepcopy(self.gaps))
        object.__setattr__(
            self,
            "additional_properties",
            MappingProxyType(deepcopy(dict(self.additional_properties))),
        )
        if self.limits is not None:
            for key in (
                "maxUploadBytes",
                "maxContinuations",
                "minTimeoutMs",
                "maxTimeoutMs",
            ):
                if key in self.limits:
                    value = self.limits[key]
                    if type(value) is not int or value < 0:
                        raise ValueError(f"{key} must be a nonnegative integer")
        if self.managed_policy is not None:
            scopes = self.managed_policy.get("scopes")
            disableable = self.managed_policy.get("disableable")
            if (
                not isinstance(scopes, list)
                or any(scope not in ("user", "project", "managed") for scope in scopes)
                or len(scopes) != len(set(scopes))
                or type(disableable) is not bool
                or ("managed" in scopes and disableable)
            ):
                raise ValueError(
                    "managed_policy requires coherent scopes and disableable"
                )

    def to_wire(self) -> dict[str, Any]:
        """Return only declared metadata, with fresh nested wire values."""
        result = deepcopy(dict(self.additional_properties))
        for name, wire_name in _COLLECTION_FIELDS.items():
            value = getattr(self, name)
            if value is not None:
                result[wire_name] = list(value)
        if self.limits is not None:
            result["limits"] = deepcopy(dict(self.limits))
        if self.managed_policy is not None:
            result["managedPolicy"] = deepcopy(dict(self.managed_policy))
        if self.gaps is not None:
            result["gaps"] = [deepcopy(dict(item)) for item in self.gaps]
        return result
