"""Explicit caller-owned tool value projections; wire evidence stays intact."""

from typing import Any, TypeVar

from ..codec import Codec, _decode_preserving
from ..contract import Candidate
from .. import _models as models

InputT = TypeVar("InputT")
ResultT = TypeVar("ResultT")
ProvenanceT = TypeVar("ProvenanceT")


class _ToolInput:
    raw: dict[str, Any]

    def decode_input(self, codec: Codec[InputT]) -> InputT:
        """Decode and round-trip-check this tool's declared input contract."""
        return _decode_preserving(codec, self.raw["params"]["event"]["tool"]["input"])


class _ToolCandidate:
    raw: dict[str, Any]

    def decode_candidate(
        self, result_codec: Codec[ResultT], provenance_codec: Codec[ProvenanceT]
    ) -> Candidate[ResultT, ProvenanceT] | None:
        """Project pending tool result/provenance without losing wire evidence."""
        candidate = self.raw["params"].get("state", {}).get("candidate")
        if candidate is None:
            return None
        provenance = (
            _decode_preserving(provenance_codec, candidate["provenance"])
            if "provenance" in candidate
            else models._UNSET
        )
        return Candidate(
            value=_decode_preserving(result_codec, candidate["value"]),
            provenance=provenance,
            additional_properties={
                key: value
                for key, value in candidate.items()
                if key not in ("value", "provenance")
            },
        )
