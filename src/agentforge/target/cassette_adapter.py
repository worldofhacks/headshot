"""Deterministic no-socket cassette used only by the authorized synthetic profile."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentforge.target.base import TargetRequest
from agentforge.target.fake_adapter import FakeTargetAdapter


@dataclass
class SyntheticCassetteAdapter(FakeTargetAdapter):
    """Reuse the proven fake transport while satisfying an exact OpenEMR binding.

    The trusted Runner may construct this adapter only for the built-in synthetic target in
    local or staging.  It has no HTTP client, resolver, provider, or other socket capability.
    """

    base_url: str = "https://synthetic.invalid"
    name: str = "openemr"
    credential: Any | None = field(default=None, repr=False)

    @classmethod
    def for_cases(
        cls,
        cases: tuple[dict[str, Any], ...],
        *,
        base_url: str,
    ) -> SyntheticCassetteAdapter:
        adapter = cls(base_url=base_url)
        for case in cases:
            request = TargetRequest(turns=tuple(case["input_sequence"]))
            expectation = case.get("oracle_expectation")
            canary = expectation.get("canary_ref") if isinstance(expectation, dict) else None
            if isinstance(canary, str) and canary:
                output = f"deterministic synthetic cassette disclosure: {canary}"
            else:
                output = "deterministic synthetic cassette: no trusted oracle signal"
            adapter.script(request, output)
        return adapter


__all__ = ["SyntheticCassetteAdapter"]
