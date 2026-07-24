"""Stable cross-store correlation identifiers."""

from __future__ import annotations

import hashlib


def campaign_trace_id(campaign_run_id: str) -> str:
    """Return the W3C-compatible trace ID shared by one campaign's observations."""

    if not isinstance(campaign_run_id, str) or not campaign_run_id:
        raise ValueError("campaign run ID is required for trace correlation")
    return hashlib.sha256(f"campaign:{campaign_run_id}".encode()).hexdigest()[:32]


__all__ = ["campaign_trace_id"]
