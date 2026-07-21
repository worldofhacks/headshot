"""Seed replay — authored AttackCase seed -> schema-valid ``attack_attempt`` (M8, P10).

ARCHITECTURE.md §3/§8/§16 (trust split F2, live-campaign gate F7), PRD-14/17.

Seed replay is the offline, network-free FIRST slice AND the offline e2e generator: it reads
the authored M11 AttackCase seeds off disk (local JSON only — no network) and maps each to a
``attack_attempt`` the P10 contract accepts. The mapped attempt carries only what the contract
permits: the ``case_ref`` (the source case's ``case_id``), the ordered multi-turn
``input_sequence``, and the ``category``. It carries NO credential, NO ``content_hash``, NO
verdict — no trusted signal at all. Evidence is minted by the trusted gateway/recorder and
adjudicated by the Judge; the Red Team, an untrusted generator, never produces any of it.

Deterministic by construction: seeds are read in sorted ``case_id`` order, so replaying the same
corpus twice yields byte-identical attempts in the same order (a regression/replay run must not
drift).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# The const schema_version the P10 attack_attempt contract requires.
_SCHEMA_VERSION = "1"


def seed_to_attempt(case: dict[str, Any]) -> dict[str, Any]:
    """Map one authored AttackCase seed to a schema-valid ``attack_attempt`` dict.

    The mapping is total and lossless for the fields the contract permits and empty of every
    trusted field:

    * ``case_ref`` <- the seed's own ``case_id`` (the attempt is traceable back to its source
      case; never invented or blank);
    * ``input_sequence`` <- the seed's ordered turns, copied turn-for-turn (a multi-turn attack
      stays first-class — it is never collapsed into a single flattened prompt); and
    * ``category`` <- the seed's attack category (selection keys on it).

    Only these keys (plus the const ``schema_version``) are emitted, so the contract's
    ``additionalProperties: false`` holds and no credential / evidence / verdict rides along.
    """
    attempt: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "case_ref": case["case_id"],
        # A fresh list, in the seed's own order — the mapped attempt never aliases the seed.
        "input_sequence": list(case["input_sequence"]),
    }
    category = case.get("category")
    if category is not None:
        attempt["category"] = category
    return attempt


def load_seed_attempts(seeds_dir: str | Path) -> list[dict[str, Any]]:
    """Ingest the whole seed corpus under ``seeds_dir`` into schema-valid attack_attempts.

    Every ``*.json`` seed is read (local disk only — no network), mapped by
    :func:`seed_to_attempt`, and returned in a stable, sorted-by-path order. Replay drops
    nothing and invents nothing: the returned ``case_ref``s are exactly the corpus ``case_id``s.
    The result is deterministic — the same corpus always yields the same attempts in the same
    order.
    """
    directory = Path(seeds_dir)
    attempts: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        attempts.append(seed_to_attempt(case))
    return attempts
