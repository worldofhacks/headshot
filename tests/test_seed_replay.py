"""M8 — Red Team seed-replay RED tests (written first, NO src/ code).

Anchors: ARCHITECTURE.md §3/§8/§16 (trust split F2, live-campaign gate F7), PRD-14/17;
IMPLEMENTATION_PLAN.md M8; wf-m8-redteam DESIGN + ACCEPTANCE. Deps: P10 contract
(``contracts/v1/attack_attempt.json``), the M11 seed corpus under ``evals/seeds/``.

Seed replay is the offline, network-free first slice: it ingests the authored AttackCase
seeds and maps each to a **schema-valid** ``attack_attempt`` (the P10 contract validates it),
carrying the ordered multi-turn ``input_sequence`` and the ``category`` — and NOTHING trusted.
The Red Team emits ONLY an AttackAttempt: it produces NO credential, NO ``content_hash``, NO
verdict, NO trusted evidence signal (that is the Recorder's / Judge's job, never the RT's).

These tests pin the ACCEPTANCE edges — never a happy path alone. Until
``agentforge.agents.red_team.seed_replay`` exists, every import below fails and this module
RED-collects for the right reason (an import error, not a logic bug).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# The RT seed-replay surface under test (does not exist yet -> RED by import error).
from agentforge.agents.red_team.seed_replay import load_seed_attempts, seed_to_attempt
from agentforge.contracts import is_valid, validate

# The repo's M11 seed corpus. Seed replay reads these authored AttackCase artifacts.
SEEDS_DIR = Path(__file__).resolve().parent.parent / "evals" / "seeds"

# Trusted signals the Red Team (an UNTRUSTED generator) must NEVER emit on an AttackAttempt.
# Evidence is minted by the trusted gateway/recorder and adjudicated by the Judge — never here.
_FORBIDDEN_TRUSTED_FIELDS = (
    "credential",
    "content_hash",
    "verdict",
    "attempt_result",
    "campaign_run_id",
    "policy_decision_id",
    "recorder_identity",
    "evidence",
    "disposition",
)


def _load_case(case_id: str) -> dict:
    """Read one authored AttackCase seed straight off disk (no RT code involved)."""
    return json.loads((SEEDS_DIR / f"{case_id}.json").read_text(encoding="utf-8"))


# ===========================================================================
# (a) seed replay maps a seed to a SCHEMA-VALID attack_attempt (P10 contract validates it)
# ===========================================================================
def test_seed_maps_to_contract_valid_attack_attempt() -> None:
    """A single authored seed maps to a dict the P10 ``attack_attempt`` schema accepts.

    ``validate`` raises on any violation; ``is_valid`` is asserted True belt-and-suspenders.
    The mapped attempt must carry the const ``schema_version`` "1" and a non-empty
    ``case_ref`` — the contract requires both.
    """
    case = _load_case("AF-M11-PI-001")

    attempt = seed_to_attempt(case)

    validate("attack_attempt", attempt)  # raises on any schema violation
    assert is_valid("attack_attempt", attempt) is True
    assert attempt["schema_version"] == "1"
    assert attempt["case_ref"]  # non-empty, minLength 1 in the contract


def test_case_ref_traces_back_to_the_source_case_id() -> None:
    """The mapped ``case_ref`` is the seed's own ``case_id`` — the attempt is traceable back
    to the authored case it descends from (never an invented or blank ref)."""
    case = _load_case("AF-M11-TM-001")

    attempt = seed_to_attempt(case)

    assert attempt["case_ref"] == case["case_id"] == "AF-M11-TM-001"


def test_category_is_carried_through() -> None:
    """The seed's attack ``category`` is preserved on the attempt (selection keys on it)."""
    case = _load_case("AF-M11-DX-001")

    attempt = seed_to_attempt(case)

    assert attempt["category"] == case["category"] == "data_exfiltration"


# ===========================================================================
# (a)+(d) a MULTI-TURN seed carries its turns IN ORDER (not a single flattened prompt)
# ===========================================================================
def test_multi_turn_seed_preserves_ordered_turns() -> None:
    """A multi-turn seed maps to an ``input_sequence`` with every turn, in the SAME order —
    a multi-turn attack is first-class, never collapsed into one prompt."""
    case = _load_case("AF-M11-PI-002")
    assert case["sequence_type"] == "multi_turn"
    assert len(case["input_sequence"]) >= 2  # a genuine multi-turn seed

    attempt = seed_to_attempt(case)

    # Identity AND order: the mapped sequence is the seed's sequence, turn-for-turn.
    assert attempt["input_sequence"] == case["input_sequence"]
    assert len(attempt["input_sequence"]) == len(case["input_sequence"])
    # Ordering is load-bearing: the reversed sequence must NOT compare equal.
    assert attempt["input_sequence"] != list(reversed(case["input_sequence"]))
    is_valid("attack_attempt", attempt)
    validate("attack_attempt", attempt)


def test_single_turn_seed_maps_to_a_one_element_sequence() -> None:
    """A single-turn seed maps to a one-element ``input_sequence`` (still an array — the
    contract's ``minItems`` is 1 — never a bare string)."""
    case = _load_case("AF-M11-PI-001")
    assert case["sequence_type"] == "single_turn"

    attempt = seed_to_attempt(case)

    assert isinstance(attempt["input_sequence"], list)
    assert attempt["input_sequence"] == case["input_sequence"]
    assert len(attempt["input_sequence"]) == 1


# ===========================================================================
# (a) the RT output carries NO credential / content_hash / verdict / trusted signal
# ===========================================================================
def test_attempt_holds_no_trusted_evidence_fields() -> None:
    """The RT is an UNTRUSTED generator: its AttackAttempt carries no evidence and no
    credential. None of the trusted fields (minted only by gateway/recorder/Judge) may appear.
    """
    attempt = seed_to_attempt(_load_case("AF-M11-PI-001"))

    for forbidden in _FORBIDDEN_TRUSTED_FIELDS:
        assert forbidden not in attempt, (
            f"the Red Team emitted a trusted field {forbidden!r} — evidence/credentials are "
            "the gateway/recorder/Judge's to mint, never the untrusted generator's"
        )


def test_attempt_has_only_contract_permitted_keys() -> None:
    """The contract sets ``additionalProperties: false``. The mapped attempt must therefore
    contain ONLY keys the schema permits — proving no stray trusted signal rides along."""
    permitted = {
        "schema_version",
        "case_ref",
        "input_sequence",
        "mutation_lineage",
        "category",
    }
    attempt = seed_to_attempt(_load_case("AF-M11-DX-003"))

    assert set(attempt).issubset(permitted), (
        f"attempt carries keys outside the contract: {set(attempt) - permitted}"
    )
    validate("attack_attempt", attempt)  # additionalProperties:false enforced here too


# ===========================================================================
# (a) load_seed_attempts ingests the WHOLE corpus; every result validates
# ===========================================================================
def test_load_seed_attempts_yields_only_contract_valid_attempts() -> None:
    """Loading the corpus produces one schema-valid AttackAttempt per seed — the offline e2e
    generator emits nothing the P10 contract would reject."""
    attempts = load_seed_attempts(SEEDS_DIR)

    assert len(attempts) >= 9  # the M11 corpus (PI/DX/TM x several) — at least the seeds present
    for attempt in attempts:
        validate("attack_attempt", attempt)
        assert is_valid("attack_attempt", attempt) is True
        # No trusted signal on ANY generated attempt.
        for forbidden in _FORBIDDEN_TRUSTED_FIELDS:
            assert forbidden not in attempt


def test_load_seed_attempts_is_deterministic() -> None:
    """Seed replay is deterministic: loading the same corpus twice yields identical attempts in
    the same order (no randomness that would break a regression/replay run)."""
    first = load_seed_attempts(SEEDS_DIR)
    second = load_seed_attempts(SEEDS_DIR)

    assert first == second
    assert [a["case_ref"] for a in first] == [a["case_ref"] for a in second]


def test_load_seed_attempts_covers_every_corpus_case_ref() -> None:
    """Every authored seed on disk is represented exactly once — replay drops nothing and
    invents nothing (the case_refs are exactly the corpus case_ids)."""
    on_disk = {
        json.loads(p.read_text(encoding="utf-8"))["case_id"] for p in SEEDS_DIR.glob("*.json")
    }

    attempts = load_seed_attempts(SEEDS_DIR)
    refs = [a["case_ref"] for a in attempts]

    assert set(refs) == on_disk
    assert len(refs) == len(set(refs)) == len(on_disk)  # no duplicates, no omissions


# ===========================================================================
# seed replay does NO network / socket I/O (offline-first slice)
# ===========================================================================
def test_seed_replay_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed replay reads local JSON only. Break socket construction; replaying the whole corpus
    then proves it opened ZERO sockets (the offline path is genuinely offline)."""
    import socket

    def boom(*_args, **_kwargs):
        raise AssertionError("seed replay attempted network I/O (opened a socket)")

    monkeypatch.setattr(socket, "socket", boom)

    attempts = load_seed_attempts(SEEDS_DIR)  # must not touch the network

    assert attempts
    validate("attack_attempt", attempts[0])
