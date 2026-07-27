"""Keep current documentation aligned with runtime authorities.

Dated evidence and historical plans intentionally retain old facts.  This contract checks only the
files classified as current by docs/DOCUMENTATION.md.
"""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from agentforge.agents.hosted import HOSTED_ROLE_MODELS
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.prompts import load_prompt_registry
from agentforge.campaign.corpus import (
    LIVE_100_BATCH_SPECS,
    LIVE_100_CASE_COUNT,
    LIVE_100_PHYSICAL_REQUEST_COUNT,
)

ROOT = Path(__file__).resolve().parents[1]
CURRENT_DOCUMENTS = (
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "ARCHITECTURE.md",
    "PLAN.md",
    "THREAT_MODEL.md",
    "USERS.md",
    ".env.example",
    "console/README.md",
    "railway/README.md",
    "docs/CURRENT_STATE.md",
    "docs/DOCUMENTATION.md",
    "docs/agents/RED_TEAM_MODEL_RESOLUTION.md",
    "docs/agents/RED_TEAM_TRACED_GENERATION.md",
    "docs/cost/COST_ANALYSIS.md",
    "docs/defense/DEFENSE_SCRIPT.md",
    "docs/demo/MVP_DEMO_SCRIPT.md",
    "docs/deployment/FOUR_MODEL_RECOVERY.md",
    "docs/deployment/RAILWAY.md",
    "docs/security/AUTHENTICATION.md",
    "docs/target/READINESS.md",
    "docs/target/TARGETS.md",
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_current_document_set_exists_and_has_no_known_obsolete_runtime_claims() -> None:
    contents = "\n".join(_read(path) for path in CURRENT_DOCUMENTS)
    obsolete = (
        "2069036e",
        "0021_four_role_agent_acceptance",
        "GitHub Actions is the sole CI gate",
        "GitLab is a passive exact mirror",
        "q is not a fourth live hosted role",
        "A case with multiple authored turns is joined into one message",
        "staging the targets load and preflight, but every live send is refused",
    )
    for claim in obsolete:
        assert claim not in contents


def test_current_state_names_every_runtime_role_and_default_policy() -> None:
    state = _read("docs/CURRENT_STATE.md")
    architecture = _read("ARCHITECTURE.md")
    instructions = _read("CLAUDE.md")

    for model in HOSTED_ROLE_MODELS.values():
        assert model in state
        assert model in architecture
        assert model in instructions

    for prompt in load_prompt_registry():
        assert prompt.sha256 in state

    digest = DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256
    assert digest in state
    assert digest in instructions

    for role, bounds in DEFAULT_HOSTED_GENERATION_POLICY.call_bounds.items():
        assert role.replace("_", " ").title() in state
        assert f"{bounds.input_tokens:,}" in state
        assert f"{bounds.output_tokens:,}" in state
        assert f"{bounds.reasoning_tokens:,}" in state
        assert f"{bounds.timeout_seconds:g} s" in state


def test_current_docs_name_the_packaged_alembic_head() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert heads == ["0026"]

    for path in (
        "README.md",
        "ARCHITECTURE.md",
        "docs/CURRENT_STATE.md",
        "docs/deployment/RAILWAY.md",
        "railway/README.md",
    ):
        assert heads[0] in _read(path)


def test_current_docs_match_live_workload_shape() -> None:
    combined = "\n".join(
        _read(path)
        for path in (
            "README.md",
            "ARCHITECTURE.md",
            "docs/CURRENT_STATE.md",
            "docs/target/TARGETS.md",
        )
    )
    assert f"{LIVE_100_CASE_COUNT} cases" in combined
    assert f"{LIVE_100_PHYSICAL_REQUEST_COUNT} target turns" in combined

    for workload_id, spec in LIVE_100_BATCH_SPECS.items():
        assert workload_id in combined
        assert f"| {int(spec['case_count'])} | {int(spec['physical'])} |" in combined
