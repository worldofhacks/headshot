#!/usr/bin/env python3
"""Run the REAL platform coordinator live: Orchestrator-authorized Red-Team corpus -> Policy
Gateway -> Execution Recorder (Postgres) -> re-read + hash-verify -> Canary Oracle -> Evidence
Envelope -> independent Judge -> immutable manifests.

This is NOT a hand-rolled scan: it drives ``agentforge.campaign.coordinator.SecureCampaignCoordinator``
— the platform's own live-campaign sequencer — over the authored M11 seed corpus against the live
Clinical Co-Pilot. The only things injected are the collaborators the production composition root
(``agentforge.campaign.__main__``) normally injects (engine / adapter / clock / accounting) PLUS a
``credential_resolver`` — the exact seam the private Runner fills — that resolves the bound
``secretref`` to ``Secret(WEEK1_SID)`` read from the environment by reference (never inlined/logged).

Two-person control: the human owner APPROVED this exact run (interactive approval, 2026-07-24); this
launcher (the agent) does NOT self-approve. The minted RunAuthorization + the written approval
artifact record ``approver != launcher``.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.red_team.seed_replay import corpus_sha256, load_seed_attempts  # noqa: E402
from agentforge.campaign.authorization import AuthorizationError, RunAuthorization  # noqa: E402
from agentforge.campaign.binding import TargetBinding  # noqa: E402
from agentforge.campaign.caps import RunCaps  # noqa: E402
from agentforge.campaign.coordinator import (  # noqa: E402
    CampaignAbort,
    RunConfig,
    SecureCampaignCoordinator,
    operation_hash_for,
)
from agentforge.campaign.manifest import ManifestStore  # noqa: E402
from agentforge.campaign.runtime import RunAccounting, SystemClock, production_engine  # noqa: E402
from agentforge.secrets import Secret  # noqa: E402
from agentforge.target.openemr_adapter import OpenEmrAdapter  # noqa: E402

TARGET_ID = "copilot-week1"
HOST = "agent-production-9f62.up.railway.app"
ADAPTER_KIND = "openemr"
CREDENTIAL_REF = "secretref://staging/copilot-week1/session/generation-20260724a"
AUTH_MODE = "session"
CANARY = "SYNTH_CANARY_SYSTEM_PROMPT_4D2B"
RUN_NONCE = "platform-live-run-20260724-week1"
CORPUS_ID = "m11-seed-corpus-v1"
CAMPAIGN_RUN_ID = os.environ.get("LC_CAMPAIGN_RUN_ID", "platform-live-20260724-week1")
SEEDS_DIR = ROOT / "evals" / "seeds"
OUT = ROOT / "evals" / "results" / "platform-live-run-20260724"
CAPS = {
    "budget_usd": 1.0,
    "max_attempts_per_run": 40,
    "target_requests_per_second": 0.5,
    "run_timeout_seconds": 1800.0,
    "logical_case_limit": 40,
    "physical_request_limit": 60,
    "target_retries_per_turn": 1,
}


def main() -> int:
    sid = os.environ.get("WEEK1_SID")
    if not sid:
        print("BLOCKED: WEEK1_SID not set", file=sys.stderr)
        return 5
    database_url = os.environ.get("DATABASE_URL")

    OUT.mkdir(parents=True, exist_ok=True)
    binding = TargetBinding(
        target_id=TARGET_ID,
        host=HOST,
        adapter_kind=ADAPTER_KIND,
        credential_ref=CREDENTIAL_REF,
        auth_mode=AUTH_MODE,
    )
    policy = RunCaps.parse(CAPS)
    seeds = load_seed_attempts(SEEDS_DIR)
    corpus_sha = corpus_sha256(seeds)
    op_hash = operation_hash_for(
        binding,
        policy=policy,
        corpus_id=CORPUS_ID,
        corpus_sha=corpus_sha,
        run_nonce=RUN_NONCE,
    )

    # --- two-person provenance: approver (human owner) != launcher (agent) ---
    now = time.time()
    deadline = now + 1800.0
    approval = {
        "artifact": "run-authorization-approval",
        "operation_hash": op_hash,
        "run_nonce": RUN_NONCE,
        "corpus_id": CORPUS_ID,
        "corpus_sha": corpus_sha,
        "deadline_utc": datetime.fromtimestamp(deadline, tz=UTC).isoformat(),
        "launcher": "agent (Claude Code) — did NOT self-approve",
        "approver": "human owner — explicit interactive approval 2026-07-24 (approver != launcher)",
        "note": "Stand-in for the Clerk two-person Approver service (not yet wired). The human owner "
        "is the distinct approving principal; the agent is the launcher.",
    }
    (OUT / "approval.json").write_text(json.dumps(approval, indent=2))
    authorization = RunAuthorization(operation_hash=op_hash, run_nonce=RUN_NONCE, deadline=deadline)

    engine = production_engine(database_url)
    adapter = OpenEmrAdapter(
        base_url=binding.host_base_url(),
        payload_profile="copilot_chat",
        relative_path="chat",
        timeout_seconds=120.0,
    )
    manifests = ManifestStore(root=OUT / "manifests")
    config = RunConfig(
        binding=binding,
        authorization=authorization,
        policy=policy,
        run_nonce=RUN_NONCE,
        canary_token=CANARY,
        environment="production",
        corpus_id=CORPUS_ID,
        corpus_sha=corpus_sha,
        campaign_run_id=CAMPAIGN_RUN_ID,
        # The Runner's credential-lease seam: resolve the bound secretref to the env SID by reference.
        credential_resolver=lambda ref: Secret(sid),
    )
    coordinator = SecureCampaignCoordinator(
        config=config,
        adapter=adapter,
        engine=engine,
        manifests=manifests,
        clock=SystemClock(),
        accounting=RunAccounting(),
    )

    print(
        f"PLATFORM LIVE RUN  campaign={CAMPAIGN_RUN_ID}  target={HOST}/chat  cases={len(seeds)}",
        flush=True,
    )
    print(
        f"  op_hash={op_hash}  canary={CANARY}  caps rps={CAPS['target_requests_per_second']}",
        flush=True,
    )

    rows = []
    # Optional subset (continuation runs): LC_ONLY_CASES=CASE1,CASE2 restricts to those case_refs.
    only = os.environ.get("LC_ONLY_CASES", "").strip()
    only_set = {c.strip() for c in only.split(",") if c.strip()} if only else None
    # Pace between cases to honor the gateway's rate cap (it HARD-ABORTS a dispatch that is under
    # the 1/rps min interval — the Runner is responsible for spacing cases). Within a multi-turn
    # case the gateway paces its own turns.
    pace_seconds = 1.0 / CAPS["target_requests_per_second"] + 0.4
    dispatched = 0
    for attempt in seeds:
        if only_set is not None and attempt["case_ref"] not in only_set:
            continue
        if dispatched:
            time.sleep(pace_seconds)
        dispatched += 1
        seed_case = {
            "case_id": attempt["case_ref"],
            "input_sequence": list(attempt["input_sequence"]),
        }
        if "category" in attempt:
            seed_case["category"] = attempt["category"]
        try:
            outcome = coordinator.run_case(seed_case, attempt_id=attempt["case_ref"])
        except (CampaignAbort, AuthorizationError) as exc:
            print(f"  {attempt['case_ref']:16} ABORT {type(exc).__name__}: {exc}", flush=True)
            rows.append(
                {"case_ref": attempt["case_ref"], "aborted": f"{type(exc).__name__}: {exc}"}
            )
            break
        v = outcome.verdict
        rows.append(
            {
                "case_ref": attempt["case_ref"],
                "category": attempt.get("category"),
                "verdict_state": v.get("state"),
                "confidence": v.get("confidence"),
                "reason_codes": list(v.get("reason_codes", [])),
                "oracle_hit": bool(outcome.oracle_signal.get("hit")),
                "integrity_ok": outcome.integrity_ok,
                "http_status": outcome.result.fields.get("http_status")
                if hasattr(outcome.result, "fields")
                else None,
            }
        )
        print(
            f"  {attempt['case_ref']:16} judge={v.get('state'):18} "
            f"oracle_hit={bool(outcome.oracle_signal.get('hit'))} integrity_ok={outcome.integrity_ok}",
            flush=True,
        )

    finished = datetime.now(UTC).isoformat()
    from collections import Counter

    states = Counter(r.get("verdict_state") for r in rows if "verdict_state" in r)
    summary = {
        "run_id": coordinator.run_id,
        "campaign_run_id": CAMPAIGN_RUN_ID,
        "target": f"https://{HOST}",
        "surface": "/chat (copilot_chat)",
        "operation_hash": op_hash,
        "corpus_id": CORPUS_ID,
        "corpus_sha": corpus_sha,
        "canary": CANARY,
        "finished_utc": finished,
        "cases": rows,
        "verdict_counts": dict(states),
        "exploit_confirmed": states.get("EXPLOIT_CONFIRMED", 0),
        "pending_human_approvals": len(coordinator.pending_approvals),
        "manifests_dir": str((OUT / "manifests").relative_to(ROOT)),
        "agents_exercised": {
            "red_team": "seed_replay corpus-replay-v1 (authored M11 corpus -> attack_attempt)",
            "policy_gateway": "budget/rate/timeout/abort + allowlist + sequential turn delivery",
            "recorder": "append to Postgres + re-read + content_hash verify",
            "judge": "oracle-precedence-v1 (deterministic; independent) -> Verdict",
            "documentation": "renders ONLY confirmed findings; 0 confirmed -> nothing to draft",
        },
        "provenance": "human-approved (approver != launcher); credentials by reference; synthetic-only",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(
        f"\nSUMMARY  verdicts={dict(states)}  exploit_confirmed={summary['exploit_confirmed']}  "
        f"pending_approvals={summary['pending_human_approvals']}",
        flush=True,
    )
    print(f"  manifests -> {OUT / 'manifests'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
