#!/usr/bin/env python3
"""Re-probe the timed-out cases from the live campaign with a longer timeout, then merge.

Completes coverage: any probe whose first pass errored (e.g. a 30s ReadTimeout) is re-sent once
with a 60s timeout at the same 1 req/2s cap, and its row is merged back into the campaign
artifacts (responses/envelopes/verdicts) with a regenerated summary. Credential handling and the
final scrub are identical to ``live_campaign.py``. Reads ``TARGET_SESSION_SID`` from os.environ only.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from live_campaign import (  # noqa: E402
    BASE_URL, CORPUS, OUT_DIR, RELATIVE_PATH, RUN_ID, allowlist_guard, build_envelope, run_oracles,
)

from agentforge.agents.judge.judge import Judge  # noqa: E402
from agentforge.contracts import is_valid  # noqa: E402
from agentforge.secrets import Secret  # noqa: E402
from agentforge.target.base import (  # noqa: E402
    AdapterError, RateLimitedError, TargetRequest, TargetSessionExpiredError, TargetUnreachableError,
)
from agentforge.target.openemr_adapter import OpenEmrAdapter  # noqa: E402

RETRY_TIMEOUT = 60.0
CORPUS_BY_ID = {p["id"]: p for p in CORPUS}


def main() -> int:
    raw_sid = os.environ.get("TARGET_SESSION_SID")
    if not raw_sid:
        print("BLOCKED: TARGET_SESSION_SID not set", file=sys.stderr)
        return 5

    rows = [json.loads(l) for l in (OUT_DIR / "responses.jsonl").read_text().splitlines() if l.strip()]
    by_id = {r["id"]: r for r in rows}
    retry_ids = [r["id"] for r in rows if r["http_status"] is None or r["error"]]
    if not retry_ids:
        print("nothing to retry")
        return 0
    print(f"RETRY {len(retry_ids)} timed-out probes with timeout={RETRY_TIMEOUT}s: {retry_ids}")

    judge = Judge()
    adapter = OpenEmrAdapter(
        base_url=BASE_URL, payload_profile="copilot_chat", relative_path=RELATIVE_PATH,
        credential=Secret(raw_sid), destination_validator=allowlist_guard, timeout_seconds=RETRY_TIMEOUT,
    )
    envelopes = {e_id: None for e_id in retry_ids}
    try:
        for i, pid in enumerate(retry_ids):
            if i:
                time.sleep(2.0)
            probe = CORPUS_BY_ID[pid]
            status, raw_text, error = None, "", None
            try:
                resp = adapter.send(TargetRequest(turns=(probe["prompt"],),
                                                  metadata={"attempt_id": pid, "synthetic": "true", "retry": "true"}))
                status, raw_text = resp.status, resp.output
            except RateLimitedError as exc:
                error = f"rate_limited:{exc}"; time.sleep(5)
            except TargetSessionExpiredError as exc:
                print(f"ABORT session expired at {pid}: {exc}"); error = "session_expired"; break
            except (TargetUnreachableError, AdapterError) as exc:
                error = f"{exc.__class__.__name__}:{exc}"
            try:
                parsed = json.loads(raw_text) if raw_text else {}
                if not isinstance(parsed, dict):
                    parsed = {"_nonobject": parsed}
            except (json.JSONDecodeError, TypeError):
                parsed = {"_raw": raw_text[:2000]}
            oracles, canaries, policy = run_oracles(probe, parsed, raw_text, raw_sid)
            env = build_envelope(probe, parsed, raw_text, oracles, canaries, policy)
            verdict = judge.evaluate(env) if is_valid("evidence_envelope", env) else {"state": "ERROR"}
            any_hit = any(o["hit"] for o in oracles) or any(c["hit"] for c in canaries)
            by_id[pid].update(dict(
                http_status=status, error=error, policy_decision=policy,
                source=parsed.get("source"), verdicts=parsed.get("verdicts"),
                brief=parsed.get("brief"), correlation_id=parsed.get("correlation_id"),
                oracle_results=oracles, canary_hits=canaries,
                judge_state=verdict.get("state"), judge_confidence=verdict.get("confidence"),
                exploit_signal=any_hit, raw_response=parsed, retried=True,
            ))
            envelopes[pid] = env
            print(f"  {pid:16} http={status} policy={policy:8} judge={verdict.get('state'):16} "
                  f"exploit_signal={any_hit} err={error}")
    finally:
        adapter.close()

    def scrub(obj):
        if isinstance(obj, str):
            return obj.replace(raw_sid, "***REDACTED_SESSION***") if raw_sid in obj else obj
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(v) for v in obj]
        return obj

    merged = [scrub(by_id[r["id"]]) for r in rows]
    (OUT_DIR / "responses.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in merged))

    # rebuild envelopes.jsonl (retried rows replaced; others rebuilt from stored data)
    env_rows = []
    for r in merged:
        if envelopes.get(r["id"]) is not None:
            env_rows.append(scrub(envelopes[r["id"]]))
        else:
            probe = CORPUS_BY_ID[r["id"]]
            env_rows.append(scrub(build_envelope(probe, r["raw_response"], "", r["oracle_results"],
                                                 r["canary_hits"], r["policy_decision"])))
    (OUT_DIR / "envelopes.jsonl").write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in env_rows))
    (OUT_DIR / "verdicts.jsonl").write_text("".join(
        json.dumps(dict(attempt_id=r["id"], state=r["judge_state"], confidence=r["judge_confidence"]),
                   ensure_ascii=False) + "\n" for r in merged))

    by_cat = {}
    for r in merged:
        c = by_cat.setdefault(r["category"], {"tested": 0, "responded": 0, "exploit_signals": 0, "refused": 0,
                                              "timed_out": 0, "probe_ids": []})
        c["tested"] += 1
        c["responded"] += 1 if r["http_status"] == 200 else 0
        c["timed_out"] += 1 if (r["http_status"] is None or r["error"]) else 0
        c["exploit_signals"] += 1 if r["exploit_signal"] else 0
        c["refused"] += 1 if r["policy_decision"] == "refused" else 0
        c["probe_ids"].append(r["id"])
    summary = json.loads((OUT_DIR / "summary.json").read_text())
    summary.update(dict(
        finished_retry=datetime.now(timezone.utc).isoformat(),
        exploit_confirmed_ids=[r["id"] for r in merged if r["judge_state"] == "EXPLOIT_CONFIRMED"],
        exploit_signal_ids=[r["id"] for r in merged if r["exploit_signal"]],
        indeterminate=sum(1 for r in merged if r["judge_state"] == "INDETERMINATE"),
        responded=sum(1 for r in merged if r["http_status"] == 200),
        timed_out=sum(1 for r in merged if (r["http_status"] is None or r["error"])),
        by_category=by_cat,
    ))
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    leaked = [p.name for p in OUT_DIR.glob("*") if raw_sid in p.read_text(errors="ignore")]
    if leaked:
        print(f"FATAL credential in {leaked}", file=sys.stderr); return 6
    print(f"\nMERGED  responded={summary['responded']}/{summary['total_probes']}  "
          f"timed_out={summary['timed_out']}  exploit_confirmed={len(summary['exploit_confirmed_ids'])}  "
          f"exploit_signals={len(summary['exploit_signal_ids'])}")
    print("credential scrub: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
