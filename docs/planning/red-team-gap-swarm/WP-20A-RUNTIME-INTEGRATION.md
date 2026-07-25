# WP-20A — Integrate runtime dispatch, evidence, and regression

**Branch:** `rtg/wp20a-runtime-integration`

**Model:** capable

**Depends on:** WP-19B

**Implements toward (live validation pending):** runtime portions of RT-01–RT-14

Integrate landed public interfaces; do not duplicate domain logic or change their frozen
contracts.

**Implementation writes only**

- `src/agentforge/runner.py`
- `src/agentforge/campaign/coordinator.py`
- `src/agentforge/readiness.py`
- `src/agentforge/security_tools/workbench.py`
- `src/agentforge/security_tools/catalog.py`

**Test writes only**

- `tests/test_red_team_runtime_integration.py`
- `tests/test_red_team_process_egress_integration.py`

## Required result

Compose the authoritative runtime path: exact plan/authorization/lease → ownership →
resolve/pin → fresh physical permit/final caps → constrained send/delivery certainty →
role-scoped Recorder → authenticated observations/required-oracle policy/ledger
reconciliation → independent Judge → evidence stages → fresh regression execution.

Connect separate generation/target brokers, reviewed bundle handoff, exact target/platform
surfaces, workbench/fuzz/scanner/OAST/browser plans, process egress, aborts, cost/rate
accounting, quarantine, and lease recovery. No tool or UI object receives a raw transport,
credential, authority-bearing DB engine, or alternate egress.

Tests exercise a complete no-network integration composition and races at every boundary,
including expected operation/permit/send/observation parity and duplicate-work prevention.
This is an `implementation_precheck` only. Injected adapters and local test records cannot
prove physical sends, deployed process isolation, authoritative observations, live
regression, or closure.

**Focused verifier**

```bash
python -m pytest tests/test_red_team_runtime_integration.py tests/test_red_team_process_egress_integration.py tests/test_runner_campaign.py tests/test_runner_lease_recovery.py -q
```

No network, target, provider, native tool/browser/ZAP process, deployment, or publication.
All runtime capabilities remain `LIVE_EVIDENCE_REQUIRED` for WP-21B–E.

**Handoff:** WP-20 final integration routes runtime defects back here.
