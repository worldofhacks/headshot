# WP-20B — Integrate authenticated backend APIs and read models

**Branch:** `rtg/wp20b-backend-api-integration`

**Model:** capable

**Depends on:** WP-19B

**Implements toward (live validation pending):** backend portions of RT-01–RT-14

Use the frozen contract manifest and landed domain services. Do not reimplement policy,
Judge, scanner, workbench, or reporting decisions in route handlers.

**Implementation writes only**

- `src/agentforge/app.py`
- `src/agentforge/api/backend.py`
- `src/agentforge/api/router.py`
- `src/agentforge/api/postgres.py`
- `src/agentforge/api/read_models.py`
- `src/agentforge/api/schemas.py`

**Test writes only**

- `tests/auth/test_red_team_gap_api.py`
- `tests/api/test_red_team_gap_read_models.py`

## Required result

Expose backend-verified Headshot organization/custom-permission APIs for immutable plans,
review requests/decisions, aborts, annotations, evidence stages, tool/process states,
investigations, regressions, and report drafts. Reads are organization-scoped and status-
honest. Writes call domain services and never dispatch directly.

There is no raw-send, raw-proxy, scan-now, run-anyway, arbitrary-code, evidence mutation,
verdict override, publication bypass, or client-authoritative endpoint. Enforce distinct
launcher/approver/reviewer identities, idempotency, CSRF/origin/session rules, bounds,
content types, hostile-string sanitation, and generic failures.

Tests cover every permission/object/action edge, cross-org IDs, stale hashes, mass
assignment, confused deputy, pagination/resource limits, hostile rendering fields, and
zero target/provider/process constructors from API handlers.

Expose `implementation_precheck` separately from `approved_live_evidence`. API projections
must never promote local tests, fixture/cassette artifacts, simulated records, or adapter
presence into live/operational/regressed/closed status.

**Focused verifier**

```bash
python -m pytest tests/auth/test_red_team_gap_api.py tests/api/test_red_team_gap_read_models.py tests/auth -q
```

No network, Clerk mutation, target/provider call, deployment, publication, push, or merge.
Live Clerk/API/read-model behavior remains `LIVE_EVIDENCE_REQUIRED` for WP-21B–E.

**Handoff:** WP-20 final integration routes API defects back here.
