# WP-20 — Integrate the complete governed red-team platform

**Branch:** `rtg/wp20-end-to-end-integration`

**Model:** capable

**Depends on:** WP-20A, WP-20B, WP-20C

**Implements toward (live validation pending):** integration portions of RT-01–RT-14

This is the narrow final composition and verification package. Runtime, backend, and
console/report work has already landed independently. Do not repair those lanes here:
route a failing invariant back to WP-20A, WP-20B, or WP-20C.

**Implementation writes only**

- `src/agentforge/integration.py`
- `src/agentforge/app.py`
- `docs/integration/INTEGRATION_PACKET.md`

**Test writes only**

- `tests/test_red_team_gap_integration.py`
- `tests/test_red_team_process_boundary.py`
- `console/tests/browser/red-team-integration.spec.ts`

## Required result

Wire one authoritative flow:

persisted plan/authorization + active lease/abort/scope → WP-08 ownership and exact-surface
verification → WP-03 resolve/validate/pin with no request body → WP-01 fresh persisted
permit plus final caps and ownership revalidation → constrained connect/TLS/write with no
second DNS path → WP-04 delivery certainty → WP-02 role-scoped Recorder → WP-11
observations/required-oracle policy and send-ledger reconciliation → independent Judge →
WP-10 coverage stages → documentation/human gates → WP-19 regression.

Integrate:

- full-spectrum WP-14 manifest loading;
- WP-15 reviewed candidate-bundle lifecycle;
- WP-13 separate generation/target brokers and WP-13E proposed tool bundles;
- WP-13F static/CI tool artifacts;
- WP-12 exact surfaces;
- WP-16A captures/templates/replay/diffs;
- WP-16B fuzz/minimization/decoder/token analysis;
- WP-16C declarative checks/search/investigations;
- WP-16D governed native-process egress;
- WP-17 API manifests/principal matrices/ZAP plans;
- WP-18A OAST deployment state/evidence;
- WP-18B streaming/browser plans;
- WP-18C owner-gated OAST deployment state;
- WP-19 replay execution and reappearance;
- WP-19A evidence-bound report drafts;
- WP-19B packaged contract manifest.

Human commands create immutable plans, annotations, authorization requests, aborts, and
approval decisions. There is no direct “send raw request,” “scan now,” or “run anyway”
endpoint. Execution begins through exact-scope authorization with distinct launcher/
approver enforcement.

Verify the WP-20B API and WP-20C UI show mapped/authored/executable/authorized/dispatched/
live/oracle/decisive/regressed states separately; sanitized projections with protected
fields locked; literal diffs; computed fuzz caps; API/principal/scanner/OAST/stream/browser
states; and regression/report evidence. They must never render adversarial text as trusted
HTML/Markdown or let client state establish authority.

Correct labels:

- Proxy and Repeater remain `governed_analogue`/`partial`; raw bidirectional MITM,
  response editing, CA/invisible proxying, and arbitrary-message replay are unsupported;
- Intruder/Comparer/Decoder/Sequencer are operational only when their literal WP-16
  behavior is reachable and evidenced;
- active ZAP, OAST, browser, streaming, and real surfaces remain `blocked`/`partial` without
  execution evidence;
- conversation ordering is not “Sequencer”;
- advisory tool output is not Judge coverage.

Tests exercise the entire no-network composition with injected adapters and assert expected
send/ledger/observation relationships, abort races, cross-org denial, hostile UI output,
all blocker states, no alternate egress, role isolation, regression planning, contract
registry/package lookup, report claim/evidence parity, and local process-interface behavior.
These results are `implementation_precheck` only. They cannot prove a physical target send,
deployed process isolation, trusted live observation, live regression, or finding closure.

**Focused verifier**

```bash
python -m pytest tests/test_red_team_gap_integration.py tests/test_red_team_process_boundary.py tests/auth/test_red_team_gap_api.py -q
cd console && npm test -- red-team-workbench.test.tsx red-team-reporting.test.tsx
cd console && npm run test:browser -- red-team-integration.spec.ts
```

Then run `bash scripts/check.sh`, all console gates, migration tests, secret scan, wheel/
container verification where available, and `git diff --check`.

No network, target, provider, ZAP/browser process, deployment, publication, push, or main
merge. The entire integrated release remains `LIVE_EVIDENCE_REQUIRED` until WP-21A–E
produce independently approved live evidence.
