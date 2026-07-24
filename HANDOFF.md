# Console / final-target remediation handoff

## Frozen handoff

- Branch: `codex1/console-remediation-handoff`
- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-console-remediation-handoff`
- Base before this lane was merged: `bf13f6f813f047011bbfacec617edd737838166f`
- Canonical requirements: `Week_3_AgentForge.pdf`
- Primary plans:
  - `docs/planning/final-target-adapters.md`
  - `docs/planning/agent-runtime-provenance.md`
  - `docs/planning/console-pages-remediation.md`
  - `docs/planning/full-console-remediation.md`

This branch deliberately does not include or stage the uncommitted files in
`/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine`. That shared worktree belongs to other
lanes and was dirty when this handoff was frozen.

No deployment, production migration, live tool run, 100-case campaign, finding publication, or
remediation was performed by this lane.

## High-level state

| Area | State | Evidence / next gate |
|---|---|---|
| T-F16a surface-policy contract | **Closed in this lane** | Final accepted commit `cda81d87a3ff44bceb66492588c37c5ee033b50a`; 1,228 backend tests passed, 3 skipped; independent code/security PASS. |
| T-F16b retry-inclusive gateway | **WIP — RED candidate, not frozen** | Candidate `dc7232f7ba793eebc4804425400a5a115095448b`; 51 intentional RED + 1 inherited pass; test SHA `1db1a755e8616ffd780e8fcfc75d3d4860839919df0405ebf9eb267cf9350eaf`, blob `8535b226c98505eb1b6c2edbe56c40b6ab4dd155`. Needs independent final test review/freeze, then GREEN. |
| T-F17a package-owned prompts | **Closed in this lane** | Final review commit `a2bee39935131b9524e08bd6a509bb89cfe9a150`; 8 focused and 1,132 offline-compatible tests passed; 60/60 secret/session/provider probes rejected generically. |
| T-F17b provider-call lineage | **WIP GREEN, not integration-ready** | Implementation commit `c29b73ab92dc94c017a8951bc3dab76f23e94604`; frozen test SHA `717ec3e316becc39bf3d5f02cdd1ad6970c3cc6c1f54815b23fa05b20afa8f8b`, blob `a4f2e3964771a80b5da6bb34fdf7860e2e0a3838`. Tests pass 29/29 only in isolated databases; normal run has 16 fixture-collision failures because `migrated_db` is session-scoped while tests reuse primary keys. Requires formal fixture repair/re-freeze and final review. |
| T-F18a console navigation | **Provisional design only** | Branch `ticket/T-F18a-canonical-console-navigation`, commit `cbb2d21bbfba9dab21acf2533938a6da38854e3b`; preserved under `handoff/patches/T-F18a/`. Do not implement before T-F16f + T-F17f + T-F19e integration. |
| Remaining console/tooling plan | **Planned, open** | T-F18b–p and T-F19a–f tickets/prompts are present. None is implemented by this handoff. |
| Railway production | **Not promoted** | Last verified lane state had Web/Runner deployed from an older release and configured as staging. Production catalog/release/grants must migrate atomically. |
| Live page audit | **Source audit complete; authenticated browser audit blocked** | Production browser remained at `/sign-in`; no Headshot authenticated page-by-page pass was possible. |
| Full tools / 100-case report | **Not run** | The existing partial nine-case run was inadequate and all verdicts were indeterminate. T-F19f remains the separately authorized final run. |

## File-by-file status

### Accepted production work

| File | Status |
|---|---|
| `src/agentforge/target/spec.py` | **Done (T-F16a):** immutable schema-v2 per-surface policy, exact document operation budgets, scope binding, canonical hashes. |
| `src/agentforge/target/catalog.py` | **Done (T-F16a):** fail-closed v2 catalog policy and exact lab `34/67` / intake `2/2` contracts. The handoff merge kept the stricter per-surface-policy rule when resolving one conflict. |
| `src/agentforge/target/registry.py` | **Done (T-F16a):** v2 targets cannot fall back to target-level auth through a policyless surface. |
| `src/agentforge/control_plane/serialization.py` | **Done (T-F16a):** exact policy encode/decode and hash-preserving scope serialization. |
| `src/agentforge/agents/prompts/__init__.py` | **Done (T-F17a):** immutable `importlib.resources` prompt authority, generic validation errors, exact identity lookup, bounded secret-shape rejection. |
| `src/agentforge/agents/prompts/registry.v1.json` | **Done (T-F17a):** exact manifest for four locked role prompts. |
| `src/agentforge/agents/prompts/v1/{orchestrator,red_team,judge,documentation}.txt` | **Done (T-F17a):** role-specific trust boundaries; raw bytes are the authority. |
| `pyproject.toml` | **Done for T-F17a:** packages prompt manifest and text resources. Reconcile with newer shared-branch dependency/package-data changes before integration. |

### WIP production work

| File | Status |
|---|---|
| `src/agentforge/providers/lineage.py` | **WIP GREEN (T-F17b):** provider logical context, pre-call invocation, terminal event and cost-state contracts. |
| `migrations/versions/0016_provider_call_lineage.py` | **WIP GREEN (T-F17b):** additive invocation/event tables, composite ownership, append-only grants and cost semantics. Migration numbering must be reconciled with newer shared migrations before merge. |
| `src/agentforge/control_plane/store.py` | **WIP GREEN (T-F17b):** begin/finish/reconcile/list provider-call operations. This overlaps active shared-lane changes; merge manually. |
| `src/agentforge/storage/models.py` | **WIP GREEN (T-F17b):** lineage table metadata and constraints. This overlaps active shared-lane changes; merge manually. |
| `docs/integration/migrations/provider-call-lineage-v1.md` | **Done as migration design; implementation remains WIP** because of the frozen fixture issue. |

### Tests and TDD evidence

| File | Status |
|---|---|
| `tests/test_final_target_surface_policy.py` | **Frozen/green (T-F16a).** |
| `.tdd-swarm/reports/T-F16a-*` | **Final PASS evidence.** |
| `tests/test_surface_operation_gateway.py` | **WIP RED candidate (T-F16b), not frozen.** Independent final review is the next action. |
| `.tdd-swarm/reports/T-F16b-test*.md` | **Current RED design/review record.** No GREEN implementation report exists. |
| `tests/test_agent_prompts.py` | **Frozen/green (T-F17a).** |
| T-F17a additions in `tests/test_packaging.py` | **Frozen/green.** |
| `.tdd-swarm/reports/T-F17a-*` | **Final PASS evidence.** |
| `tests/test_provider_call_lineage.py` | **Frozen contract, product passes only with isolated database per case.** Do not silently edit it; formally repair/re-review the fixture scope. |
| `.tdd-swarm/reports/T-F17b-*` | **Test freeze + WIP implementation evidence.** Formal code/security review reports were not committed after the implementation. |

### Plans, prompts and execution manifest

| Files | Status |
|---|---|
| `docs/planning/final-target-adapters.md`, `tickets/T-F16a..h.md`, corresponding `.tdd-swarm/prompts/` | **Reviewed plan.** |
| `docs/planning/agent-runtime-provenance.md`, `tickets/T-F17a..f.md`, `tickets/T-F18j.md`, corresponding prompts | **Reviewed plan.** |
| `docs/planning/console-pages-remediation.md`, `tickets/T-F18a..p.md`, `tickets/T-F19a..f.md`, corresponding prompts | **Reviewed plan.** |
| `handoff/patches/T-F18a/` | **Exact provisional T-F18a RED/review patch series.** Preserve but do not apply until dependencies exist. |
| `scripts/release-audit/legacy-1ac3ee0/` | **Archived:** five exact scripts moved out of the temporary worktree. Not current production authority. |
| `handoff/patches/release-lint/` | **Archived:** exact two-commit release-lint series, including non-script formatting changes. |

## Execution waves and ticket state

Ticket frontmatter still says `status: backlog`; the state below is the evidence-backed lane status,
not a rewrite of ticket metadata.

| Wave | Ticket(s) | State at stop |
|---|---|---|
| 17 | T-F16a | **Closed/PASS.** |
| 18 | T-F16b | **WIP RED; candidate repaired, not frozen.** |
| 19 | T-F16c, T-F16d | **Open; blocked on accepted T-F16b GREEN.** |
| 20 | T-F16e | **Open; depends on T-F16c/d plus earlier owners.** |
| 21 | T-F16f | **Open; real parent/eight-child authorized multi-surface scan.** |
| 22 | T-F16g | **Open; signed read-only deployment observation/preflight.** |
| 23 | T-F16h | **Open; deploy and live verification.** |
| 26 | T-F17a, T-F17b | **T-F17a closed; T-F17b WIP GREEN with fixture blocker.** |
| 27 | T-F17c | **Open; binds prompt system messages to physical lineage.** |
| 28 | T-F17d | **Open; hosted Runner path, depends on T-F16f.** |
| 29 | T-F18j | **Open; canonical cost-state consumers.** |
| 30 | T-F17e | **Open; production promotion gate.** |
| 31 | T-F17f | **Open; authenticated provider/prompt lineage API.** |
| 32–36 | T-F19a–e | **Open; governed full-tool plans/brokers/evidence.** |
| 37–50 | T-F18a–p | **Open; T-F18a only provisional and not frozen.** |
| 51 | T-F19f | **Open; separately authorized 100-case + full-tool run/report.** |

## Console/source audit outcome

None of the ten current console routes met the strict “fully live and evidence-backed” bar.
Most read PostgreSQL projections, but the accepted WP-10 and WP-20A/B/C workflows are absent.

Highest-priority findings for the next agent:

1. **P0 auth shell:** `src/agentforge/web.py` still has a public SPA catch-all; unknown/protected
   HTML routes must 404 under the closed public allowlist.
2. **P0 coverage/resilience:** `/coverage` and `/resilience` silently normalize to Live. Removing
   the standalone Resilience page is correct, but the requirements are not preserved. Implement
   evidence-stage coverage and approved exact-version regression replay, then expose them
   discoverably (the reviewed plan calls this “Coverage & Regression”).
3. **P0 tool execution:** Tooling is a static catalog plus loose counts. Implement immutable
   target-bound plans, applicability review, governed brokers, per-tool events/artifacts and the
   real “run every applicable tool” launch path.
4. **P0 human gates:** finding triage is not report publication, remediation approval or regression
   admission. Add distinct hash-bound decisions and permissions.
5. **P1 Agents:** configured model is distinct from provider-served model. T-F17a is ready;
   complete T-F17b/c/f before presenting actual model/upstream/request/cost and prompt content.
6. **P1 paging/accessibility:** no cursor paging; direct entity routes depend on bounded list
   windows; selectable rows/mobile navigation need keyboard/focus fixes.

The full source audit referenced these primary files:

- `console/src/App.tsx`
- `console/src/router.ts`
- `console/src/screens/ConsoleScreens.tsx`
- `console/src/screens/AgentToolScreens.tsx`
- `console/src/screens/ObservabilityScreens.tsx`
- `src/agentforge/api/postgres.py`
- `src/agentforge/api/birdseye.py`
- `src/agentforge/api/router.py`
- `src/agentforge/web.py`

## Exact next steps

1. Start in this handoff worktree and verify it is clean. Do not use or stage the dirty shared
   worktree.
2. Independently review T-F16b candidate `dc7232f...`; if PASS, freeze its exact test hash/blob.
   Then implement T-F16b, run full gates, and obtain independent code/security PASS.
3. Repair the T-F17b test infrastructure formally: make the disposable database function-scoped
   or clean reused synthetic primary keys, update/re-review the frozen contract, then rerun the
   normal suite. Do not claim the isolated 29/29 result alone as final acceptance.
4. Rebase/merge T-F16a, T-F17a and the accepted T-F17b result onto the newest clean shared
   integration commit. Resolve `store.py`, `storage/models.py`, migration numbering, `pyproject`,
   and hosted-runtime overlaps explicitly.
5. Implement T-F16c and T-F16d in parallel after T-F16b; serialize T-F16e → T-F16f → T-F16g →
   T-F16h. Keep document surfaces disabled unless the private Runner proves the exact fixture
   binding with zero target calls.
6. Complete T-F17c, then T-F17d/T-F18j/T-F17e/T-F17f in dependency order. The four locked models
   remain:
   - Orchestrator: `anthropic/claude-opus-4.8`
   - Red Team: `qwen/qwen3.5-397b-a17b`
   - Judge: `google/gemini-2.5-pro`
   - Documentation: `openai/gpt-5.4`
7. Complete T-F19a–e before console page implementation. Only then freeze/apply T-F18a and execute
   the rest of T-F18.
8. Run backend/console/security/migration/contract gates, push the same release to both remotes,
   require both CI systems green, then deploy Runner before Web with signed environment-specific
   grants and fresh observations.
9. Complete the authenticated live page-by-page audit. The existing production tab was still at
   `/sign-in` when work stopped.
10. Execute T-F19f only after all gates: one worker, exact approved caps/rate, no disabled-document
    claims, 100 cases, all applicable tools, durable evidence, independent Judge, and a legitimate
    report. Do not relabel the prior nine indeterminate cases as the baseline.

## Decisions and blockers

- Keep standalone Resilience removed, but do not remove the resilience requirement.
- Coverage and Tooling are not interchangeable: Tooling is execution truth; Coverage/Regression
  is requirement/evidence-stage and replay truth.
- A user-launched scan must use every **authorized and applicable** tool/surface. “All” never
  overrides target allowlists, child approvals, fixture proof, rate/cost/time caps or abort gates.
- Requested/configured provider identity is not observed provider identity.
- Unknown cost is `NULL/not_observed`, never zero and never tokens multiplied by a price.
- Production document execution remains blocked unless private fixture binding is mechanically
  proven. Do not upload or commit the extracted credential bundle.
- The shared integration worktree was actively modified by other lanes. Do not reset, checkout,
  stage, clean or overwrite it.

## Closure ownership: T-F00 through T-F10c

Every listed ticket still has `status: backlog` in its frontmatter. This lane did not change or
claim closure for any T-F00–T-F10c owner. Use their own accepted test/review/release evidence, not
the presence of code on the shared branch.

| Owner(s) | Closure responsibility | State recorded here |
|---|---|---|
| T-F00 | Mechanical swarm/spec/security gates | Backlog metadata; external lane. |
| T-F01a / T-F01b | Sanitized export / final reconciliation | Backlog metadata; external lane. |
| T-F02 | Package-authority root contracts | Backlog metadata; external lane. |
| T-F03a / T-F03b | Judge code / authorized calibration evidence | Backlog metadata; external lane. |
| T-F04a / T-F04b | Red Team controls / authorized provider eval | Backlog metadata; external lane. |
| T-F04c–T-F04h | Hosted configuration, authority preflight, transport and smoke | Backlog metadata; external lane. |
| T-F05a | Durable release lineage | Backlog metadata; external lane. |
| T-F05b / T-F05c | Live campaign / preflight consumers | Backlog metadata; external lane. |
| T-F05d | Authorized target/session/patient evidence | Backlog metadata; external lane. |
| T-F05e | Immutable SMART context / validator | Backlog metadata; external lane. |
| T-F05f | Runner post-claim/per-attempt enforcement | Backlog metadata; external lane. |
| T-F05g | Zero-overlap config and full-chain verifier | Backlog metadata; external lane. |
| T-F05h | Signed deployment observation | Backlog metadata; external lane. |
| T-F05i | Authenticated control-state projection | Backlog metadata; external lane. |
| T-F05j | Config/reference/job persistence | Backlog metadata; external lane. |
| T-F05k | Fixed-path secure context load/pin | Backlog metadata; external lane. |
| T-F05l | Authenticated controller observation acquisition | Backlog metadata; external lane. |
| T-F05m | Non-cached runtime state provider | Backlog metadata; external lane. |
| T-F05n | Signed activation and rotation evidence | Backlog metadata; external lane. |
| T-F05o | Bounded predecessor campaign/job history | Backlog metadata; external lane. |
| T-F05p | Secret-free two-target catalog and Web/Runner parity | Backlog metadata; external lane. |
| T-F06a / T-F06b | Regression replay code / evidence | Backlog metadata; external lane. |
| T-F07a / T-F07b | Benchmark / authorized live stress | Backlog metadata; external lane. |
| T-F08 | Cost analysis | Backlog metadata; external lane. |
| T-F09a / T-F09b | ATO packet / drills | Backlog metadata; external lane. |
| T-F10a / T-F10b / T-F10c | Release / reports / final submission | Backlog metadata; external lane. |

## Preserved branch references

- `ticket/T-F16a-surface-policy-contract` → `cda81d87a3ff44bceb66492588c37c5ee033b50a`
- `ticket/T-F16b-physical-operation-gateway` → `dc7232f7ba793eebc4804425400a5a115095448b`
- `ticket/T-F17a-hosted-role-prompt-contract` → `a2bee39935131b9524e08bd6a509bb89cfe9a150`
- `ticket/T-F17b-provider-call-lineage` → `c29b73ab92dc94c017a8951bc3dab76f23e94604`
- `ticket/T-F18a-canonical-console-navigation` → `cbb2d21bbfba9dab21acf2533938a6da38854e3b`
- `codex/release-lint-fix-1ac3ee0` → `2187fbf6d5a0561cdf630978477d837299558113`

Stop reason: the user explicitly requested a clean freeze and handoff before further work.
