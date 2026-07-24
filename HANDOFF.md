# Console / final-target remediation handoff

## Frozen handoff

- Branch: `codex1/console-remediation-handoff`
- Worktree: `/Users/quietguy/Documents/Dev/Gauntlet/wt-console-remediation-handoff`
- Base before this lane was merged: `bf13f6f813f047011bbfacec617edd737838166f`
- Shared integration merged in: `12eb13e` then `723be15..9f5721b`
- Canonical requirements: `Week_3_AgentForge.pdf`
- Primary plans:
  - `docs/planning/final-target-adapters.md`
  - `docs/planning/agent-runtime-provenance.md`
  - `docs/planning/console-pages-remediation.md`
  - `docs/planning/full-console-remediation.md`

This branch deliberately does not include or stage the uncommitted files in
`/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine`. That shared worktree belongs to other
lanes and is actively being written to — its `git status` changed on every inspection. Only
committed shared refs were merged; nothing there was modified, staged, or cleaned.

No deployment, production migration, live tool run, 100-case campaign, finding publication, or
remediation was performed by this lane.

## Integration session — what changed since the first freeze

**A silent breakage was found and repaired.** The earlier merge `c728870` brought the T-F17b ticket
branch onto the lane. That branch had been cut from a base predating `0016_agent_langfuse_delivery`,
so the merge produced **two alembic revisions both named `0016`**. Git reported no conflict because
the filenames differ. The consequences were severe and unnoticed:

- `alembic upgrade head` failed with `MultipleHeads`, so the session-scoped `migrated_db` fixture
  errored during setup and **every DB-backed test in the suite errored** — not the 16 failures the
  first freeze reported.
- `readiness.expected_alembic_head()` raises when there is not exactly one head, so **`GET /ready`
  would have failed closed** on any deploy carrying the lane.
- Therefore **none of the first freeze's test evidence described the merged lane**. The "29/29" and
  "16 fixture collisions" were both measured on the pre-merge ticket branch `c29b73a`, where the
  lineage migration was the sole head.

Repaired by renumbering to `0018_provider_call_lineage` with `down_revision = "0017"`. Single head
restored; the full chain applies cleanly to a fresh database.

**The two lineages were reconciled, not chosen between.** They are complementary rather than
duplicative, so the resolution is a dependency stack, not a selection:

- `agent_executions` (shared `0017`) is the **logical** execution record — hosted identity,
  configuration/prompt authority hashes, and Judge calibration/reconciliation.
- `provider_call_invocations` / `provider_call_events` (`0018`) is the **append-only physical**
  per-attempt record, with pre-call reservation, `physical_sequence`, idempotency key, and an
  eight-value physical status vocabulary.

One cost semantic now spans both. `measured_cost` is `NUMERIC(20, 12) NULL` — precision from `0017`,
nullability from `0018` — and `cost_measurement_state` is its provenance.

**Two live invariant violations were fixed.**

1. `store.py`'s hosted finish path defaulted an unobserved cost to `Decimal("0")` and never set
   `cost_measurement_state`, so a real cost was written against a `not_observed` default. An
   unobserved cost is now `NULL`/`not_observed`; an observed one is `measured`.
2. Both cost columns and `ProviderTerminalEventV1` were six-decimal. A routine OpenRouter charge of
   `0.0000391` was **rejected outright** as "exceeds storage precision", and anything below a
   microdollar rounded to `0.000000` — a fabricated zero. Sub-microdollar per-call charges are
   ordinary on the cheaper roles (Red Team qwen is $0.39/M input). Now twelve places throughout,
   with a regression case.

**Verified state of the lane now:**

| Gate | Result |
|---|---|
| Backend suite (normal full run) | `1,697` collected, `51` failed — **all** the intentional T-F16b RED |
| `tests/test_provider_call_lineage.py` | `33/33` in the normal run (was 16 failing), not in isolation |
| Alembic | single head `0018`; full chain applies to a fresh database |
| `ruff check` / `ruff format --check` | clean |
| Console `tsc --noEmit` | clean |
| Console `vitest run` | `16` files, `116` tests passed |
| Console forbidden-language gate | passed |

**Correction to the previous handoff's premise.** There is no uncommitted "reports / approver
enrichment" in the shared worktree. That work is **committed** in `12eb13e` and is now merged into
this lane. What is genuinely uncommitted there is Coverage & Regression console work plus provider
unresolved-accounting enrichment — owned by another lane, left untouched.

**Locked models are confirmed live.** All four slugs resolve and are served on OpenRouter, verified
against raw JSON rather than a summarizer: `anthropic/claude-opus-4.8` (7 endpoints),
`qwen/qwen3.5-397b-a17b` (11 endpoints, 10 healthy), `google/gemini-2.5-pro` (8),
`openai/gpt-5.4` (5). All advertise structured outputs. `HOSTED_ROLE_MODELS`
(`src/agentforge/agents/hosted.py:31-36`) already carries all four exactly — the deepseek
divergence in production code was already reconciled. **No escalation is needed; qwen is safe to
wire.** One residual `deepseek/deepseek-chat` remains as an arbitrary pass-through fixture at
`tests/test_red_team_hosted_generation.py:32`; it asserts config plumbing, not the locked roster.

> Caution for anyone running tests here: the lane worktree has **no `.venv`**. The only interpreter
> on PATH belongs to the shared worktree and its editable install points at
> `Adversarial Machine/src`. `pytest` and `alembic` are safe (`pyproject.toml` sets
> `pythonpath = ["src"]`, `alembic.ini` sets `prepend_sys_path = src`), but any bare
> `python -c "import agentforge"` silently loads the **shared** source. Never run
> `pip install -e` from this lane — it would repoint the shared venv and break every other lane.

## High-level state

| Area | State | Evidence / next gate |
|---|---|---|
| T-F16a surface-policy contract | **Closed in this lane** | Final accepted commit `cda81d87a3ff44bceb66492588c37c5ee033b50a`; 1,228 backend tests passed, 3 skipped; independent code/security PASS. |
| T-F16b retry-inclusive gateway | **RED FROZEN — implementation is the next action** | Independent review PASS; see `.tdd-swarm/reports/T-F16b-test-review-final.md`. Blob `8535b226c98505eb1b6c2edbe56c40b6ab4dd155` and SHA `1db1a755e8616ffd780e8fcfc75d3d4860839919df0405ebf9eb267cf9350eaf` re-verified byte-identical after both shared merges. 51 RED + 1 inherited pass, all failing on the single intended "operation-flow boundary is absent" assertion. Durable fixture pre-validated against a real migrated DB. No GREEN implementation exists yet. |
| T-F17a package-owned prompts | **Closed in this lane** | Final review commit `a2bee39935131b9524e08bd6a509bb89cfe9a150`; 8 focused and 1,132 offline-compatible tests passed; 60/60 secret/session/provider probes rejected generically. |
| T-F17b provider-call lineage | **GREEN in the normal suite; needs a final independent code/security review** | Fixture collision repaired with an autouse per-case TRUNCATE following the `tests/test_queue.py:50-57` convention, guarded on `request.fixturenames` so the eight no-DB cases still run without one. `33/33` in a normal full-suite run (29 original + 4 new precision cases), **not** in isolation. Cost precision widened to `NUMERIC(20, 12)` across both columns, the terminal-contract hash, and `ProviderTerminalEventV1`. The test contract changed, so it needs a **new freeze identity and an independent code/security review**, which this session did not produce. |
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
| 18 | T-F16b | **RED FROZEN and reviewed PASS; GREEN implementation not started.** |
| 19 | T-F16c, T-F16d | **Open; blocked on accepted T-F16b GREEN (still the gate).** |
| 20 | T-F16e | **Open; depends on T-F16c/d plus earlier owners.** |
| 21 | T-F16f | **Open; real parent/eight-child authorized multi-surface scan.** |
| 22 | T-F16g | **Open; signed read-only deployment observation/preflight.** |
| 23 | T-F16h | **Open; deploy and live verification.** |
| 26 | T-F17a, T-F17b | **T-F17a closed; T-F17b green in the normal suite, pending re-freeze + independent review.** |
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

Steps 1–4 of the previous list are **done** — see "Integration session" above. The alembic graph is
repaired, the shared integration is merged with overlaps resolved explicitly, T-F16b is reviewed and
frozen, and the T-F17b fixture is repaired and green in a normal run. Remaining work, in order:

1. **Implement T-F16b GREEN** against the frozen contract. The missing surface is exactly
   `SurfaceOperation` and `SurfaceOperationResponse` in `src/agentforge/target/base.py`, plus
   `OperationFlowAborted` and `PolicyGateway.execute_operation_flow` in
   `src/agentforge/policy/gateway.py`. Do not modify the frozen test module. Then run full gates and
   obtain an independent code/security PASS.
2. **Re-freeze T-F17b and review it.** The test contract changed (isolation fixture + precision
   cases), so record a new test SHA/blob and obtain the independent code/security review that was
   never committed for this ticket. While re-reviewing, settle one open design question: the
   `cost_measurement_state` column has a `'not_observed'` server default, so any writer that
   supplies a cost without also declaring provenance produces a constraint violation. Three fixtures
   have already hit this. Either drop the default so it fails loudly as a NOT NULL violation, or
   extend the existing `normalize_agent_execution_unknown_cost` trigger to derive `measured` from a
   non-NULL cost. This session fixed the call sites explicitly rather than deciding it mid-merge.
3. **Resolve the requested-vs-observed identity conflict** before wiring more provenance. Shared
   `0017`'s `agent_execution_provider_identity` asserts `returned_model IS NULL OR returned_model =
   model`, and `hosted_runtime.py:425-433` raises `HostedCompositionError` while `:478-495` returns
   `None` and discards the lineage when they differ. So a provider substitution is currently
   **unrepresentable and unrecorded**.

   The two layers verifiably disagree. Against a freshly migrated database:

   ```
   ck_agent_executions_agent_execution_provider_identity
     CHECK (... AND (returned_model IS NULL OR returned_model::text = model::text))
   provider_call_events status
     CHECK (status = ANY (ARRAY['succeeded','timeout','retryable_failure','terminal_failure',
                                'model_mismatch','invalid_usage','invalid_output','outcome_unknown']))
   ```

   The physical layer already models the divergence as a first-class terminal status; the logical
   layer forbids the row outright. That contradicts the locked invariant that requested identity
   is not observed identity, and for an evidence platform it discards exactly the evidence that
   matters. The physical lineage already models this correctly — `ProviderTerminalEventV1` has a
   first-class `model_mismatch` status carrying `returned_model` next to the invocation's
   `requested_model`. Reconcile toward recording the divergence and enforcing the authorization
   decision in policy, rather than making the row impossible to write.
4. Implement T-F16c and T-F16d in parallel after T-F16b; serialize T-F16e → T-F16f → T-F16g →
   T-F16h. Keep document surfaces disabled unless the private Runner proves the exact fixture
   binding with zero target calls.
5. Complete T-F17c, then T-F17d/T-F18j/T-F17e/T-F17f in dependency order. The four locked models
   remain, and all four are **confirmed served on OpenRouter** (see above), so none of this is
   blocked on model availability:
   - Orchestrator: `anthropic/claude-opus-4.8`
   - Red Team: `qwen/qwen3.5-397b-a17b`
   - Judge: `google/gemini-2.5-pro`
   - Documentation: `openai/gpt-5.4`
   Note for T-F18j specifically: `cost_measurement_state` is now the persisted provenance and should
   become the source of truth for the API's derived `accounting_status`. Today
   `/api/v1/agent-activity` still projects an unaccounted cost as `0`
   (`tests/test_postgres_api_m1d.py`), which is the same fabricated zero the invariant forbids,
   surfaced at the API rather than the database.
6. Complete T-F19a–e before console page implementation. Only then freeze/apply T-F18a and execute
   the rest of T-F18.
7. Run backend/console/security/migration/contract gates, push the same release to both remotes,
   require both CI systems green, then deploy Runner before Web with signed environment-specific
   grants and fresh observations.
8. Complete the authenticated live page-by-page audit. The existing production tab was still at
   `/sign-in` when work stopped; it needs a signed-in Headshot session.
9. Execute T-F19f only after all gates: one worker, exact approved caps/rate, no disabled-document
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
