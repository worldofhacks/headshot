# Open integration decisions

Three decisions surfaced during the console-remediation convergence. They were deliberately not
settled inside a merge, because each changes behaviour that another lane depends on.

**Ownership: 1 and 2 are for the integration manager. 3 is done — see below.**

---

## 1. `cost_measurement_state` has a server default that invites constraint violations

**Owner: integration manager.**

`agent_executions.cost_measurement_state` is `NOT NULL DEFAULT 'not_observed'`, and
`agent_execution_cost_measurement` requires `not_observed` to carry a NULL cost. So any writer that
supplies `measured_cost` without also declaring provenance produces a check violation — the schema
invites exactly the error it then rejects.

This is not hypothetical. Four fixtures hit it during integration
(`test_birdseye_api`, `test_postgres_api_m1d` ×3), and the shared lane keeps adding more, so it will
recur on every merge until it is decided.

Two coherent options:

- **Drop the default.** A writer that omits provenance then fails loudly as a NOT NULL violation
  instead of silently producing an invalid row. Strongest guarantee — every cost row states how it
  was measured — at the cost of touching every INSERT site once.
- **Derive it.** Extend the existing `normalize_agent_execution_unknown_cost` trigger so a non-NULL
  cost arriving with the default state becomes `measured`. Cannot fabricate a cost (the dangerous
  direction, `measured` with a NULL cost, stays rejected) and ends the recurring breakage, but
  weakens "every writer declares provenance" to "the database guesses when they don't".

This lane fixed the call sites explicitly rather than choosing, so nothing is blocked — but the
next lane to add a cost-bearing fixture will hit it again.

## 2. The API still projects an unaccounted cost as `0`

**Owner: integration manager. Belongs with T-F18j (canonical cost-state consumers).**

The database now holds the invariant correctly — an unobserved cost is `NULL`/`not_observed`, never
a fabricated zero. The projection does not: `/api/v1/agent-activity` reports `measured_cost == 0`
for a row whose accounting was never observed, so the console renders "$0.00" for "we do not know".
That is the same fabricated zero the invariant forbids, surfaced one layer up.

`cost_measurement_state` is now the persisted provenance and should become the source of truth for
the derived `accounting_status`, with an unobserved cost projecting as null rather than zero. Note
this is an API response-shape change, so the console decoders move with it — they are strict
(`exactKeys`) and reject unknown or missing keys.

## 3. `returned_model = model` made a provider substitution unrecordable — **RESOLVED**

**Taken by this lane. Branch `codex1/recordable-provider-identity`.**

`agent_execution_provider_identity` asserted `returned_model IS NULL OR returned_model = model`, and
`hosted_runtime` raised `HostedCompositionError` on a divergence while `_observed_failure_lineage`
returned `None` and discarded the record. A provider serving a different model than authorized was
therefore both unstorable and unrecorded — the platform destroyed the evidence its own
"requested identity is not observed identity" claim depends on.

Resolved by separating the two things the code conflated:

- **Authority** is what we requested plus the bound hashes. `requested_model` must still match
  exactly — a mismatch there means *we* sent the wrong call and the whole observation is untrusted.
- **Observation** is what the provider served. `returned_model` may now differ; that divergence is
  the finding.

Migration `0019` relaxes the constraint to
`returned_model IS NULL OR returned_model = model OR status <> 'succeeded'`, so a substitution is
recordable but **can never terminalize as succeeded** — recording it does not become trusting it.
`HostedModelSubstitutionError` (code `provider-model-substituted`) carries the refusal, the
preserved lineage keeps the observed identity and the charge that was really incurred, and
`AgentActivityReadModel.model_substituted` surfaces it as a derived field so no consumer has to
remember to compare the pair.

Sequencing note: `0019` depends on `0018_provider_call_lineage`, which is the still-open
`codex/integration-provider-lineage-0018` work. `0018` must land first. The number was chosen
specifically to avoid a second double-numbering incident.

**Scope, stated precisely.** What is complete is the *logical* record: the row is writable, the
store refuses to terminalize it as succeeded, the runtime preserves the lineage instead of
discarding it, and the read model and console surface it. What is **not** wired is the *physical*
half. `provider_call_events` already carries `model_mismatch` as a first-class terminal status with
a bijective status/error-code map, but nothing emits those rows yet — there is no production caller
of the provider-call lineage methods outside `control_plane/store.py`. Connecting the physical
recorder to the hosted runtime is T-F17c. Until it lands, a substitution is provable from
`agent_executions` alone (`model` vs `returned_model`, plus the `provider-model-substituted` error
code), not from a per-attempt physical event.

Two properties worth keeping when that wiring happens, both verified against a migrated database:

- A substituted row cannot be laundered into a success. A direct
  `UPDATE agent_executions SET status='succeeded'` is refused by the relaxed constraint, and
  setting `returned_model = model` first and then succeeding is refused by
  `agent_execution_terminal_shape` (a succeeded row cannot carry an `error_code`). The guarantee is
  enforced in the database, not only in the store API.
- The refused call's measured cost is preserved rather than dropped with its output, so a
  substitution still shows up in spend.
