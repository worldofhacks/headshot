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

**Scope, stated precisely.** The *logical* record is complete and reachable on the real transport:
`OpenRouterTransport` raises `HostedProviderResponseError(code="provider-model-substituted")`
carrying the observed result after settling the billed usage, the runtime preserves that lineage,
the store refuses to terminalize it as succeeded, and the read model, Birdseye and the console all
show the divergence rather than the served model alone.

What is **not** wired is the *physical* half. `provider_call_events` already carries
`model_mismatch` as a first-class status, but nothing emits those rows — there is no production
caller of the provider-call lineage methods outside `control_plane/store.py`. Connecting the
physical recorder is T-F17c. Two consequences until it lands:

- A substitution is provable from `agent_executions` and the `agent.failed` audit event (which
  records `requested_model` and `returned_model` together), not from a per-attempt physical event.
- `finish_physical_attempt` already rejects a `succeeded` event whose `returned_model` differs from
  the invocation's `requested_model`, and a `model_mismatch` event correctly terminalizes the
  logical row as `failed`. But that path never propagates the observed identity **onto** the
  logical row, so once it is wired a substitution recorded physically would leave
  `agent_executions.returned_model` NULL and `model_substituted` false. Propagating the full
  seven-column observation tuple belongs to that same ticket — a partial propagation would violate
  `agent_execution_hosted_measurement_tuple`.

**Not durable before terminalization.** The observed identity lives only in the in-process result
until the single `finish` write. A runner death between the provider response and that write leaves
the row `running` with the evidence gone. Closing that gap needs the pre-call physical reservation,
which is again T-F17c.

Two properties worth keeping when that wiring happens, both verified against a migrated database:

- A substituted row cannot be laundered into a success. A direct
  `UPDATE agent_executions SET status='succeeded'` is refused by the relaxed constraint, and
  setting `returned_model = model` first and then succeeding is refused by
  `agent_execution_terminal_shape` (a succeeded row cannot carry an `error_code`). The guarantee is
  enforced in the database, not only in the store API.
- The refused call's measured cost is preserved rather than dropped with its output, so a
  substitution still shows up in spend.
