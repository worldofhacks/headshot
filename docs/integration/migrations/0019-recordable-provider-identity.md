# Recordable provider identity — revision 0019

Revision `0019` is a constraint-only PostgreSQL migration over `0018`. It adds no table, no column
and no index. It replaces one CHECK, `agent_execution_provider_identity`, so that
`agent_executions.returned_model` may differ from `agent_executions.model` on any row whose status
is not `succeeded`.

The platform's claim is that requested provider identity is not observed provider identity. Until
`0019` the constraint asserted `returned_model IS NULL OR returned_model = model`, which made a
provider substitution physically unstorable: when OpenRouter served a model other than the
authorized one, the row could not be written, so the only evidence that the substitution happened
was destroyed. `0019` makes the divergence recordable while keeping it untrusted — the relaxed
predicate is `returned_model IS NULL OR returned_model = model OR status <> 'succeeded'`, so a
substituted call can be persisted but can never terminalize as a success.

## Effect on existing rows

None. The new predicate is strictly weaker than the old one, so every row that satisfied `0018`
satisfies `0019`. There is no backfill, no defaulting, and no column that becomes non-nullable, so
a populated production database migrates with no data loss and no row rewritten. `ALTER TABLE …
DROP CONSTRAINT` / `ADD CONSTRAINT` takes an `ACCESS EXCLUSIVE` lock on `agent_executions` for the
duration of one validating scan; on a table of this size that is short, but it does block reads and
writes, which is why the ordering below stops the writer first.

`tests/test_migrations.py::test_0019_applies_stepwise_over_a_populated_0018_database` asserts this
against a real database populated at `0018` — an observed hosted row, a failed row with no
observation, and a row with no observation at all — and checks all three survive the upgrade, the
downgrade and the re-upgrade unchanged.

## Downgrade

`0019` is reversible, with one deliberate loss. A row recording a genuine substitution cannot
satisfy the pre-`0019` predicate, so its observation is cleared. It must be cleared **as a whole**:
`agent_execution_hosted_measurement_tuple` requires the seven observation columns to be all-NULL or
all-NOT-NULL, so clearing only the three identity columns leaves a shape the older constraint
rejects and aborts the rollback on exactly the rows this migration exists to permit. The cost is
cleared with them, because a measured cost left on a row whose usage columns are now NULL projects
as an `unavailable` accounting status carrying a measured value, which `AgentActivityReadModel`
refuses to serialize — and since agent activity serializes every row in one response, a single
rolled-back substitution would otherwise fail the whole view.

After a rollback the substitution remains provable from the `agent.failed` audit event, which
records `requested_model` and `returned_model` together and which `0019.downgrade()` does not
touch. It is **not** provable from `provider_call_events`: that table has no production writer yet,
so do not rely on it as the rollback safety net until T-F17c wires it.

## Ordered production steps, Runner-first

The Runner is the only writer of hosted agent executions and the only component that produces the
observations this constraint governs. Web reads them. So the Runner stops first and starts last,
and the schema moves while nothing is writing.

1. Confirm the graph resolves to a single head before touching production. `alembic heads` must
   print exactly `0019`. Two revisions once shipped numbered `0016`; git reported no conflict
   because the filenames differed, and the result was that `alembic upgrade head` failed with
   `MultipleHeads` and `GET /ready` failed closed on every deploy carrying it.
   `tests/test_migrations.py::test_migration_graph_has_exactly_one_head` guards this.
2. Verify the target database is at `0018`. If it is behind, apply the intervening revisions first
   and re-verify; `0019` is not a substitute for them.
3. Take the pre-migration backup or confirm the restore point, per the standing release runbook.
   `0019` needs no backfill, but the rollback is only clean back to `0018`.
4. Stop the Runner service and confirm it has drained — no in-flight hosted execution may be
   mid-`finish` while the constraint is swapped, or its terminalizing write will fail against a
   table it cannot lock.
5. Apply `alembic upgrade 0019` against the production database. It is a single transaction; on
   failure it rolls back whole and the deployment is unchanged.
6. Verify: `SELECT version_num FROM alembic_version` is `0019`, and the constraint definition
   contains the `status <> 'succeeded'` disjunct. `GET /ready` must pass, since
   `readiness.expected_alembic_head()` raises unless the graph has exactly one head.
7. Deploy and start the **Runner** with signed environment-specific grants, and confirm it comes up
   healthy before touching Web. Only the Runner writes these rows.
8. Deploy **Web**. The agent-activity and Birdseye projections now expose `model_substituted` and
   render `requested → served` when the two differ, so Web must not be older than the Runner that
   can produce such a row.
9. Confirm on live data that an ordinary hosted execution still records `returned_model = model`
   with `model_substituted` false. Do not manufacture a substitution against a live provider to
   test this; the behaviour is covered by
   `tests/test_openrouter_transport.py` driving real provider bytes.

## Rollback

Reverse the order: stop Web, stop the Runner and let it drain, `alembic downgrade 0018`, then start
the Runner and Web from the previous release. Expect the observation columns of any recorded
substitution to be cleared, per the downgrade section above. Capture those rows' audit events first
if they are wanted as evidence.
