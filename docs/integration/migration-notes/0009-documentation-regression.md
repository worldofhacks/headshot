# Migration note: 0009 Documentation and regression disposition

`0009` is an additive, rollback-compatible expansion after `0008`.

- Adds append-only `vuln_reports` for schema-valid Documentation Agent drafts.
- Adds append-only `regression_dispositions` for deterministic admission decisions.
- Both rows remain correlated to Organization, finding, campaign run, attempt, and authoritative evidence.
- The only report publication states represent unpublished drafts; no publication authority is added.
- Regression admission is data-constrained so only the `admitted` state can carry `admitted=true`.
- `headshot_runner` may insert/select; `headshot_web` may select. Neither role gains update/delete.

Compatibility: the migration changes no existing table or contract. An older Web/Runner build can continue
operating after the database expands, though it will not create or read the new records. Rollback is therefore
an application rollback with the expanded tables retained; database downgrade is for local verification only.
