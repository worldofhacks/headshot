# Migration note: 0017 hosted agent execution lineage

Revision `0017` is an additive hosted-lineage expansion after `0016`.

- Widens `agent_executions.measured_cost` from `numeric(14,6)` to `numeric(20,12)`.
- Adds provider-returned model, upstream provider, provider request ID, reasoning tokens, physical
  attempts, configuration-set hash, role-configuration hash, and generation-policy hash.
- Adds Judge calibration identity/state, oracle agreement, and decision authority.
- Adds checks for hash format, non-negative accounting, complete provider identity, complete hosted
  measurement tuples, hosted advisory mode, terminal lineage, and valid Judge authority.
- A hosted Judge may use `decision_authority=model` only when calibration state is `enabled`.
- Adds an Organization/provider-request lookup index.

Rows with `configuration_set_sha256 IS NULL` are explicitly treated as pre-`0017` rows. New successful
hosted rows must carry the complete terminal provider/accounting tuple; missing provider-supplied
measurements cannot be presented as zero.

## Compatibility and rollback

Older code can ignore the nullable lineage columns and continue creating pre-`0017` rows with no
configuration-set hash. Code rollback should retain the expanded schema.

Database downgrade deletes the new lineage/calibration columns and narrows measured-cost precision.
It is destructive to evidence and may fail or round values that exceed the old numeric shape.
Production rollback therefore uses a compatible prior image with the `0017` schema retained; a
downgrade is for isolated verification only.
