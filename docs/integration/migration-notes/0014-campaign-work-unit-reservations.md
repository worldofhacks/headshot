# Migration note: 0014 campaign work-unit reservations

Revision `0014` is an additive expansion after `0013`.

- Adds `campaign_work_unit_reservations`, keyed by the immutable physical coordinate
  `(run_id, attempt_id, turn_index, retry_index)`.
- Binds every coordinate to its Organization, campaign attempt, queue job, worker, job attempt, and
  SHA-256 of the lease token.
- Adds an Organization/run index and a partial index for unobserved reservations.
- Permits only one mutation: nullable observation fields may move once to a terminal
  `returned`/`raised` state. Trigger logic rejects delete, identity changes, clearing an observation,
  and a second terminal update.
- Grants Runner insert/select and column-limited observation update. It grants no replay or campaign
  authorization.

An unobserved reservation after a crash is intentionally ambiguous. It must not be assumed unsent or
blindly replayed.

## Compatibility and rollback

Older Web/Runner code ignores the new table. Code rollback should retain the expanded table and its
audit rows. A database downgrade drops reservation evidence and is appropriate only for isolated
migration verification before real work exists, not production rollback.

Before activating a `0014+` Runner, migrate Web's single pre-deploy path first and verify the exact
head. A `0014+` Runner must not consume work against a database below `0014`.
