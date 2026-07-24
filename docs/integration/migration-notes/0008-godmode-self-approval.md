# Migration note: 0008 historical demo self-approval exception

Revision `0008` is a historical migration after `0007`. It added
`campaign_authorization_decisions.self_approval_override` and temporarily allowed a verified demo
principal to approve its own campaign when that flag was set.

This behavior is **not part of the current authorization model**. Revision `0012` is the forward
security correction: it retains the column only for expand-only compatibility and historical audit
readability, rejects every new override, accepts only Operator/Approver roles, and unconditionally
requires `approver_user_id != launcher_user_id`.

## Compatibility and release rule

- A database upgrading from `0007` traverses `0008`, then must continue through `0012` or later before
  accepting campaign work.
- Do not deploy or operate a final release at revisions `0008` through `0011`; those revisions retain
  the retired self-approval behavior.
- Application rollback may retain the expanded schema at `0012+`, but must not run code that attempts
  to set the override.
- A database downgrade below `0012` would restore the retired trigger semantics and is prohibited as
  a release rollback strategy.
- No data is deleted by `0012`; historical override rows remain visible for audit and are rejected by
  current Runner preflight.

The source migration is
[`../../../migrations/versions/0008_godmode_self_approval.py`](../../../migrations/versions/0008_godmode_self_approval.py);
the revocation is
[`../../../migrations/versions/0012_two_role_clerk_authorization.py`](../../../migrations/versions/0012_two_role_clerk_authorization.py).
