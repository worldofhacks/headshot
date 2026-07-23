# Migration note: 0012 Two-role Clerk authorization

`0012` is a forward security correction after `0011`.

- Human Organization access is limited to `org:operator` and `org:approver`.
- A launcher can never approve their own campaign authorization.
- The historical `self_approval_override` column remains readable for expand-only compatibility,
  but the database rejects every new override and runtime dispatch rejects any legacy override.
- Operator owns launch, abort, target, and configuration actions; Approver owns campaign
  authorization and finding approval/resolution. Both roles may read the console and audit trail.

Compatibility: deploy the updated Web and Runner with this migration. Older code that attempts a
self-approval override will fail closed at the database trigger. Downgrade restores only the legacy
trigger semantics and is for local verification, not a production rollback strategy.
