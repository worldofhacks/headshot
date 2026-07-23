# Migration 0013 — private regression scheduler

Revision `0013` grants the existing `headshot_scheduler` role the minimum table privileges needed
to detect a READY target-version change, create an append-only blocked regression replay plan, and
publish its private-process heartbeat.

The scheduler receives no target credential, adapter, campaign approval, or execution privilege.
Every generated replay plan remains `pending_human_authorization` / `blocked`; execution continues
to require the exact two-person campaign authorization enforced by the Web control plane and
Runner.

Rollback revokes the added scheduler privileges. It does not delete append-only replay plans or
heartbeat evidence.
