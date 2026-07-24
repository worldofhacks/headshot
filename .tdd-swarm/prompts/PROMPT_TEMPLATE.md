# Strict prompt contract

Every generated role prompt states: model; exact ticket/input/output paths; `<WORKTREE>` and exact branch;
allowed write scopes; frozen-test ownership or named mechanical verifier; exact gate command; maximum three
attempts; `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` return; no main merge/push; and no
network/spend/live traffic without the named authorization artifact. The full report is written to the
declared path and only status + one-line summary is returned.
