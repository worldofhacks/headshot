# T-F17b Security Reviewer — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on the assigned T-F17b review branch.
Review T-F17b ticket/diff/gates. Write only `.tdd-swarm/reports/T-F17b-security.md`. Attack cross-org
reads, forged provider identity/request ids, UPDATE/DELETE/TRUNCATE, privilege escalation, raw
prompt/message/credential/session/evidence persistence, JSON/error injection, oversized values,
uniqueness races, and audit leakage. Validate real PostgreSQL grants/triggers. Critical/Important
findings block. No edits/external network/deployment/main push.
