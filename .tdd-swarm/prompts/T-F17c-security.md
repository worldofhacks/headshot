# T-F17c Security Reviewer — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on the assigned T-F17c review branch.
Review T-F17c ticket/diff/gates. Write only `.tdd-swarm/reports/T-F17c-security.md`. Attack
user-to-system role smuggling, prompt hash confusion, model/upstream spoofing, alias/fallback routing,
retry/accounting bypass, error-body leakage, callback omission/duplication, unbounded messages,
credential exposure, and hostile output deserialization. Critical/Important block. No edits/live
calls/deployment/main push.
