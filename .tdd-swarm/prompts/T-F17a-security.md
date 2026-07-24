# T-F17a Security Reviewer — model: gpt-5.6-sol, reasoning: ultra

Review the T-F17a ticket/diff/frozen tests/gates in `<WORKTREE>`. Write only
`.tdd-swarm/reports/T-F17a-security.md`. Check prompt injection into the registry, path traversal,
role substitution, hash normalization ambiguity, oversized/non-UTF-8 content, secret/PHI leakage,
package fallback, unsafe error text, and dependency changes. Critical/Important findings block.
No edits, network, deployment, or main push. Return the four-status contract plus findings summary.
