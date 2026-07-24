---
id: T-F05k
title: Securely install load and pin SMART lease contexts
status: backlog
wave: 12
depends_on: [T-F05e, T-F05j]
branch: ticket/T-F05k-smart-session-context-loader
file_scopes:
  - src/agentforge/policy/smart_session_delivery.py
  - scripts/install_smart_session_lease_context.py
test_scopes: [tests/test_smart_session_lease_context_loader.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-lease-scope-review.md I3
---

## Context
[locked-decision] This half-day ticket owns only the fixed-path create-only filesystem
installation, startup load, post-claim reload, and immutable pin lifecycle for the T-F05e context
and T-F05j typed reference. It does not parse environment settings, persist jobs, acquire source
state, refresh observations, dispatch, or resolve a credential.

## Acceptance Criteria
- **AC-1**: A validated T-F05j reference derives exactly `/run/agentforge/lease-contexts/staging/<release_sha>/<generation>/<context_sha256>.json`; no setting, job, CLI flag, symlink, cwd, or environment variable chooses the root or any path component. The source context is at most 65536 bytes and T-F05e canonical bytes/hash/release/generation must equal the reference.
- **AC-2**: `python scripts/install_smart_session_lease_context.py --context <SMART_SESSION_LEASE_CONTEXT> --install` first validates/re-hashes the context and typed reference, then writes only the derived fixed path. Every ancestor/source/final is inspected or opened through directory descriptors with no-follow checks; ancestors are root-owned, not group/world writable, and the final is one regular root-owned `0400` file with link count one.
- **AC-3**: Installation uses a same-directory `O_CREAT|O_EXCL|O_NOFOLLOW` temporary file, exact bounded write, file fsync, link/rename-with-no-replace semantics, post-link inode/stat/byte verification, and directory fsync. Existing byte-identical safe output is idempotent success without rewrite. Symlink/nonregular/wrong owner-mode-link count/different bytes, hard-link substitution, ancestor/final race, traversal, replacement, partial write, or cross-device behavior exits 4 and preserves existing artifacts.
- **AC-4**: Startup receives already parsed T-F05j configuration, no-follow loads the fixed context, validates canonical bytes/hash/release/generation/trust/database binding, and retains no ephemeral source state. Immediately after a SMART claim, the per-job loader requires stored ref equal startup ref, independently reopens/revalidates the same inode/bytes, and returns a non-serializable pinned context handle for that campaign.
- **AC-5**: The pinned handle holds the immutable byte/object identity until terminal cleanup. Attempts never reopen, reload, replace, refresh, or choose a path. A changed inode/stat/bytes between startup and post-claim fails before source acquisition, resolver, adapter/client, mutation, network, or spend. Non-session jobs do not invoke this loader.
- **AC-6**: Stable failures are `lease-context-path-unsafe`, `lease-context-hash-mismatch`, `lease-context-replacement-refused`, and `lease-context-pin-mismatch`; none includes path/context content. Deterministic tests use temporary dirfd abstractions, inject ownership/stat operations, and patch resolver/source/adapter/client/socket/database/controller/provider/target hooks to fail.

## Test Plan
- Unit (deterministic): fixed derivation, no-follow/stat/mode/link/size/hash rules, create-only/idempotent/refusal behavior, and stable redacted failures.
- Integration (deterministic): startup versus immediately-post-claim reopen/pin lifecycle, replacement/TOCTOU attacks, cleanup, and non-session bypass.
- Eval/E2E: none; no live `/run`, source authority, Runner dispatch, database, Railway, provider, target, or secret.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05k.md <DIFF_BASE>` exits 0.
- [ ] The install/load/pin lifecycle is frozen independently of configuration and provider logic.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No configuration/reference parser, migration/job/queue change, source acquisition/provider,
Runner dispatch, credential resolution, live filesystem mutation, Railway action, network, or spend.
