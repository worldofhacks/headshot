# WP-21 — Reconcile and independently review live evidence

**Branch:** `rtg/wp21-authorized-live-evidence`

**Model:** capable

**Depends on:** WP-21A–E complete or honestly blocked

**May close with approved evidence:** live-evidence portions of RT-01–RT-14

This is a no-call evidence-reconciliation prompt, not an implementation or execution prompt.
Use an identity distinct from every executor, launcher, approver, Judge, reviewer, and
publisher.

**Writes only**

- `docs/evidence/authorized-red-team/reconciliation/candidate/**`
- `docs/evidence/authorized-red-team/reconciliation/final/**`
- `.tdd-swarm/reports/RTG-WP21-reconcile.md`

WP-21A–E artifacts, raw evidence, source, tests, migrations, authorizations, review records,
and deployment configuration are read-only.

## Required reconciliation

Load the immutable WP-21A preflight and every WP-21B–E execution manifest. Recompute
canonical hashes and produce one content-addressed matrix from every RT-01–RT-14 criterion
to:

- exact deployed Railway release SHA and deployment/topology attestation;
- exact owner-authorized deployed OpenEMR URL, target/surface version, and certificate/
  network identity;
- seeded synthetic non-PHI live-data namespace and provisioned test-principal attestation;
- exact authorization, launcher/approver/executor identities, caps, abort epoch, and lane;
- genuine provider/native-tool/ZAP/browser/OAST/process version and profile hashes where
  applicable;
- fresh exact-SHA GitHub/GitLab Semgrep, dependency-audit, and secret-scan job artifacts
  and attestations for release-control claims;
- operation/permit/physical-send/delivery/broker/collector/Judge/evidence ledger parity;
- trusted observation and required-oracle-policy completeness;
- decisive independent Judge result;
- fresh live regression/right-reason result when closure requires regression;
- cleanup/rollback, cost, partial/abort, and publication-blocked state;
- independent Evidence and Security review decision hashes.

Never infer success from an implementation status, local suite, adapter/configuration
presence, authored case, imported/saved artifact, or a nonzero process exit. Mocks, fakes,
doubles, cassettes, fixture adapters, checked-in responses, simulated artifacts, local app
servers, in-process receivers, loopback/fake targets, and local process logs cannot appear
in a supporting-evidence set. If any lane used one as evidence, mark the affected claim
`REJECTED_NON_LIVE_EVIDENCE`.

Validate aggregate request/turn/frame/callback/token/USD/time/rate/concurrency counts against
both per-lane and target-wide caps. Reconcile all partial/abort evidence and verify parallel
lanes used the exact disjoint namespaces and concurrency authority from WP-21A. Any overlap,
counter mismatch, missing stop, authorization drift, unexpected data indicator, or evidence
mutation rejects the affected lane.

The immutable candidate manifest and matrix are content-addressed under
`reconciliation/candidate/<CANDIDATE_MANIFEST_SHA>/`. Use only these candidate states:

- `LIVE_EVIDENCE_PENDING_REVIEW`;
- `RELEASE_CONTROL_PENDING_REVIEW`;
- `PARTIAL_LIVE_EVIDENCE`;
- `BLOCKED_LIVE_EVIDENCE`;
- `REJECTED_LIVE_EVIDENCE`.

This prompt cannot itself mark a finding closed.

## Independent review

After writing the immutable candidate manifest and matrix, launch separate
`ROLE-EVIDENCE-REVIEWER.md` and `ROLE-SECURITY-REVIEWER.md` agents in parallel on the same
exact manifest hash. Neither may make an external call or repair evidence. Cherry-pick only
their report-only commits after verifying paths and hashes.

After both immutable review reports exist, create a distinct content-addressed final
manifest and matrix under `reconciliation/final/<FINAL_MANIFEST_SHA>/`; never edit or
replace the candidate directory. Use only these final states:

- `APPROVED_LIVE_EVIDENCE`;
- `VERIFIED_RELEASE_CONTROL`;
- `PARTIAL_LIVE_EVIDENCE`;
- `BLOCKED_LIVE_EVIDENCE`;
- `REJECTED_LIVE_EVIDENCE`.

Only claims approved by both reviewers become `APPROVED_LIVE_EVIDENCE`. A rejected or
missing review remains rejected/blocked. `VERIFIED_RELEASE_CONTROL` is allowed only for
fresh exact-SHA static/dependency/secret CI evidence and cannot support target behavior or
LLM/Web coverage. Findings remain publication- and remediation-blocked pending their
separate human gates.

Do not contact the target/provider/Clerk/Railway/OAST, resolve credentials, start a native
tool/scanner/browser, rerun a campaign, deploy, publish, remediate, spend, push, or merge
main.

Return the README status contract, candidate/final manifest hashes, approved/partial/
blocked/rejected claim counts, aggregate request count/cost, reviewer states, and one-line
blocker summary. Never print credentials, session values, canaries, raw clinical content,
or hostile transcripts.
