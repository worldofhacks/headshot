# Final-submission execution manifest (session-lease scope repair round 3)

[locked-decision] Canonical requirements remain `Week_3_AgentForge.pdf`; this is not a replacement PRD/roadmap.

## Evidence boundary

- Baseline `23490ea`: 1001 Python passed/3 skipped, 75 console, 4 browser, dual CI green.
- Planning catalog baseline `efd5ce3` adds only the tracked secret-free target catalog; this repair does not amend it. Later shared-worktree commits are not attributed to this planning repair.
- Run `aceddc495808427992efbd2b73b3598d`: 9 HTTP 200, 9 evidence, 9 `INDETERMINATE`, $0.09 outbound.
- Judge baseline 60% agreement/33.3% false negatives/60% abstention is failed.
- [locked-decision] None proves calibrated safe/unsafe outcomes, findings, current-SHA live trace, production isolation, performance, or report completeness.

## Closure ownership

| requirement family | owner(s) |
|---|---|
| mechanical swarm gates | T-F00 |
| sanitized export / final reconciliation | T-F01a / T-F01b |
| package-authority root contracts | T-F02 |
| Judge code / authorized calibration evidence | T-F03a / T-F03b |
| Red Team controls / authorized provider eval | T-F04a / T-F04b |
| hosted role configuration/preflight/transport/smoke | T-F04c through T-F04h |
| durable release lineage | T-F05a |
| authorized target/session/patient evidence | T-F05d |
| tracked non-secret Clinical Co-Pilot target catalog and Web/Runner parity | T-F05p |
| signed deployment observation projection | T-F05h |
| current authenticated control-state projection | T-F05i |
| immutable SMART context and sole fresh validator | T-F05e |
| configuration/reference/job persistence and sanitized queue failure contract | T-F05j |
| fixed-path secure context install/load/pin | T-F05k |
| fixed authenticated controller-observation acquisition | T-F05l |
| non-cached per-call runtime state provider | T-F05m |
| exact bounded predecessor campaign/job history | T-F05o |
| signed activation event and five-stage rotation evidence | T-F05n |
| Runner post-claim/per-attempt enforcement | T-F05f |
| zero-overlap config and full-chain verifier/runbooks | T-F05g |
| campaign/replay/performance/evidence/docs consumers | T-F05c, T-F05b, T-F06a through T-F15 |
| final-target surface auth/transport policy | T-F16a |
| gateway-owned multi-operation physical accounting | T-F16b |
| anonymous evidence + redacted UI probe adapters | T-F16c |
| exact-fixture Week 2 document workflow | T-F16d |
| immutable environment catalogs + per-surface Runner composition | T-F16e |
| durable API parent/eight-child authorization, approval, queue, fanout, and aggregation | T-F16f |
| trusted state observation/attestation plus deterministic deployment verifier | T-F16g |
| authorized final-target deployment/evidence/rollback | T-F16h |

## Invariants

- No production/config code without reviewed failing deterministic tests; sampled behavior uses graded eval artifacts.
- No controller/database/activation/network/spend/live traffic without exact named authorization; absent authority is zero-action `BLOCKED`.
- T-F04h remains target-free smoke. T-F05d remains the synthetic patient fixture authority.
- T-F05p's tracked secret-free catalog contains exactly `clinical-copilot-week1` and `clinical-copilot-week2`. Staging Web and Runner load identical file bytes/hash. Only chat surfaces are enabled; UI, evidence/search, and upload/write surfaces remain explicitly disabled until their own adapter RED/GREEN/code/security reviews land.
- Every live campaign selects exactly one T-F05p target, one enabled session-auth chat surface, one opaque credential reference/generation, and one T-F05d patient/context identity. T-F05e/T-F05f pin the entire target/session/patient tuple; no switching or cross-target resolution exists.
- Web can read the non-secret catalog but never receives or resolves target credential variables. Runner alone holds sealed variables mapped by reviewed opaque credential bindings. No credential/session value or locally extracted browser/bundle artifact enters source control, tickets, prompts, reports, tests, logs, jobs, or evidence.
- T-F05h verifies strict signed `DeploymentControllerObservation/v1` envelopes including request nonce, controller sequence, truthful phase, and rotation hash fields. T-F05l is the only production acquisition channel: one fixed no-follow Unix seqpacket endpoint, peer plus Ed25519 authentication, fresh challenge, bounded response, freshness/replay checks, no cache/retry/fallback.
- T-F05i projects current control state in one authenticated read-only repeatable-read transaction. T-F05m performs T-F05l acquire → T-F05h project → T-F05i project → T-F05e validate on every call; it never uses H's offline path CLI, caller artifacts, combined state, or prior success.
- T-F05j owns only settings/reference/job persistence and preserves the queue sanitizer. T-F05k owns only fixed-path install/load/pin. These land before T-F05m and T-F05f.
- The only public/persisted SMART policy-rejection message is `worker-supplied failure detail omitted`. Separate machine state is `smart_session_lease_rejected`, durable `dead_letter`, and `DEAD_LETTERED`. Any queue-required internal failure detail is sanitized and is never exposed or persisted.
- T-F05o freezes the exact complete predecessor campaign/job set plus high-watermarks after durable admissions closure, then proves the identical set terminal with no later predecessor work and zero live leases.
- T-F05n authenticates a signed controller activation receipt and binds exactly start control → terminal control → zero-generation deployment → activation event → exactly-one-generation final deployment. Hash links establish cross-authority order; signed controller sequence/nonces/times reject replay. A final snapshot or opaque activation hash alone proves nothing.
- T-F05g consumes and reauthenticates every separate chain artifact. No caller-combined document, local queue count, process boolean, overwrite, reload, rolling overlap, or in-place session/patient swap is authority.
- T-F05f permits only atomic queue claim before immediate J/K/M validation. All other mutation, resolution, adapter/client construction, network, and spend follow success. Every physical attempt obtains a new L→H/I refresh through M.
- T-F05e timestamp/reference languages remain Python 3.12 ASCII `re.fullmatch` plus portable Draft 2020-12 patterns, exact lengths, semantic validation, and explicit control rejection including terminal CR/LF.
- No PHI/secrets/sessions/raw hostile evidence in artifacts; staging/test is never called production. Swarm never merges main, publishes critical findings, remediates, load-tests, or posts socially autonomously.
- Final-target adapter selection is bound to a canonical per-surface policy hash. Anonymous evidence resolves no credential; UI uses exact query key `sid`; chat/document use exact key `session_id`.
- A multi-operation adapter is a pure response-driven state machine. The Policy Gateway reserves retry-inclusive maxima before dispatch and alone sends, reauthorizes, rate-limits, charges, traces, and counts every upload, poll, retrieval, and retry. Lab is bounded at 34 logical/67 physical operations and intake at 2/2; ambiguous uploads never retry.
- UI availability proof is HTTP-only and retains no credential-bearing URL, HTML body, DOM, browser history, subresource, or screenshot.
- Week 2 document upload accepts only complete authorization-bound fixture descriptors through a mechanically verified Runner-only binding. Documents remain disabled in v2.0 and v2.1 remains inactive until that proof passes.
- Catalog versions are immutable, environment-specific snapshots with within-environment Web/Runner parity and append-only activation/rollback events; Staging and production refs are intentionally distinct.
- A launched final-target scan begins at the real API and durably persists one parent plus the fixed eight-child declared scope. A distinct approver separately approves the exact parent and every child before an idempotent launch can enqueue hashes; Runner reloads those records and never treats queue payload as authority.
- Scan results reject `full_surface_scan`. `declared_scope_complete=true` requires success for all eight known children; inactive/unproved lab or intake keeps it false. `active_surface_scan_complete` is narrower and cannot support a full-target claim.
- Deployment current state is a canonical signed attestation from a trusted observer, with issuer/key, freshness, environment/services, monotonic deployments, raw provider digests, topology, session/fixture proof, and input hashes. After every transition, a distinct approver supplies an immutable transition-grant version binding the new attestation hash; T-F16h cannot create it and reruns the networkless verifier before the next action.
- Final-target operational commands use exact `python3`; grant-bound interpreter realpath/version/executable, script, dependency-manifest/set, and release hashes make the bootstrap mechanically executable and auditable.

## Deterministic order

```text
{T-F05a,T-F05d} -> T-F05h -> T-F05i --\
T-F05p --------------------------------> T-F05e -> T-F05j
                                                   /          \
                                              T-F05k          T-F05l
                                                   \          /
                                                     T-F05m
                                                     /     \
                                                T-F05f     T-F05o
                                                     \     /
                                                     T-F05n
                                                        |
                                                     T-F05g
                                                        |
                                                {T-F05c,T-F06a}

T-F00 -> T-F16a -> T-F16b -> {T-F16c,T-F16d}
{T-F05a,T-F06a,T-F16c,T-F16d} -> T-F16e -> T-F16f -> T-F16g -> T-F16h
```

T-F05p also precedes every target/session consumer. Every campaign/replay/stress/docs ticket directly
depends on each artifact it consumes. External authority may block observation/evidence but never
justify skipping or parallelizing this deterministic chain.

## Deadline triage

- **P0 deterministic:** existing hosted/smoke order; A+D+P → H → I → E → J → K+L → M → F+O → N → G → C/06a. Tests use only synthetic signatures, fake read-only transactions, fake IPC/stat/resolver, and zero network.
- **P1 external:** actual controller IPC/database projection/activation receipt and T-F03b/T-F04b/T-F04e/T-F05b/T-F06b/T-F07b may remain `BLOCKED`; no caller-created state/catalog/session substitutes.
- **P2 packaging:** T-F12/T-F13 and every live/release/cost claim consume all landed contract/test/review hashes or remain incomplete.
- **Final-target adapter closure:** T-F16a surface contract → T-F16b retry-aware gateway accounting → parallel T-F16c evidence/UI and T-F16d document flow → T-F16e immutable catalogs/composition → T-F16f durable API authorization/eight-child queue/fanout → T-F16g trusted state attestation and zero-action verifier → T-F16h transition-gated deploy/review.

## Open owner gates

- [open-question] Supply immutable `campaign.json` selecting one catalog target, one enabled chat surface, one session generation, and one complete T-F05d patient identity with exact allowlist/corpus/config/smoke/reviews/caps/principals.
- [open-question] Supply deployment/controller and control-projector trust roots, workload DB identity, immutable context reference, and maximum lifetime; none is inferred/defaulted.
- [open-question] Authorize controller IPC, private database projection, activation action/receipt, campaign, replay, and stress separately. Absence is zero-action `BLOCKED`.
- [open-question] Provision only Runner-side sealed variables matching reviewed opaque bindings. Never copy values or discovered local artifacts into planning/evidence.
- [open-question] Retain distinct Evidence/Security reviewers, launcher/Approver, Judge, Red Team, replay, stress, reproduction, drill, publication, Railway/Clerk, and deployment authorities.
- [open-question] Supply a durable T-F16h deployment grant that the exact T-F16g verifier can bind to current SHA, Railway environments/services, trusted observer issuer/key and maximum age, monotonic deployments/raw digests, environment catalogs, target/surface-policy hashes, host/allowlist, session generations, post-deploy Runner fixture proof, eight-child ScanPlan, retry-inclusive caps, exact `python3` bootstrap provenance, expiry, launcher/distinct approver, rollback release, and production-promotion scope.
- [open-question] Provision or identify a pre-approved Runner-only read-only private fixture root/object binding for the two Week 2 PDF refs. The extracted owner bundle is never committed and is not assumed uploadable.

[locked-decision] P0 deterministic proof is prioritized; P1/P2 remain honestly blocked when authority or evidence is absent.
