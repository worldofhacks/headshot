# Fresh live-execution readiness audit — zero-call

- Audit time: 2026-07-24T15:19:48Z (11:19:48 EDT)
- Repository: `swarm/final-submission-gap-closure`
- Audited HEAD: `66e670fee8c6c66a5236c7d932a0c4a2e9f74b87`
- Decision: **BLOCKED — do not make a provider or target call.**

## Audit boundary

This was a read-only audit of repository files and Railway status/deployment/domain/volume metadata.
The only write was this sanitized report. Railway variable listing was deliberately not invoked because
the installed CLI returns raw values. No credential or session value was read, copied, hashed, validated,
or passed to a command. The session supplied in chat was deliberately not used.

No target, provider, Clerk-admin, database, health-probe, campaign, approval, deployment, or spend action
was performed. The repository evidence basis was `AGENTS.md`, `CLAUDE.md`, `tickets/T-F05c.md`,
`tickets/T-F05b.md`, `tickets/T-F07b.md`, and the prior
`.tdd-swarm/reports/live-gate-readiness.md`, plus current source/config and Railway metadata.

## Gate results

| Gate | Fresh observation | Decision |
|---|---|---|
| Current deployed release | Staging Web, Runner, and Scheduler report successful deployments and running instances, but none records a commit SHA. Only the extra private `headshot` service records `23490ea9846bffcf36168b58f2c36edeceabb8df`, while the audited integration HEAD is `66e670fee8c6c66a5236c7d932a0c4a2e9f74b87`. The recorded legacy SHA is an ancestor and differs across 163 repository paths. No current deployment manifest exists. | **BLOCKED.** The exact audited SHA is not provably deployed to all three platform services. |
| Public/private topology | Staging Web has one Railway service domain. Runner, Scheduler, Postgres, and the extra `headshot` service have zero public/custom domains. | **PASS for domain inventory only.** Reconcile or explicitly document the extra private `headshot` service before release evidence is accepted. |
| Staging/production database isolation | Staging and production have distinct Postgres environment instances but the same Postgres service ID and the exact same Railway volume ID. | **BLOCKED.** This is a direct isolation violation, not merely missing evidence. |
| Target credential reference | Current runtime requires one canonical `secretref://` handle in the target, authorization scope, Runner binding map, and lease metadata. The committed `.env.example` still shows a legacy `env:` example that is not accepted by the current `TargetDefinition`/Runner resolver. Current deployed binding presence was not re-read because doing so would resolve raw Railway variable output. | **BLOCKED.** No fresh, secret-safe proof binds the exact target generation to a Runner-only sealed variable. |
| SMART lease metadata | Current `SessionLeaseMetadata` accepts only `generation`, `expires_at`, and `value_sha256`. T-F05c additionally requires not-before and exact target binding, plus agreement with the credential-reference hash. `src/agentforge/campaign/live_preflight.py`, `scripts/preflight_live_campaign.py`, and their tests are absent. | **BLOCKED.** The current implementation cannot satisfy the ticket's required lease contract as written. |
| Exact target allowlist and surface | Repository contract requires an exact HTTPS authority/host allowlist and reviewed `POST /chat` surface. There is no current target-observation artifact, deployment-bound catalog projection, allowlist hash, or campaign grant. The prior report's suppressed structural catalog observation is historical and not an exact current-scope authorization. | **BLOCKED.** Exact target, version, scheme/host/port, surface, and allowlist cannot be mechanically proven. |
| Synthetic-test-data assertion | Domain code rejects a target unless `synthetic_data_only` is true, but no exact synthetic-fixture manifest/hash or grant binding exists. A template setting or historical catalog observation is not run authorization. | **BLOCKED.** Bind reviewed synthetic fixture IDs/hashes and `synthetic_only:true` into the immutable grant and current preflight inputs. |
| Clerk launcher and distinct approver | Source and database logic require launch/abort permission, authorize permission, and `approver.user_id != launcher_user_id`. No immutable staging trace or grant proves two currently enrolled Headshot Organization principals with those exact custom permissions. | **BLOCKED.** Code enforcement exists; operational two-person readiness is unproven. |
| Campaign authorization | `docs/evidence/authorizations/campaign.json` is absent. The T-F05c public zero-call verifier and all required current deployment/configuration/smoke/review/lease inputs are absent. | **BLOCKED.** T-F05b must not start. |
| 100-case load authorization | `docs/evidence/authorizations/live-stress.json` and `docs/performance/live/` are absent. | **BLOCKED.** T-F07b must not start, and campaign approval cannot be reused for load. |
| Abort, rate, and cap controls | Existing target code has four legacy caps—USD, attempts, target requests/second, and run timeout—and a hard-abort path. T-F05c requires additional aggregate/per-role call, retry, token, USD, rate, concurrency, timeout, wall-clock, and abort bindings. The hosted configuration/reservation/preflight tickets remain backlog and no exact grant carries these values. | **BLOCKED.** Structural legacy controls are not the complete current authorization envelope. |

## Required non-secret actions, in order

1. **Isolate staging first.** Provision a dedicated staging Postgres service/database and volume,
   bind only staging Web/Runner/Scheduler to it, migrate through the reviewed Web pre-deploy path, and
   retain metadata proof that staging and production service, volume, database, Clerk, origin, and
   sealed-reference boundaries differ.
2. **Land and review the deterministic gate chain.** Complete the required prerequisites through
   T-F04c/T-F04g/T-F04f/T-F04h/T-F05a and T-F05c. The public T-F05c command must exist and fail with
   exit 4 before any secret resolution, adapter construction, database mutation, network action, or spend.
3. **Deploy one traceable release.** Deploy the same reviewed commit to Staging Web, Runner, and
   Scheduler and create a secret-free deployment manifest binding each deployment ID, image digest,
   commit SHA, schema revision, and private-domain inventory. Reconcile the extra `headshot` service.
4. **Provision a fresh SMART session through Railway's secret manager, never through chat.** The owner
   should create a new immutable generation, place its value directly in a new Runner-only sealed Railway
   variable using the Dashboard secret field or CLI standard input, and map a canonical
   `secretref://staging/openemr/session/<generation>` handle to that variable name. Do not put the value
   in a command argument, shell history, Web variable, repository file, ticket, log, screenshot, or
   evidence artifact; do not reuse the chat-supplied value.
5. **Create lease metadata in the approved provisioning flow.** After the ticket-compliant schema lands,
   write only non-secret metadata for the same immutable reference: generation, absolute not-before,
   absolute expiry, value digest, and exact staging target/version/surface binding. Compute the digest
   inside the secret-provisioning boundary without printing the value. Ensure the lease covers the
   bounded authorization window and never overwrite an already authorized generation.
6. **Record exact target and synthetic inputs.** Produce the current target observation, exact HTTPS
   scheme/host/port and host-allowlist hash, reviewed `POST /chat` surface/version, corpus manifest, and
   synthetic fixture manifest with IDs, hashes, and `synthetic_only:true`.
7. **Establish two real human principals.** Enroll two different MFA-enabled users in the exact staging
   Headshot Clerk Organization: an Operator with launch/abort permissions and a different Approver with
   authorize permission. Preserve only opaque immutable identity references and a secret-safe approval
   trace; never export Clerk session tokens.
8. **Create and verify the immutable campaign grant.** `campaign.json` must bind the current release,
   target/allowlist/surface, corpus/synthetic fixtures, hosted configuration and policies, reviewed smoke
   and unequal Evidence/Security review hashes, complete caps, expiry/nonce, launcher/distinct approver,
   credential-reference hash, and SMART lease metadata. Run the zero-call T-F05c verifier first.
9. **Only after every prior gate passes, consider T-F05b.** Preserve partial evidence on any drift or
   abort. Create a separate `live-stress.json` binding exactly 100 staging cases, its own caps, monitor,
   abort owner, lease, launcher, and distinct approver before T-F07b; never infer or reuse authorization.

Funding and possession of a session do not satisfy any of these gates.
