# Final release binding ledger

Status: **pre-release — all final values below are pending unless explicitly marked historical**.

This ledger is filled atomically from retained release artifacts after the candidate is assembled.
The packet preparation base, `f39e22722d3b4e256110ac5be5ce160a0ad654e4`, is not the shipped SHA.

## Source and build

| Field | Required value | Current value |
|---|---|---|
| Final release SHA | Exact 40-character commit | `pending` |
| GitHub `main` | Must equal final release SHA | `pending` |
| GitLab `main` passive mirror | Must equal final release SHA | `pending` |
| GitHub Actions run | URL and all required checks green on final SHA | `pending` |
| Alembic heads | Exactly one | Preparation base: `0021`; release target: `0022` pending integration |
| Container image digest | Immutable digest built from final SHA | `pending` |
| Dependency manifest hashes | SHA-256 values from final SHA | `pending final-SHA refresh` |

## Staging proof

Historical Railway state observed while this packet was prepared:

| Service | Source identity | Image digest (abbreviated) | Public route |
|---|---|---|---|
| Web | `2069036e` | `sha256:77f43ce5…bbdc` | Yes |
| Runner | `2069036e` | `sha256:8cb818…bcc9` | No |
| Scheduler | `2069036e` | `sha256:98860d…e078` | No |

These abbreviated historical digests are not substitutes for the full digest of the pending final
candidate.

| Field | Required value | Current value |
|---|---|---|
| Deployment ID and image digest | Exact final candidate | `pending` |
| Database before → after | Exact revisions; after must be `0022` | Historical proof: `0013 → 0021` at `2069036e`; final proof pending |
| Runner-first health | Runner healthy after migration before Web activation | `pending` |
| Public Web checks | `/health` 200, `/ready` 200, protected route 401, console shell loads | Historical proof exists for `2069036e`; final proof pending |
| Private topology | Runner, Scheduler, and PostgreSQL have no public route | `pending final-candidate recheck` |
| Blank-surface contingency | If blank, Web-only rollback while Runner/data remain | Procedure defined; execution `not applicable` unless triggered |

## Hosted configuration and Judge gate

These fields are sequential. A later field cannot be accepted when an earlier one is pending or
different.

| Field | Required value | Current value |
|---|---|---|
| Staged four-role configuration | Canonical set bound to final release SHA | `pending` |
| Command acknowledgement | `resource_id` equals independently recomputed `configuration_sha256` | `pending` |
| Runner sealed bindings | All four OpenRouter references resolve for that hash; no value is recorded here | `pending` |
| Runner Langfuse readiness | Authenticated and heartbeat `operational and evidenced` for the same hash | `pending` |
| Agents read model | Same configuration hash, provider `openrouter`, exact requested/returned role identities | `pending` |
| Judge calibration handoff | Observed provider/model/version/criteria/implementation and Red Team identity plus `identity_sha256` | `pending` |
| Re-attestation | Versioned ground-truth slices and thresholds; content-addressed passing artifact | `pending` |
| Human enablement | Same identity; `human_approved=true`, `runtime_enabled=true` | `pending` |

Missing, failed, passed-but-not-enabled, invalidated, drifted, or hash-mismatched calibration blocks
campaign authorization and launch. It does not degrade to an advisory campaign.

## Production proof

Historical Railway state observed while this packet was prepared:

| Service | Source identity | Image digest (abbreviated) | Public route |
|---|---|---|---|
| Web | `23490ea` | `sha256:4bdfb1…551c7` | Yes |
| Runner | `23490ea` | `sha256:806d42…f55d` | No |
| Scheduler | `23490ea` | `sha256:0983d5…60b67` | No |

| Field | Required value | Current value |
|---|---|---|
| Pre-release identity | Current production commit and schema | Historical: `23490ea`, `0013` |
| Deployment ID and image digest | Exact final candidate | `pending` |
| Runner-first migration and health | Schema `0022`, healthy private Runner before Web | `pending` |
| Web activation checks | Health/ready 200, protected route 401, console loads | `pending` |
| Scheduler/private topology | Healthy and private | `pending` |

No database-backup artifact is required for this synthetic assignment. Safety is provided by the
clean staging migration proof, additive serialized migrations, service quiescence during migration,
and compatible image rollback. A blank Web surface triggers Web-only rollback; Runner and data stay
in place while the surface is investigated.

## Governed campaign and evidence

| Field | Required value | Current value |
|---|---|---|
| Launcher principal | Authenticated immutable user ID | `pending` |
| Approver principal | Authenticated immutable user ID, different from launcher | `pending` |
| Operation/corpus/config/policy hashes | Exact reviewed values | `pending` |
| Caps | Logical case count, physical turn sum, retries `0`, hard USD cap | `pending final corpus authorization` |
| Campaign/run IDs | Exact durable identifiers | `pending` |
| Four-role executions | Ordered Orchestrator, Red Team, Judge, Documentation rows | `pending` |
| Provider/model identities | Exact returned identities | `pending` |
| Langfuse reconciliation | Expected/observed/missing/extra and verification timestamp | `pending` |
| Finding manifest | Content hash and regenerated severity/count summary | `pending` |
| Publication decisions | Human approval for every finding/report severity; distinct raiser/approver lineage | `pending; no report is publication-authorized by this packet` |
| Performance report | Content hash; p50/p95, throughput, memory and method | `pending` |
| Usage and invoice exports | Redacted hashes and measured totals | `pending` |

## Publication

| Field | Required value | Current value |
|---|---|---|
| Submission manifest hash | Content-addressed manifest derived from retained artifacts | `pending` |
| Demo video URL | Human-owned 3–5 minute final recording | `pending` |
| Social post URL | Published post after evidence reconciliation | `pending` |
