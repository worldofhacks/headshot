# Pre-run PostgreSQL/storage baseline — 2026-07-24

## Evidence boundary

This read-only snapshot was captured from the Railway staging PostgreSQL service before the final
release deployment and authorized 100-case campaign. It contains counts and byte sizes only—no row
contents, credentials, session references, prompts, or responses. The deployed schema was still
Alembic `0013`; this is a delta baseline, not evidence for the newer implementation.

## Database total

- `pg_database_size(current_database())`: **11,425,471 bytes**
- Canonical agent executions: **0**
- Finding/evidence links: **0**
- Vulnerability reports: **0**

## Selected relation baselines

`bytes` is `pg_total_relation_size`, including indexes and TOAST storage.

| Relation | Rows | Bytes |
|---|---:|---:|
| `campaign_runs` | 5 | 65,536 |
| `campaign_attempts` | 45 | 147,456 |
| `campaign_authorization_requests` | 5 | 81,920 |
| `campaign_authorization_decisions` | 5 | 49,152 |
| `campaign_run_events` | 15 | 40,960 |
| `attempt_result` | 32 | 229,376 |
| `verdict` | 32 | 65,536 |
| `outbound_http_requests` | 22 | 188,416 |
| `audit_events` | 86 | 98,304 |
| `agent_executions` | 0 | 40,960 |
| `finding` | 0 | 65,536 |
| `finding_evidence_links` | 0 | 24,576 |
| `vuln_reports` | 0 | 40,960 |

## Required post-run comparison

After staging migration and the exact authorized campaign, capture the same database and relation
sizes. Report absolute growth and growth per logical case, physical target request, provider
request, Langfuse observation, finding, and report. Do not divide the whole pre-existing database by
100 or call allocated Railway volume consumed evidence.
