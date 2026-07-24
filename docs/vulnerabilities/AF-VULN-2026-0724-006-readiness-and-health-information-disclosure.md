# AF-VULN-2026-0724-006 — Unauthenticated readiness/health endpoints disclose internal architecture

> **Status: DRAFT — not published.** Publishing is a separate two-person human-approval gate
> (approver ≠ launcher). Drafted autonomously by the Documentation agent; awaiting review.
> **Disposition: LOW–MEDIUM — information disclosure / security misconfiguration (config finding).**

| Field | Value |
|---|---|
| Report ID | `AF-VULN-2026-0724-006` (unique) |
| Severity | **Low–Medium** (recon-grade information exposure) |
| Category | Information disclosure · Security misconfiguration |
| OWASP Web | `A05:2021` Security Misconfiguration (CWE-200 exposure of sensitive information) |
| OWASP LLM | `LLM02:2025` Sensitive Information Disclosure (reveals the AI/RAG stack: model provider, reranker, graph state) |
| Target | Clinical Co-Pilot — `https://agent-production-9f62.up.railway.app` |
| Campaign | Bruno `week1` + `week2` collections (authorized synthetic live run, 2026-07-24) |
| Judge verdict | `INDETERMINATE` (configuration finding, not an oracle-confirmed exploit) |

## Description & clinical impact
The public, unauthenticated `GET /ready` endpoint returned a full internal **dependency topology**
in its body — the exact set of backing services, their trust classification (`hard`/`soft`), and
per-dependency status detail. Observed verbatim (both weeks, identical):

```
openemr_fhir (hard, "HTTP 200")        anthropic (hard, "HTTP 200")
session_store (hard, "ok")             langfuse (soft, "HTTP 200")
retrieval_index (soft, "ok")           active_reranker (soft, "ok")
document_runtime (hard, "ready")       document_category_read (hard, "authorized_read_ok")
graph_state (soft, "graph_enabled")
```

This tells an anonymous caller the co-pilot is backed by an **OpenEMR FHIR** record system, the
**Anthropic** model provider, a **Langfuse** observability pipeline, a **retrieval index + active
reranker** (RAG), and a **graph state** engine — a precise map for planning further attacks
(which dependency to target, which are "hard" vs "soft", whether reads are authorized). Separately,
`GET /health` returned the **exact deployed build commit SHA** (a full 40-character git hash, e.g.
`d15c21da…`), letting an attacker pin the running version to a specific source revision and its
known issues.

Clinical impact is indirect but real for a "defend it to a hospital CISO" posture: unauthenticated
architecture and version disclosure lowers the cost of a targeted attack against a system that
brokers patient data, and it is trivially avoidable.

## Minimal reproduction sequence
```
curl -s https://agent-production-9f62.up.railway.app/ready
# -> 200; body enumerates openemr_fhir, anthropic, session_store, langfuse, retrieval_index,
#    active_reranker, document_runtime, document_category_read, graph_state (name/kind/ok/detail).

curl -s https://agent-production-9f62.up.railway.app/health
# -> 200; body includes {"status":"alive","sha":"<full 40-char build commit SHA>"}.
```

## Observed vs expected
| | |
|---|---|
| **Expected** | An anonymous liveness/readiness probe returns a minimal status (e.g. `ok`/`ready` + a boolean aggregate). Internal dependency names, trust tiers, per-dependency detail, and the exact build SHA are reserved for authenticated operators/observability. |
| **Observed** | `/ready` enumerates nine internal dependencies with kinds and detail strings; `/health` returns the full build commit SHA — both fully unauthenticated. |

## Recommended remediation
1. **Split the probes.** Keep `/health` and `/ready` returning only a coarse status/HTTP code to
   anonymous callers; move the detailed dependency envelope behind operator authentication
   (`org:console:read` / observability), or gate it to internal networks only.
2. **Stop returning the exact build SHA** on the public `/health`; expose version detail only to
   authenticated operators.
3. Keep the useful hard/soft dependency model for the authenticated readiness view — the fix is
   about *audience*, not removing the signal.

## Current status & fix-validation
Status **open — Low–Medium**. Directly observed from the captured live `/ready` and `/health`
response bodies (both weeks). No adversarial exploit was oracle-confirmed (Judge `INDETERMINATE`);
this is an information-exposure/config finding. Fix-validation: **not run** (awaiting remediation).
