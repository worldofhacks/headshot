# WP-21C — Execute the live LLM, agentic, and native-tool matrix

**Branch:** `rtg/wp21c-live-llm-toolchain`

**Model:** capable

**Depends on:** approved WP-21A manifest admitting this lane

**May close with approved evidence:** live portions of RT-01–RT-05 and RT-07

Read and follow `ROLE-LIVE-EVIDENCE-EXECUTOR.md`. Use only this lane's immutable manifest
entry and exact authorizations.

**Writes only**

- `evals/results/authorized/llm-toolchain/**`
- `docs/evidence/authorized-red-team/llm-toolchain/**`
- `.tdd-swarm/reports/RTG-WP21C-live-llm-toolchain.md`

## Required live matrix

Execute the reviewed B/I/R case matrix against every applicable deployed OpenEMR Clinical
Co-Pilot surface, not a chat approximation:

- chat and multi-turn session behavior;
- live ingestion/indexing and retrieval/RAG with source, tenant, patient, document, chunk,
  and metadata-scope observations;
- live memory/context lifecycle and principal/session switching;
- live tool discovery, selection, arguments, authorization, execution, side effects, and
  rollback;
- exact authorized write/upload sandbox operations on seeded synthetic non-PHI resources;
- rendered HTML/Markdown/URL and downstream sink observations;
- supported provider, inter-agent, approval/handoff, and cascading-failure surfaces.

Cover all applicable OWASP Web, LLM 2025 LLM01–LLM10, Agentic 2026 ASI01–ASI10, and six PRD
categories with the exact reviewed corpus hash. A mapped/authored case is not executed
evidence. Each accepted live attempt needs complete trusted observations, required-oracle
policy satisfaction, an independent decisive Judge result, physical-send/collector ledger
parity, and exact case/surface/principal/state lineage. `INDETERMINATE`, missing observation,
refusal without the required oracle, tool error, or zero candidate does not close coverage.

Run genuine pinned Garak, PyRIT, Giskard, and Promptfoo processes through WP-16D and the
separate WP-13 brokers. For each tool require its exact version, capability inventory,
profile/configuration/native artifact hash, nonzero accepted native record, ordered-turn
lineage, broker and physical-send parity, and independent adjudication. Never call adapter
presence, imported sample output, or a generated profile “tool execution.”

When separately authorized, run provider-backed candidate generation/mutation with
`target_scope:none`, persist the proposed bundle, require the existing distinct human review,
then use a fresh target authorization for the resulting corpus. Generation can never inherit
target authority or silently mutate an active campaign.

Use only live seeded target records and provisioned test principals. Do not use checked-in
response fixtures, replay cassettes, fake brokers/targets, simulated RAG/tool results, local
model servers, or adapter harnesses as evidence. Missing live surface instrumentation is
`BLOCKED_MISSING_LIVE_ORACLE`, not a chat simulation.

Run independent cleanup verification for all authorized live writes/memory/index state.
Return the Live Evidence Executor status contract with per-risk/surface/tool evidence hashes,
request/turn/generation counts, cost, verdict distribution, and blockers.
