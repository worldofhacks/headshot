---
id: T-F07a
title: Measure deterministic 100-case full-regression baseline
status: backlog
wave: 5
depends_on: [T-F06a]
branch: ticket/T-F07a-benchmark
file_scopes:
  - scripts/benchmark_platform.py
  - src/agentforge/performance/**
  - docs/performance/local/**
  - .tdd-swarm/baselines.md
test_scopes: [tests/performance/test_platform_benchmark.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf CPU/memory/latency/throughput and SQL/regression SLO
  - docs/requirements/REQUIREMENTS_MATRIX.csv OPT-16, OPT-17
---

## Context
Wave 5 deterministic code consumes T-F06a's replay executor and emitted duration interface to run fixed-seed, network-disabled measurement and produce `docs/performance/local/<sha>/` summaries. `Week_3_AgentForge.pdf`, OPT-16/17, the current release/input hashes, and the human-approved `.tdd-swarm/baselines.md` hash are authoritative.

## Acceptance Criteria
- **AC-1**: Three fixed-seed, network-disabled 100-case plus full-replay runs retain command/env/SHA/input hashes/raw CPU/peak RSS/p50/p95/throughput/storage/critical/full durations.
- **AC-2**: Case order/hashes must match; incomplete/warm-up/missing/fewer-than-100 run exits 2 and is excluded.
- **AC-3**: Human-approved `.tdd-swarm/baselines.md` records metric definitions and thresholds; CI smoke compares same environment class and exits 1 on breach; absent approval blocks promotion.
- **AC-4**: Summary JSON/CSV hashes and bottleneck analysis are stored under `docs/performance/local/<sha>/`; Performance Reviewer recomputes percentiles.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F07a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No target/provider network, live stress, or cost projection.
