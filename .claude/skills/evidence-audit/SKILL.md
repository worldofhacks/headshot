---
name: evidence-audit
description: Audit checkpoint completeness against the requirements matrix and assemble the submission evidence packets. Use this WHENEVER the user says "audit the checkpoint", "what's missing before submission", "assemble the ATO packet", "assemble the integration packet", or "verify the AI-use disclosure". It reports what is built / tested / evidenced versus what is missing per checkpoint, and verifies the AI-use disclosure in ARCHITECTURE.md is complete and current. This is a completeness + assembly audit over existing artifacts — NOT authoring new architecture (arch-finalize) and NOT writing individual vuln reports (vuln-report).
---

# Evidence Audit

Graded deliverables get discovered-missing at submission time unless something tracks them. This skill is
that tracker: a completeness audit against `docs/requirements/REQUIREMENTS_MATRIX.csv`, plus assembly of
the two evidence packets the reviewer expects.

## When this runs
"audit the checkpoint", "assemble the ATO / integration packet", "verify the AI-use disclosure", before a
checkpoint submission.

## Completeness audit
For each requirement in the matrix, report **built · tested · evidenced** vs **missing**, per checkpoint
(Defense / MVP / Final). Missing graded items are surfaced as a list, not a summary. De-risk the
"Optional Engineering Deliverables are mandatory" surface specifically.

## ATO-style evidence packet (a distinct submission artifact — not ARCHITECTURE.md)
Assemble: architecture + data-flow diagram · **auth-model matrix** (each agent → the targets/credentials
it may use, via the Policy Gateway) · **dependency list with versions** · **self-scan** (Semgrep + the
platform's eval suite run against itself) · test evidence (platform tests + eval results) · a **sample
incident/postmortem** built from the failure-modes section.

## Integration packet
Assemble: interface diffs (including the RedTeam→Judge → mediated-chain correction) · correction ADRs ·
both-sided contract-test results · a cross-agent dependency map · an end-to-end trace proving correctness
through the full platform, anchored on the finding's lineage.

## AI-use disclosure verification
Confirm ARCHITECTURE.md §15 lists every AI-powered role, the deterministic verification or human gate that
follows each AI decision, the residual risk, and specifically **how a drifting Judge is detected and
corrected**. Flag anything stale or missing.

## Key rule
Nothing graded is discovered missing at submission. Every packet is assembled from existing, verifiable
artifacts — this skill audits and assembles; it does not invent evidence.
