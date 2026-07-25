# WP-09 — Generate security-tool status from authoritative evidence

**Branch:** `rtg/wp09-authoritative-evidence-status`

**Model:** capable

**Depends on:** `<RED_TEAM_GAP_BASE_SHA>`

**Implements toward (live validation pending):** evidence-drift portion of RT-14

Read checked-in ZAP artifacts, ATO evidence, tool repository/contracts, both CI systems,
and the RT-14 status-drift finding.

**Implementation writes only**

- `src/agentforge/evidence/status.py`
- `scripts/check_evidence_status.py`
- `docs/evidence/status.v1.json`
- marked generated sections only in `docs/evidence/zap/README.md`
- marked generated sections only in `docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`
- `.github/workflows/ci.yml`
- `.gitlab-ci.yml`

**Test writes only**

- `tests/test_evidence_status.py`

## Required result

Create a versioned status index recording exact artifact path/hash, tool/version/config,
run mode, target classification, authorization reference and verification level
(`recorded` or `cryptographically_verified`), execution state, review state, publication
state, and provenance. Free-form `AUTHORIZATION.md` can be `recorded`, never upgraded to
cryptographically verified. Bind the authorization evidence hash, exact target origin/
surface/version, caps, nonce, not-before, expiry, and verifier identity. Verify every
referenced hash.

The current ZAP artifact must resolve narrowly as live-target, unauthenticated, passive,
authorized, unvalidated, and publication-blocked—not active, confirmed, or globally green.

Generate deterministic bounded Markdown sections from the index. `--check` must fail for
missing artifacts, hash drift, malformed/duplicate/contradictory records, unsupported
states, hand-edited generated text, path escape, or absent authorization. Historical prose
must not override current machine status. `--check` also rejects contradictory current-
status claims outside generated markers rather than leaving stale “operational” prose.

CI check mode performs no network or artifact mutation. Never rerun a scan or edit raw
scanner artifacts in this package.

**Focused verifier**

```bash
python -m pytest tests/test_evidence_status.py -q
python scripts/check_evidence_status.py --check
```

**Security focus:** symlink/path escape, hash substitution, duplicate precedence,
Markdown injection, status escalation, secret leakage, and GitHub/GitLab parity.

**Handoff:** WP-20B/WP-20C consume this status source; no hand-maintained “operational”
claims.
