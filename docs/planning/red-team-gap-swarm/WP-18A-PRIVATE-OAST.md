# WP-18A — Private, per-attempt OAST evidence

**Branch:** `rtg/wp18a-private-oast`

**Model:** capable

**Depends on:** WP-08, WP-11, WP-16A

**Implements toward (live validation pending):** Collaborator/OAST portion of RT-06

**Implementation writes only**

- `src/agentforge/security_tools/oast.py`
- `src/agentforge/security_tools/oast_receiver.py`
- `src/agentforge/security_tools/oast_repository.py`
- `src/agentforge/storage/models.py`
- `migrations/versions/<MIGRATION_REV>_private_oast.py`
- `src/agentforge/contracts/v1/oast_reservation.json`
- `src/agentforge/contracts/v1/oast_event.json`
- `src/agentforge/contracts/v1/oast_correlation.json`

**Test writes only**

- `tests/security_tools/test_oast.py`
- `tests/security_tools/test_oast_receiver.py`
- `tests/security_tools/test_oast_repository.py`

## Required result

Generate cryptographically random, single-purpose per-attempt tokens; persist token hashes
only. Bind each reservation to organization, target/surface/version, campaign/attempt,
authorization scope, approved callback domain/protocol, TTL, event cap, and synthetic-data
attestation.

The receiver accepts only preregistered tokens. Unknown/expired/exhausted/malformed tokens
receive indistinguishable minimal responses. Persist only bounded protocol/timestamp/
reservation correlation, source-network hash, and sanitized metadata—never body, query,
cookies, Authorization, arbitrary headers, PHI, or attacker text.

Correlation is trusted WP-11 evidence only when token, TTL, authorization, attempt, target,
and integrity all match. It cannot decide severity, verdict, or publication.

Protect against guessing, replay, Host spoofing, cache poisoning, storms, source spoofing,
duplicates, timing enumeration, cross-org access, and retention bypass. Add expiry/reaping
and idempotent ingestion.

Tests may use an in-process receiver and controlled clock only as non-evidentiary
implementation prechecks. They can never establish an operational callback. The existing
public-route policy does not authorize OAST; deployment remains blocked until the owner
approves an explicit architecture/domain change. Operational status requires WP-21D to
observe a genuine correlated callback at the exact deployed authorized domain/receiver.

Direct-validate new schemas in this package; WP-19B owns final registry/package parity.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_oast.py tests/security_tools/test_oast_receiver.py tests/security_tools/test_oast_repository.py tests/test_migrations.py tests/test_readiness_m1d.py -q
```

**Handoff:** WP-20C may show `deployment_blocked`; WP-21A/WP-21D require the separate owner
decision, deployed receiver/domain, and OAST authorization before any callback test.
