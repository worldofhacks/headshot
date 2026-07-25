# WP-08 — Verify signed, scoped, expiring target ownership authorization

**Branch:** `rtg/wp08-ownership-authorization`

**Model:** capable

**Depends on:** `<RED_TEAM_GAP_BASE_SHA>`

**Implements toward (live validation pending):** part of RT-14

Read target catalog/spec/binding, authorization records, deployment requirements, and the
RT-14 prefix-check finding.

**Implementation writes only**

- `src/agentforge/target/authorization.py`
- `src/agentforge/target/catalog.py`
- `pyproject.toml` only if a reviewed pinned signature dependency is necessary
- `docs/deployment/RAILWAY.md`

**Test writes only**

- `tests/target/test_ownership_authorization.py`

## Required result

Replace the `authorization://` prefix check with a typed, versioned, detached-signature
record binding:

- authorization ID, issuer, key ID, algorithm;
- target ID and environment;
- exact hosts and surface IDs/methods/paths;
- exact approved IP/CIDR/network references for any private staging destination;
- not-before and expiry;
- terms/evidence hash;
- canonical payload version.

Use a standard reviewed primitive such as Ed25519; never implement cryptography manually.
Runtime receives public verification keys only. Reject unknown fields, algorithms/keys,
noncanonical payloads, malformed encodings, signature confusion, wildcard scope, time
failure, target/surface drift, and cross-environment replay.

Ownership authorization is necessary but never sufficient for campaign approval. It cannot
create, approve, launch, widen, or publish a run. A platform-owned offline record may
authorize only a non-network implementation precheck, must be excluded from the deployed
executable catalog, and cannot validate or evidence a live entry.

Tests use ephemeral test keys and an injected clock. No live key, owner signature, private
key, or fabricated production record may be committed.

WP-21A/WP-21B must verify a genuine exact owner authorization for the deployed URL and
surfaces before live status or RT-14 closure.

**Focused verifier**

```bash
python -m pytest tests/target/test_ownership_authorization.py tests/target/test_target_registry.py tests/target/test_target_spec.py -q
```

**Security focus:** canonicalization, malleability, key-ID injection, wildcard scope,
clock boundaries, cross-target replay, and synthetic-to-live substitution.

**Handoff:** WP-03 must wire this verifier into Runner preflight and every WP-01 physical
permit; WP-06/WP-20A consume that integration. This package defines and tests the verifier
only to preserve Wave 0 file ownership.
