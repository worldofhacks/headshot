# WP-16C — Declarative custom checks, Search, and Organizer

**Branch:** `rtg/wp16c-custom-checks-search`

**Model:** capable

**Depends on:** WP-11, WP-16A

**Implements toward (live validation pending):** extension/search/organizer portions of RT-06

**Implementation writes only**

- `src/agentforge/security_tools/custom_checks.py`
- `src/agentforge/security_tools/investigation.py`
- `src/agentforge/security_tools/custom_check_repository.py`
- `src/agentforge/security_tools/search.py`
- `src/agentforge/contracts/v1/custom_check.json`
- `src/agentforge/contracts/v1/investigation_record.json`
- `src/agentforge/contracts/v1/search_query.json`

**Test writes only**

- `tests/security_tools/test_custom_checks.py`
- `tests/security_tools/test_custom_check_repository.py`
- `tests/security_tools/test_investigation.py`
- `tests/security_tools/test_search.py`

## Required result

Provide a safe BCheck-like **declarative** check format over sanitized captured messages and
trusted observation fields. The closed grammar may compare typed status/header/JSON/hash/
length/timing/oracle fields and emit advisory signals. It must not execute Python,
JavaScript, shell, templates, regex supplied by users, files, network calls, imports,
deserialization hooks, or dynamic plugins.

This is a passive declarative BCheck subset. Active BChecks, arbitrary request generation,
runtime extensions, and the BApp/Montoya ecosystem remain explicitly unsupported.

Checks are versioned, schema-validated, content-addressed, organization-scoped, reviewed,
and disabled by default. Check output cannot authorize, dispatch, set a Judge verdict,
override severity, publish, or remediate. Limits cover expression depth, operations,
records, runtime, output, and memory.

Persist checks, review decisions, immutable investigation versions, and linked hashes via
an explicit repository over the existing append-only content-addressed artifact store; do
not rely on process memory. If the existing store cannot enforce organization scope and
append-only history without a schema change, return `NEEDS_CONTEXT` for a separately
serialized migration rather than widening this package.

Implement deterministic Search across sanitized captures, templates, observations, tool
artifacts, findings, and regression references using typed fields and bounded literal
queries. Redacted/omitted data remains distinguishable. No secret reconstruction,
cross-organization indexing, unbounded regex, or hostile snippet rendering.

Implement Organizer-style immutable investigation records with tags, bounded plain-text
notes, linked hashes, owner/reviewer identity, and append-only history. Notes remain
advisory and render as hostile text.

Tests cover grammar injection, algorithmic complexity, cross-org access, hostile notes,
redaction, stale references, check tampering/version drift, duplicate results, authority
escalation, and deterministic bounded search.

Direct-validate new schemas in this package; WP-19B owns final registry/package parity.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_custom_checks.py tests/security_tools/test_custom_check_repository.py tests/security_tools/test_investigation.py tests/security_tools/test_search.py -q
```

**Handoff:** WP-20B/WP-20C expose reviewed checks/search/investigations. Runtime arbitrary-code
extensions remain unsupported and must not be labeled equivalent to the Burp BApp/Montoya
ecosystem.
