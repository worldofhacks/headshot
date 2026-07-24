# T-F17a Test Design Review

Status: `REVIEW_CHANGES_REQUIRED`

Freeze: `NOT_FROZEN`

Reviewed commit: `236774123bcbfbd5801b57fcc65939e17e8f58ae`

Reviewed test snapshot:

- `tests/test_agent_prompts.py`:
  `dfac53abf2900430d316234e7c2148c706847bd28d7878737abccd8b25ab6949`
- `tests/test_packaging.py`:
  `0177cf51e46a6711154dc58fd29b2696b5b2ad563bccd56c257bc4cd0377f424`
- `.tdd-swarm/reports/T-F17a-test.md`:
  `bf83cbf02affc2893ed0fd330c38ab8943334bf11a1fec6f42d3b99aba43f66a`

These hashes identify the rejected review snapshot; they are not frozen implementation
contracts.

## Authority and scope

The four exact role/model assignments in the tests match the locked table in
`docs/planning/agent-runtime-provenance.md`:

| role | model |
|---|---|
| `orchestrator` | `anthropic/claude-opus-4.8` |
| `red_team` | `qwen/qwen3.5-397b-a17b` |
| `judge` | `google/gemini-2.5-pro` |
| `documentation` | `openai/gpt-5.4` |

The prompt-boundary clauses trace to the same plan and to the distinct-role, Judge-independence,
model-choice, and AI-verification requirements in `Week_3_AgentForge.pdf`. The changed tests do
not exercise provider-message transport (T-F17c) or prompt API/UI authorization and rendering
(T-F17f).

## Important findings

### I-1 — One new test is GREEN before T-F17a exists

`tests/test_agent_prompts.py:109-111` asserts only the already-landed
`HOSTED_ROLE_MODELS`. It passes on the RED base:

```text
tests/test_agent_prompts.py::test_spec_T_F17a_AC_1_locked_role_model_assignments_cannot_drift
1 passed
```

The TDD-swarm Test Agent contract requires every new test to fail because the ticket feature is
missing. The Test Agent report's `6 failed, 1 passed` therefore cannot support its final claim of
clean RED.

Required repair: bind the exact model table assertion to the new four-role prompt-registry
identity in a test that is RED while the registry is absent. Do not add any provider invocation or
transport behavior.

### I-2 — The purported offline wheel RED is environment-dependent and fails for the wrong reason

`tests/test_packaging.py:160-165` uses an isolated pip build that may fetch build requirements, and
`tests/test_packaging.py:202-209` asks the fresh environment to install `jsonschema>=4` from an
index. Neither subprocess encodes the report's claimed local wheelhouse. With network disabled by
`PIP_NO_INDEX=1`, the reviewed test fails before building the wheel:

```text
ERROR: Could not find a version that satisfies the requirement setuptools>=68
FAILED at tests/test_packaging.py:165
```

That is setup/build-isolation RED, not T-F17a's missing manifest/resource RED. It also contradicts
the deterministic zero-network contract.

Required repair: make build and install mechanically offline and self-contained (for example,
disable build isolation with already-verified local build tooling and install the produced wheel
with `--no-index --no-deps`, while supplying `jsonschema` through a deterministic local
environment). Re-run with network disabled and prove that the first failure is the missing prompt
manifest/resource, not dependency acquisition.

### I-3 — Zero-network behavior is guarded on only one in-process path

The socket guard at `tests/test_agent_prompts.py:80-85` is installed only by the hostile-bundle
test at lines 220-239. Normal registry loading, exact-identity lookup, trust-boundary inspection,
unsafe-resource-name validation, and the installed-wheel probe execute without a network guard.
A registry that performs network I/O only during `load_prompt_registry()` can pass the reviewed
suite.

Required repair: apply a zero-network guard to every new registry/lookup/validation path and make
the isolated installed-wheel probe deny network before importing/loading the registry. Package
build and install must also remain offline as required by I-2.

### I-4 — Immutable identity and hostile swaps are under-tested

At `tests/test_agent_prompts.py:104-105`, only `content` mutation is attempted and the test
requires the dataclass-specific `FrozenInstanceError`; it does not prove that `role`, `version`,
and `sha256` are immutable. The lookup test exercises only one cross-role combination at line 124,
and bundle validation exercises only one Orchestrator/Judge content swap at lines 160-172. A lazy
implementation can special-case those examples while accepting other role/resource/hash swaps.

Required repair:

- prove all four record identity fields remain unchanged after hostile mutation attempts without
  prescribing a dataclass as the only valid immutable representation;
- exercise every cross-role prompt identity swap, not one selected pair;
- exercise manifest role/resource/hash swaps across the four-role catalog; and
- connect each exact locked model assignment to its corresponding registry role identity.

These remain pure registry/configuration tests; do not reach T-F17c transport.

### I-5 — “No prompt fragment” assertions allow partial disclosure

For missing, duplicate, and role-mismatched cases, `_invalid_bundles()` supplies an entire prompt
as `private_fragment` (`tests/test_agent_prompts.py:141-147,160-172`). The assertion at lines
235-239 rejects only disclosure of that complete byte sequence. An exception may reveal a prefix
or any other proper substring and still pass. A bounded probe confirmed that leaking
`AgentForge system role: judge\nPr` is not detected.

Required repair: give every resource one or more short unique leak canaries and assert that none
appears in either `str(error)` or `repr(error)` for every hostile case. Preserve generic,
content-free failures for missing, duplicate, altered, mismatched, invalid-UTF-8, oversized,
secret-shaped, unmanifested, and traversal-shaped inputs.

## Minor finding

`tests/test_agent_prompts.py:102,190-193` freezes an undocumented public
`MAX_PROMPT_BYTES` symbol and an unexplained 256-byte minimum. The ticket requires bounded prompt
size, but it does not define that public API or minimum. Either lock the numeric contract in the
ticket/planning authority or express the oversized behavior without requiring an unrequested
public implementation symbol.

## Bounded review evidence

- Focused registry RED: `6 failed, 1 passed`; all six failures are the explicit missing-registry
  assertion, with no collection or fixture error.
- Offline wheel check with `PIP_NO_INDEX=1`: failed at build dependency acquisition, before the
  prompt manifest assertion.
- Existing hosted-configuration and non-wheel packaging checks: `14 passed`.
- Collection: `tests/test_agent_prompts.py: 7`, `tests/test_packaging.py: 5`.
- Ruff check on both owned test files: passed.
- Diff check from the RED commit: passed.

Verdict: Critical findings: `0`; Important findings: `5`; Minor findings: `1`.
The tests must return to the Test Agent, then receive a fresh independent review and new hash
freeze before implementation begins.
