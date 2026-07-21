# Headshot

Headshot is a target-agnostic, multi-agent platform for continuously discovering, evaluating,
recording, and regression-testing adversarial behavior in AI applications. The OpenEMR Clinical
Co-Pilot is the first target, not the product boundary: target-specific behavior belongs behind a
`TargetAdapter`, while the evaluation contracts, policy controls, evidence model, Judge, and corpus
remain reusable.

> **Synthetic data only.** Never use real PHI, production patient records, live credentials, or an
> unapproved target. A configured URL or loaded credential is not authorization.

This repository currently proves the secure spine offline. It contains no authorized live-campaign
result and makes no claim that the MVP live gate has been crossed.

## Architecture and trust boundaries

```text
Orchestrator
    │ campaign scope and caps
    ▼
Red Team (untrusted) ── AttackAttempt ──► Policy Gateway + Execution Recorder (trusted)
                                              │ authorized, allowlisted dispatch
                                              ▼
                                      External target (untrusted output)
                                              │ hashed recorded evidence
                                              ▼
                                      Independent Judge (governed)
                                              │ validated Verdict
                                              ▼
                                Documentation / regression / human gates
```

The Red Team can generate and mutate hostile inputs but cannot hold target credentials, publish a
finding, or judge its own work. The trusted Policy Gateway is the only intended dispatch boundary;
the Execution Recorder owns canonical, append-only evidence. Target output remains hostile data.
The independent Judge evaluates a typed evidence envelope and has no target, mutation, publication,
or remediation capability.

Verdict precedence is deterministic and outside any model:

1. Missing, malformed, contradictory, timed-out, uncalibrated, or integrity-failed evidence is
   `INDETERMINATE` or `ERROR`, never safe.
2. A verified oracle or synthetic-canary hit produces `EXPLOIT_CONFIRMED`.
3. A model may evaluate only inconclusive evidence and may never downgrade deterministic
   confirmation.

Headshot therefore **fails closed on the verdict, not the campaign**: an ambiguous attempt is parked
for review while unrelated authorized work may continue. A human must approve publication of a
critical finding and any remediation action. Those gates are separate from campaign-launch
authorization.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the binding design and
[THREAT_MODEL.md](THREAT_MODEL.md) for the target attack surface and versioned OWASP mappings.

## Current capability status

Status below is scoped to source commit `075a7ec`.

| Capability | Current state |
|---|---|
| Contracts and storage | Versioned, packaged contracts; Postgres migrations, role separation, append-only evidence schema, and replay constraints are exercised offline. |
| Policy and target components | Policy Gateway, Recorder, deterministic fake, OpenEMR adapter, and network-free preflight components exist and have deterministic tests. A production campaign coordinator does not yet wire them into an authorized live path. |
| Red Team and Judge | Seed replay/mutation seams and a deterministic independent Judge exist. Oracle precedence and hostile-envelope containment are tested offline; hosted inference has not been run. |
| Evaluation corpus | Nine synthetic, not-executed seeds across prompt injection, data exfiltration, and tool misuse; three ground-truth slices with fifteen labels; no duplicate sequences. |
| Observability | Local tracing, reconciliation, coverage, alert interfaces, and redaction tests exist. Cloud observability and durable live-run monitoring are not configured. |
| Live results and final roles | No live result artifacts or vulnerability reports exist. A bounded live runner, immutable run manifest, Orchestrator, Documentation Agent, and full regression workflow remain pending. |

The [integration packet](docs/integration/INTEGRATION_PACKET.md) records the offline component history
and evidence. Authored expectations and ground-truth labels are not observed results; see the
[result boundary](evals/results/README.md).

## Deployed synthetic target URL

**Synthetic-data demo instance:**

`<DEPLOYED_SYNTHETIC_TARGET_URL — REQUIRED BEFORE MERGE>`

This placeholder is not a runnable target and must be replaced with the public URL of the authorized
synthetic-data demo instance before merge. Do not substitute a mock URL and call it the live gate.

## Local setup

Prerequisites are Python 3.12+ and, for the full storage suite, Docker with Compose.

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
docker compose up -d postgres
```

The dependency-install commands may contact the configured package index. Tests, corpus validation,
and the deterministic fake do not contact a target or hosted model.

### Safe `.env.example` use

Offline tests need no target or provider secret. If local configuration is required, create only the
ignored local file and confirm Git ignores it:

```sh
(
  set -eu
  if [ -e .env.local ] || [ -L .env.local ]; then
    echo '.env.local already exists; refusing to overwrite' >&2
    exit 1
  fi
  (umask 077; cp .env.example .env.local)
  chmod 600 .env.local
  git check-ignore -q .env.local
)
```

Use synthetic/local values only unless a separate live campaign has been explicitly authorized.
Never commit `.env.local`, paste it into logs or tickets, copy real values into `.env.example`, or
source it into an untrusted shell. Local mode may load `.env.local`; staging and production must use
environment-scoped secret references instead.

## Offline verification

Run the repository's consolidated local gate from an activated environment:

```sh
bash scripts/check.sh
```

That runs Ruff lint and format checks, corpus/schema and duplicate validation, the full test suite,
and the tracked-file secret scan. No type checker is configured at this commit, so no type-check claim
is made.

Focused commands are:

```sh
ruff check .
ruff format --check .
pytest
pytest tests/contract -q
```

### Corpus validation

```sh
PYTHONPATH=src python -m agentforge.evals validate-corpus evals
PYTHONPATH=src python -m agentforge.evals detect-duplicate-sequence evals/seeds
```

Expected corpus summary at this commit is nine cases, fifteen ground-truth labels, three categories,
one fixture, and no duplicate input sequences.

### Packaging and containers

The wheel isolation gate may download build dependencies but does not contact a target or model:

```sh
bash scripts/wheel_outside_repo_check.sh
```

The CI-equivalent image and in-container corpus checks are:

```sh
docker build -t agentforge:local .
docker run --rm --entrypoint python \
  -v "$PWD/evals:/corpus:ro" agentforge:local \
  -m agentforge.evals validate-corpus /corpus
docker run --rm --entrypoint python \
  -v "$PWD/evals:/corpus:ro" agentforge:local \
  -m agentforge.evals detect-duplicate-sequence /corpus/seeds
```

For the local app and Postgres stack:

```sh
docker compose up --build
```

`GET http://127.0.0.1:8000/health` is the liveness endpoint. At `075a7ec`, the ASGI entrypoint's
schema-readiness check remains fail-closed, so `/ready` returns `503 not_ready`; do not use it as a
successful deployment claim.

## Authorized campaign launch

There is **no supported live-campaign command at `075a7ec`**. The repository ships offline validators
and a presence-only `scripts/preflight_status.py`, but that report neither grants authorization nor
dispatches a campaign. Direct construction of the adapter or Gateway is not a supported launch path.

A future bounded command may be used only after it implements all of these gates:

1. Record explicit, expiring human authorization scoped to the exact target host, corpus/version,
   operator, run nonce, and immutable caps.
2. Resolve an immutable allowlist binding for target ID, exact HTTPS host, adapter, and credential
   reference; confirm synthetic provenance and canary/oracle availability.
3. Parse finite positive budget, attempt, rate, and timeout values, enforce hard policy maxima, and
   prove the durable abort/monitoring path.
4. Pass the offline quality and corpus gates, then execute only through the trusted Gateway/Recorder.
5. Persist an immutable run-config manifest, hashed `AttemptResult` evidence, correlated validated
   Verdicts, abort/degraded state, and a result manifest.

The exact launch command and output paths are intentionally **TBD until that runner exists**. No one
should infer live outcomes from the corpus or populate result fields by hand.

## Vulnerability reports

No live vulnerability report has been produced. The required report set remains pending an authorized
campaign, verified results, and human publication approval. This section is the stable link target until
the planned `docs/vulnerabilities/` artifacts exist.

## Project references

- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Integration packet](docs/integration/INTEGRATION_PACKET.md)
- [Vulnerability reports](#vulnerability-reports)
- [Cost analysis](docs/cost/COST_ANALYSIS.md)
