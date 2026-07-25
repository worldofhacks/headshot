# Dependency and version inventory

Inventory preparation base: `f39e22722d3b4e256110ac5be5ce160a0ad654e4`

This is not a final-release attestation. Refresh hashes and the deployed image digest after the
release candidate is assembled. This inventory distinguishes an exact pin from a lower-bound
constraint; a lower bound is not a reproducible resolution.

## Runtime and container substrate

| Component | Declared version | Pin quality | Source |
|---|---|---|---|
| AgentForge package | `0.1.0` | Exact application version | [`../../../pyproject.toml`](../../../pyproject.toml) |
| Python | `>=3.12`; container `3.12.11-slim-bookworm` | Container tag pinned, image digest not pinned | [`../../../pyproject.toml`](../../../pyproject.toml), [`../../../Dockerfile`](../../../Dockerfile) |
| Node build stage | `22.17.1-bookworm-slim` | Tag pinned, image digest not pinned | [`../../../Dockerfile`](../../../Dockerfile) |
| PostgreSQL | `16` | Major version only, image digest not pinned | [`../../../compose.yaml`](../../../compose.yaml), GitHub CI |
| Railway processes | Web, Runner, Scheduler from the same image | Commands pinned in repository; external deployment revision pending | [`../../../railway/`](../../../railway/) |
| OWASP ZAP image | `2.17.0`, Linux AMD64 digest `sha256:c558ee87358911ab17278c70991e856f57793e115d9cd0f88ca475cf82907a1a` | Exact digest | [`../../../security-tools/toolchain.lock.json`](../../../security-tools/toolchain.lock.json) |

## Python direct dependencies

| Dependency | Manifest constraint | Use |
|---|---|---|
| FastAPI | `>=0.111` | Web API and dependency enforcement |
| Uvicorn | `>=0.30` | ASGI server |
| psycopg binary | `>=3.1` | PostgreSQL driver and readiness |
| python-dotenv | `>=1.0` | Explicit local environment-file loading |
| SQLAlchemy | `>=2.0` | Storage and repositories |
| Alembic | `>=1.13` | Single schema migration path |
| jsonschema | `>=4` | Runtime inter-agent/eval contract validation |
| httpx | `>=0.27` | Target adapter HTTP transport |
| clerk-backend-api | `6.0.1` | Networkless human request authentication |
| langfuse | `4.14.1` | OTEL-native agent/target observation projection and query-back |

Development constraints are Ruff `==0.16.0`, pytest `>=8`, and pre-commit `>=3`. Ruff is pinned
because 0.15.x and 0.16.x format tagged Markdown code fences differently.

**Supply-chain limitation:** the repository has no committed Python resolution lock or hashes for the
application dependency graph. Only Clerk and Langfuse are exact direct pins; the remaining direct and
all transitive Python versions may change on a fresh build. Before production, generate and review a
hash-locked Python resolution for Python 3.12, rebuild from it, rerun `pip-audit`, and bind the resulting
image digest to the release.

## Frontend direct dependencies

`console/package-lock.json` uses lockfile version 3 and contains 765 package entries, including the
root package. Direct versions are exact:

| Runtime dependency | Version |
|---|---:|
| `@clerk/clerk-js` | `6.25.6` |
| `@clerk/react` | `6.12.6` |
| `@clerk/ui` | `1.25.6` |
| `react` | `18.3.1` |
| `react-dom` | `18.3.1` |

| Development dependency | Version |
|---|---:|
| `@playwright/test` | `1.61.1` |
| `@testing-library/react` | `16.3.2` |
| `@types/react` | `18.3.31` |
| `@types/react-dom` | `18.3.7` |
| `@vitejs/plugin-react` | `5.2.0` |
| `jsdom` | `29.1.1` |
| `typescript` | `5.9.3` |
| `vite` | `7.3.6` |
| `vitest` | `4.1.10` |

The lock also overrides `uuid` to `11.1.1`.

## Security-tool inventory

| Tool | Exact version or artifact |
|---|---|
| Garak | `0.15.1` with LiteLLM constraint `1.84.0` |
| Giskard Scan | `1.0.0b3`; wheel SHA-256 `38ecd28d91e2f28962b413545b76030db2081ff142aa140dd36f5539a77b0da3` |
| Gitleaks | `8.30.1` |
| pip-audit | `2.10.1` |
| Promptfoo | `0.121.19` |
| PyRIT | `0.14.0` |
| Semgrep | `1.170.0` |
| OWASP ZAP | `2.17.0`; exact image digest listed above |

Exact execution scope and evidence are in
[`SECURITY_TOOL_EVIDENCE.md`](SECURITY_TOOL_EVIDENCE.md).

## Manifest integrity hashes

These SHA-256 values identify the files in the inspected source baseline; they are not substitutes
for a signed release or container digest.

| Manifest | SHA-256 |
|---|---|
| `pyproject.toml` | `3712fc50824f60b08ae36ec61b92a889a89b35604a8604df4f089ebfeeec4777` |
| `console/package-lock.json` | `67ba981b416804eb6aff511d8a3c95044475ca8bc304ea70e4f1df15aa1494ae` |
| `security-tools/toolchain.lock.json` | `c35dd73014dc72d3455de93ae685c8d669ebfc92ff78c33a5d91168fdc094d95` |
| `Dockerfile` | `12384162042ec58870c8f6cb73d2893a46590535f5557cc43b3af6ca53e672fd` |
| `compose.yaml` | `425732f0633b503d415b2ddac8a6a95bb604e6ad938f511b9bc7bfde0e4f59cb` |

## Versioning and migration posture

The package ships 18 v1 JSON Schemas under
[`../../../src/agentforge/contracts/v1/`](../../../src/agentforge/contracts/v1/). Producer and
consumer conformance is exercised by `tests/contract`. Breaking inter-agent changes require a new
schema version, compatibility analysis, migration note, and updated both-sided tests.

Alembic has one serialized head at `0021` in the preparation base. Migration notes and compatibility
references are indexed in
[`../../integration/INTEGRATION_PACKET.md`](../../integration/INTEGRATION_PACKET.md). Staging
historically reached `0021`; production remains at `0013`. The release target is the incoming
revision `0022`, which must be reconciled onto the current integration line and reverified as the
single head before any final inventory is signed.

## Architecture-to-manifest reconciliation

- No LangGraph package or Postgres checkpoint dependency is declared in `pyproject.toml`. The current
  source uses its own durable coordinator/queue/runtime composition; any older architecture statement
  that presents LangGraph as an installed runtime is planned/stale, not manifest evidence.
- No Anthropic or OpenAI SDK is declared. Hosted role calls in this baseline use the OpenRouter
  transport through `httpx`; provider/model identity must come from the returned response and durable
  lineage rather than an inferred architecture label.
- Redis, ClickHouse, and S3 are not application dependencies because this release uses Langfuse
  Cloud. They belong only to a future self-hosted Langfuse topology.
- GitHub Actions references `actions/checkout@v4`, `actions/setup-python@v5`,
  `actions/setup-node@v4`, and `actions/upload-artifact@v4` by major tag rather than immutable commit
  SHA. Pinning CI actions by commit is a release supply-chain hardening item.
