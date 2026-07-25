# OpenRouter catalog preflight — 2026-07-24

Status: **PASSED** (`ok:true`)

This is a credential-free, non-paid public-catalog observation. It is not a provider inference call,
campaign authorization, deployment assertion, Judge calibration result, or live security result. The
input was a non-secret schema-v2 `HostedConfigurationSet` assembled from the intended exact endpoint
tags, role-specific completion-token parameters, price ceilings, and then-current closed limits. It
was not read from Railway and does not prove that the configuration is deployed. The artifact
predates the candidate's later 400-call source ceiling and is not a preflight of a final 100-case
configuration.

## Observation identity

- Observed: `2026-07-24T23:18:55.799967Z`
- Implementation inspected through exact-endpoint change: `f580752`
- Configuration/input SHA-256:
  `b57d3e5aea6ec4e334968a277f469e151106093dd333f9aef09bfa2627c85ca2`
- Generation-policy SHA-256:
  `0607de1fcdba86992709c6875d1e428e151751cfe8752f2b4ee2c751d0f64891`
- Combined canonical public-feed SHA-256:
  `a6fe33d6d3cffa5b7046e70ec658c95a145c707a69785997bc829b3556fb8e45`
- Canonical redacted artifact SHA-256:
  `fb96432a4e9659b18a6d62cdf5321fb1adb96847cdb2e6f2642b70cee3fa2e7c`
- Artifact:
  [`OPENROUTER_CATALOG_PREFLIGHT_2026-07-24.json`](OPENROUTER_CATALOG_PREFLIGHT_2026-07-24.json)

The artifact records five successful unauthenticated public `GET` attempts, zero inference calls,
zero credential reads, and zero authorization headers. It contains no credential value or secret
reference.

Reproduce with an exact canonical configuration supplied by the control plane:

```bash
python scripts/preflight_openrouter_catalog.py hosted-configuration.json \
  --output openrouter-catalog-preflight.json
```

The configuration input is intentionally not committed. The emitted artifact retains only its hash
and non-secret role/model/routing identities. Exit `0` means all catalog checks passed.

## Exact result and observed public rates

Prices are the endpoint catalog's USD-per-million-token values at observation time. They validate
one-call reservation capacity; they are not a bill, final campaign cost, or permission to activate
the later 400-call source ceiling.

| Role | Exact tag | Token parameter | Public provider | Input | Output | Reasoning | One-call reservation / role cap | Result |
|---|---|---|---|---:|---:|---:|---:|---|
| Orchestrator | `amazon-bedrock/eu-west-1` | `max_tokens` | Amazon Bedrock | $5.50 | $27.50 | $27.50 | $1.16736 / $1.50 | pass |
| Red Team | `atlas-cloud/fp8` | `max_tokens` | AtlasCloud | $0.55 | $3.50 | $3.50 | $0.34816 / $1.00 | pass |
| Judge | `google-vertex/global` | `max_tokens` | Google | $1.25 | $10.00 | $10.00 | $3.02400 / $4.00 | pass |
| Documentation | `azure/eu` | `max_completion_tokens` | Azure | $2.75 | $16.50 | $16.50 | $0.98304 / $1.00 | pass |

Each exact tag matched one endpoint, advertised the configured completion-token parameter plus
reasoning/structured-output support, fit the configured context/completion bounds and Decimal price
ceilings, and appeared in the public ZDR registry. Fallback remains disabled. The public feed
reported no 30-minute uptime value for Amazon Bedrock or Azure; the artifact preserves `null` rather
than inventing availability.

## Public feed identities

| Feed | Canonical SHA-256 |
|---|---|
| `anthropic/claude-opus-4.8` endpoints | `419301ce93f89b4b4f009ba6f0face5eecb79d512dcb489077a7f6615ed0b5c9` |
| `qwen/qwen3.5-397b-a17b` endpoints | `9a65263d1b6b308c532ff165e6a626a674ba789ef42378d7cc847bcee35d5bee` |
| `google/gemini-2.5-pro` endpoints | `8573b9602275b7e0df0ac2b656318c4a1962ff2d62183fadcf7abd4a90578181` |
| `openai/gpt-5.4` endpoints | `847fc0e0d92d3fd1815d7f1175391bca4ad9b2f5a7dde3e17bda753f3fadc77c` |
| Public ZDR endpoints | `f675045095a70c4737b70c97537629b9e78a21242d2388c2f8560add7d6a6924` |

Catalog state and rates are time-sensitive. Rerun the script against the exact final configuration
immediately before authorization. A later catalog pass still does not replace provider-returned
identity, persisted physical-call cost, or post-run billing/Langfuse reconciliation.
