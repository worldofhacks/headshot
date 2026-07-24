# OpenRouter catalog preflight — 2026-07-24

Status: **BLOCKED** (`ok:false`)

This is a credential-free, non-paid public-catalog observation. It is not a provider call,
campaign authorization, deployment assertion, Judge calibration result, or live security result.
The input was a non-secret release-candidate `HostedConfigurationSet` envelope assembled from the
four frozen model assignments, current provider slugs, price ceilings, and closed limits. It was
not read from Railway and does not prove that this configuration is deployed.

## Observation identity

- Observed: `2026-07-24T22:50:36.992066Z`
- Base commit inspected: `f2c67735558a6ff3d592998145670faa90cb9c47`
- Configuration SHA-256:
  `2333692d12bac191ddb69b600ff7fa35c3b8317d4bf34a43bed7a2138fba8204`
- Generation-policy SHA-256:
  `0607de1fcdba86992709c6875d1e428e151751cfe8752f2b4ee2c751d0f64891`
- Combined canonical public-feed SHA-256:
  `bc92616e4c505f5b6c63863b95a2ba9cc39ff767e8fcbcd3c2d0c4f3f08980d7`
- Canonical redacted artifact SHA-256:
  `814085fe5ed2437466f0c4ecee8a973e2e22a38e3aa2d643bc1711d54fd4a9de`
- Artifact:
  [`OPENROUTER_CATALOG_PREFLIGHT_2026-07-24.json`](OPENROUTER_CATALOG_PREFLIGHT_2026-07-24.json)

The artifact records five successful unauthenticated public `GET` attempts, zero inference calls,
zero credential reads, and zero authorization headers.

Reproduce with an exact canonical configuration supplied by the control plane:

```bash
python scripts/preflight_openrouter_catalog.py hosted-configuration.json \
  --output openrouter-catalog-preflight.json
```

The configuration input is intentionally not committed. The emitted artifact retains only its
hashes and non-secret role/model/routing identities. Exit `4` means the catalog gate is closed.

## Exact result

| Role | Configured slug | Public matches | Result |
| --- | --- | --- | --- |
| Orchestrator | `anthropic` | `anthropic`, `anthropic/2` | blocked: `configured_provider_is_ambiguous` |
| Red Team | `together` | none | blocked: `configured_provider_has_no_candidate` |
| Judge | `google-vertex` | `google-vertex/eu`, `google-vertex/global`, `google-vertex/global/flex`, `google-vertex/global/priority`, `google-vertex/us` | blocked: `configured_provider_is_ambiguous` |
| Documentation | `openai` | `openai`, `openai/flex`, `openai/priority` | blocked: `configured_provider_is_ambiguous` |

No price, capability, context, completion-bound, or privacy claim is made for ambiguous or absent
selections: the gate stops before choosing an endpoint. A future passing observation must bind
exactly one endpoint per role and then prove status, required parameters, context/completion
bounds, Decimal-normalized prices, one-call reservation capacity, and public ZDR membership.

## Public feed identities

| Feed | Canonical SHA-256 |
| --- | --- |
| `anthropic/claude-opus-4.8` endpoints | `1fe19e3ff4b8a0dbbc9a40668ed65a5afce11571703853d31a378fe64b871372` |
| `qwen/qwen3.5-397b-a17b` endpoints | `5717e6359579a4aeccd33773f8d872a8471914ac105a9f9b1af2879c443e67a1` |
| `google/gemini-2.5-pro` endpoints | `937d662fb233542b17c4fe1c093488844a99bdcc1cd6d7223301cf5f579d6d27` |
| `openai/gpt-5.4` endpoints | `5a714a6777dddbfb1ee3fd8dd7c7df5427257dc723ac969be448e1865f0cf307` |
| Public ZDR endpoints | `bd507874c6df3eff1150d944f9698165ef8eab95e3cdd735d1fda0b08a9fc973` |

Catalog state is time-sensitive. This observation must not be reused as a launch-time preflight;
rerun the script against the exact final configuration immediately before authorization.
