# Red Team model resolution check (evidence)

Before the traced Red Team generator (`agents/red_team/hosted_generation.py`) is exercised live, the
configured red_team model must resolve on OpenRouter's live model list — a bad id fails `generate()`
at runtime the moment it is first called.

## Check

- **Configured red_team model** (`src/agentforge/agents/hosted.py:34`): `qwen/qwen3.5-397b-a17b`
- **Source of truth:** `GET https://openrouter.ai/api/v1/models` (public list), queried 2026-07-24.

## Result — RESOLVES ✓ (no change needed)

`qwen/qwen3.5-397b-a17b` is a real, fully-populated OpenRouter model entry:

| field | value |
|---|---|
| id | `qwen/qwen3.5-397b-a17b` |
| name | Qwen: Qwen3.5 397B A17B |
| context_length | 262144 |
| max_completion_tokens | 65536 |
| pricing (prompt / completion, USD/token) | 0.00000039 / 0.00000234 |
| created | 1771223018 (~2026-02-16 UTC) |

The `created` date (~Feb 2026) is *after* the assistant's Jan-2026 knowledge cutoff — the reason the
id looked unfamiliar; it is a genuinely released model, not a placeholder. Fetch validated against
known anchors (`openai/gpt-4o`, `meta-llama/llama-3.1-70b-instruct` present; 345 models total).

Because the id resolves, **no provider change is required** and there is nothing to re-push for this.
`TracedHostedRedTeamProvider` is model-agnostic (the model is injected via `RedTeamRoleIdentity` from
the config), so if the config default ever changes the provider follows with no code change.

## Documented fallback (also confirmed available)

If the red_team model default is ever repointed, `deepseek/deepseek-chat-v3-0324` resolves on the
same live list (DeepSeek V3 0324, 163840 context, pricing 0.00000027 / 0.00000112). Repointing is a
one-line change in `src/agentforge/agents/hosted.py` (the config default) + its config test fixtures
— not in the traced generator.

## Full hosted-demo model envelope — all four roles (evidence)

The hosted 4-agent demo routes all four roles through OpenRouter, so a single unresolved id fails
the acceptance run at runtime mid-demo. All four `HOSTED_ROLE_MODELS`
(`src/agentforge/agents/hosted.py:31-36`) were checked against `GET
https://openrouter.ai/api/v1/models` (public live list, queried 2026-07-24, 345 models; validated
against anchors `openai/gpt-4o`, `meta-llama/llama-3.1-70b-instruct`).

| role | configured id | resolves | live name / context | nearest real substitute (if ever needed) |
|---|---|---|---|---|
| orchestrator | `anthropic/claude-opus-4.8` | ✓ | Claude Opus 4.8 / 1,000,000 | `anthropic/claude-opus-4.7` (or `-4.8-fast`) |
| red_team | `qwen/qwen3.5-397b-a17b` | ✓ | Qwen3.5 397B A17B / 262,144 | `deepseek/deepseek-chat-v3-0324` |
| judge | `google/gemini-2.5-pro` | ✓ | Gemini 2.5 Pro / 1,048,576 | `google/gemini-3.1-pro-preview` (or `-2.5-pro-preview`) |
| documentation | `openai/gpt-5.4` | ✓ | GPT-5.4 / 1,050,000 | `openai/gpt-5.2` (or `gpt-5.1`) |

**Result: the whole hosted-demo model envelope resolves — no substitution required.** Every id is a
real, fully-populated live model entry (several `created` after the Jan-2026 cutoff, hence
unfamiliar by name: Opus 4.8, Qwen3.5, GPT-5.4). The substitute column lists ids confirmed present on
the same live list; each is a one-line change in `hosted.py` `HOSTED_ROLE_MODELS` + its config test
fixtures — never in any agent's runtime code.
