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
