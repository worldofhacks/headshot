# AGENTS.md

Concise, durable, cross-tool rules for this repo.

- **Requirements source of truth:** `Week_3_AgentForge.pdf`
- **Roadmap / plan:** `PLAN.md`
- **Full operating rules (Claude Code):** `CLAUDE.md` — read it; the below is the short version.

> The full PRD was previously pasted into this file. It has been removed to keep AGENTS.md
> a concise rules file. The PDF is canonical; nothing was lost.

## One-liner
Multi-agent adversarial evaluation platform that continuously red-teams the OpenEMR
Clinical Co-Pilot. **This repo is the platform**; the target is attacked over its live
deployed URL. No target code here.

## Non-negotiables
- Deployed target URL submitted every checkpoint; test a live system, not a mock.
- Multi-agent, not a pipeline. The Judge is independent of attack generation.
- Human approval gate before publishing critical findings or remediation.
- Every eval = boundary | invariant | regression, mapped to OWASP Web + LLM Top 10.
- The Judge must never approve a confirmed exploit. Cost is never tokens × N.
- "Optional Engineering Deliverables" are mandatory (the PRD grades them).
- No real PHI — synthetic fixtures only.

## Skills
Dev-workflow skills live in `.claude/skills/` (this repo is **Claude-Code-primary**).
If you later drive with Codex, mirror them to `.agents/skills/`, add `agents/openai.yaml`,
and normalize frontmatter per Codex docs — not done yet, deliberately.

## Deadlines
Architecture Defense ~2.5h post-kickoff · MVP Tue Jul 21 23:59 · Final Fri Jul 24 12:00.
