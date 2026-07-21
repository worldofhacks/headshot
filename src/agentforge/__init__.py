"""AgentForge / Adversarial Machine — framework-neutral platform core.

This top-level package intentionally imports nothing heavy: the domain model, the
target-adapter interface, and the contracts stay framework-neutral (ARCHITECTURE.md §4/§6,
DECISIONS.md D10) so the build-vs-configure stack choice never forces a rewrite. Runtime
agents (Orchestrator, Red Team, Judge, Documentation) and their orchestration land in later
phases and live under ``agentforge.agents``.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
