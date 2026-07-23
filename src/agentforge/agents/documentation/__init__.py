"""Confirmed-verdict-only Documentation Agent.

The agent is deliberately draft-only.  Publication is a separate, human-authorized operation.
"""

from agentforge.agents.documentation.agent import (
    DocumentationAgent,
    DocumentationInput,
    DocumentationInputError,
    DuplicateReproductionError,
)

__all__ = [
    "DocumentationAgent",
    "DocumentationInput",
    "DocumentationInputError",
    "DuplicateReproductionError",
]
