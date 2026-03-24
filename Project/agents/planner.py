"""Planner Agent — breaks a user goal into executable browser steps.

The Planner receives a natural-language objective and produces an ordered
list of ``Step`` objects that the Executor can translate into action intents.

In production, this calls an LLM.  The implementation provides a pluggable
``plan()`` coroutine with a default stub for testing without API keys.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

from defense.intent_schema import ActionType

logger = logging.getLogger(__name__)


class Step(BaseModel):
    """A single planned browser step."""

    step_number: int
    action: ActionType
    description: str = Field(description="Human-readable description of the step")
    selector: str = Field(default="", description="CSS/XPath selector for the target element")
    value: str = Field(default="", description="Value to fill / URL to navigate to")
    reasoning: str = Field(default="", description="Why this step is needed")


class PlanResult(BaseModel):
    """Output of the Planner Agent."""

    goal: str
    steps: list[Step] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------------
# LLM interface (stub)
# ------------------------------------------------------------------

async def plan(
    goal: str,
    *,
    page_context: dict[str, Any] | None = None,
    history: list[dict[str, Any]] | None = None,
) -> PlanResult:
    """Break a user goal into browser steps.

    Parameters
    ----------
    goal:
        Natural-language objective (e.g. "Go to example.com and read the title").
    page_context:
        Optional current page accessibility tree / sanitized DOM context.
    history:
        Previous steps and their results for multi-turn planning.

    Returns
    -------
    PlanResult
    """
    # ----- STUB: deterministic fallback for testing -----
    # Replace this body with an LLM call (OpenAI / Anthropic / local model)
    logger.info("Planner invoked for goal: %s", goal)

    steps: list[Step] = []

    # Simple heuristic: if goal mentions a URL, plan a navigate step
    import re
    url_match = re.search(r"https?://\S+", goal)
    if url_match:
        steps.append(Step(
            step_number=1,
            action=ActionType.NAVIGATE,
            description=f"Navigate to {url_match.group()}",
            value=url_match.group(),
            reasoning="The goal references a URL — navigate there first.",
        ))
        steps.append(Step(
            step_number=2,
            action=ActionType.WAIT,
            description="Wait for the page to stabilise",
            reasoning="Ensure the DOM is fully loaded before interacting.",
        ))
    else:
        steps.append(Step(
            step_number=1,
            action=ActionType.WAIT,
            description="Awaiting further instructions — no actionable URL detected",
            reasoning="The goal did not contain a clear navigation target.",
        ))

    result = PlanResult(goal=goal, steps=steps)
    logger.info("Plan generated: %d step(s)", len(steps))
    return result
