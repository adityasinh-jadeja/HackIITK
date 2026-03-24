"""Orchestrator — State machine wiring the Planner, Executor, and Critic.

State flow:
  INIT → PLAN → EXECUTE → CRITIQUE → PLAN (loop) → DONE | FAILED

The orchestrator owns the full lifecycle of a browsing task:
  1. Planner breaks the goal into steps.
  2. DOM is sanitized before each interaction batch.
  3. Executor runs each step through the OPA + risk pipeline.
  4. Critic sanitizes the raw results before feeding back to the Planner.
  5. Loop continues until the Planner signals completion or max iterations.
"""

from __future__ import annotations

import logging
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from agents.planner import PlanResult, Step, plan
from agents.executor import ExecutionResult, execute_step
from agents.critic import PageDataExtract, critique_and_extract
from browser.sandbox import BrowserSandbox, TaskContext
from defense.dom_sanitizer import SanitizedDOM, sanitize_dom

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# State machine
# ------------------------------------------------------------------

class TaskState(str, Enum):
    INIT = "init"
    PLAN = "plan"
    EXECUTE = "execute"
    CRITIQUE = "critique"
    DONE = "done"
    FAILED = "failed"
    PAUSED = "paused"  # HitL waiting


class StepRecord(BaseModel):
    """Immutable log of a single executed step."""

    step: Step
    executed: bool = False
    result_data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    risk_score: float = 0.0
    risk_level: str = "low"


class TaskRecord(BaseModel):
    """Full record of a browsing task."""

    task_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    goal: str
    state: TaskState = TaskState.INIT
    iteration: int = 0
    max_iterations: int = 10
    step_history: list[StepRecord] = Field(default_factory=list)
    critique_history: list[PageDataExtract] = Field(default_factory=list)
    current_plan: PlanResult | None = None
    error: str | None = None


# ------------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------------

class Orchestrator:
    """Runs the full Plan → Execute → Critique loop for a browsing task."""

    def __init__(self, sandbox: BrowserSandbox) -> None:
        self._sandbox = sandbox

    async def run(self, goal: str, *, max_iterations: int = 10) -> TaskRecord:
        """Execute a full browsing task.

        Parameters
        ----------
        goal:
            Natural-language user objective.
        max_iterations:
            Safety limit on plan→execute→critique cycles.

        Returns
        -------
        TaskRecord
            Complete record of what happened.
        """
        record = TaskRecord(goal=goal, max_iterations=max_iterations)
        logger.info("Orchestrator starting task %s: %s", record.task_id, goal)

        async with self._sandbox.new_task_context() as ctx:
            try:
                await self._loop(ctx, record)
            except Exception as exc:  # noqa: BLE001
                record.state = TaskState.FAILED
                record.error = str(exc)
                logger.error("Task %s FAILED: %s", record.task_id, exc)

        logger.info(
            "Task %s finished — state=%s  iterations=%d  steps=%d",
            record.task_id,
            record.state.value,
            record.iteration,
            len(record.step_history),
        )
        return record

    # ------------------------------------------------------------------

    async def _loop(self, ctx: TaskContext, record: TaskRecord) -> None:
        page = ctx.page

        while record.iteration < record.max_iterations:
            record.iteration += 1
            logger.info("=== Iteration %d ===", record.iteration)

            # ---- PLAN ----
            record.state = TaskState.PLAN
            page_context: dict[str, Any] = {}
            if record.critique_history:
                last_critique = record.critique_history[-1]
                page_context = last_critique.model_dump()

            plan_result = await plan(
                record.goal,
                page_context=page_context,
                history=[sr.model_dump() for sr in record.step_history],
            )
            record.current_plan = plan_result

            if not plan_result.steps:
                record.state = TaskState.DONE
                logger.info("Planner returned no steps — task complete.")
                return

            # ---- EXECUTE ----
            record.state = TaskState.EXECUTE

            # Sanitize DOM before this batch of actions
            sanitized: SanitizedDOM = await sanitize_dom(page)

            for step in plan_result.steps:
                exec_result: ExecutionResult = await execute_step(
                    step, page, sanitized, task_id=record.task_id
                )
                record.step_history.append(StepRecord(
                    step=step,
                    executed=exec_result.executed,
                    result_data=exec_result.result_data,
                    error=exec_result.error,
                    risk_score=exec_result.risk.score,
                    risk_level=exec_result.risk.level.value,
                ))

                if not exec_result.executed and exec_result.error:
                    logger.warning(
                        "Step %d not executed: %s", step.step_number, exec_result.error
                    )
                    # Continue with remaining steps unless it's a blocker
                    if exec_result.risk.level.value == "high" and not exec_result.executed:
                        logger.warning("High-risk denial — stopping this iteration.")
                        break

            # ---- CRITIQUE ----
            record.state = TaskState.CRITIQUE

            # Re-sanitize after execution to get fresh DOM state
            post_sanitized = await sanitize_dom(page)

            page_title = await page.title()
            critique_result = critique_and_extract(
                raw_html=post_sanitized.cleaned_html,
                accessible_tree=post_sanitized.accessible_tree,
                url=page.url,
                title=page_title,
            )
            record.critique_history.append(critique_result)

            logger.info(
                "Critique complete — title=%s  headings=%d  links=%d",
                critique_result.title,
                len(critique_result.headings),
                len(critique_result.links),
            )

            # Check if all steps executed successfully
            all_ok = all(sr.executed for sr in record.step_history[-len(plan_result.steps):])
            if all_ok:
                record.state = TaskState.DONE
                logger.info("All steps executed successfully — task complete.")
                return

        # Max iterations exhausted
        record.state = TaskState.FAILED
        record.error = f"Max iterations ({record.max_iterations}) exhausted"
        logger.warning("Task %s: %s", record.task_id, record.error)
