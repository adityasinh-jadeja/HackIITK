"""Executor Agent — translates planned Steps into ActionIntent payloads
and executes them against a Playwright page after OPA approval.

The Executor never generates raw Playwright calls from the LLM.  Its
pipeline is:
  Step → ActionIntent → OPA validation → Risk assessment → Playwright call
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import Page

from agents.planner import Step
from config import settings
from defense.dom_sanitizer import SanitizedDOM, sanitize_dom
from defense.intent_schema import ActionIntent, ActionType
from defense.opa_client import evaluate_action
from defense.risk_scorer import RiskAssessment, RiskLevel, assess_risk
from defense import hitl

logger = logging.getLogger(__name__)


class ExecutionResult:
    """Result of executing a single step."""

    def __init__(
        self,
        *,
        step: Step,
        intent: ActionIntent,
        opa_allow: bool,
        risk: RiskAssessment,
        executed: bool,
        result_data: dict[str, Any] | None = None,
        error: str | None = None,
    ):
        self.step = step
        self.intent = intent
        self.opa_allow = opa_allow
        self.risk = risk
        self.executed = executed
        self.result_data = result_data or {}
        self.error = error


# ------------------------------------------------------------------
# Step → ActionIntent
# ------------------------------------------------------------------

def _step_to_intent(step: Step, *, page_url: str) -> ActionIntent:
    """Convert a planner Step into a structured ActionIntent."""
    parsed = urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""

    return ActionIntent(
        action=step.action,
        selector=step.selector,
        value=step.value,
        target_url=step.value if step.action == ActionType.NAVIGATE else "",
        current_page_origin=origin,
    )


# ------------------------------------------------------------------
# Playwright action dispatch
# ------------------------------------------------------------------

async def _run_playwright_action(page: Page, intent: ActionIntent) -> dict[str, Any]:
    """Execute a single Playwright action corresponding to *intent*."""
    result: dict[str, Any] = {"action": intent.action.value}

    match intent.action:
        case ActionType.NAVIGATE:
            await page.goto(intent.value, wait_until="domcontentloaded")
            result["url"] = page.url
            result["title"] = await page.title()

        case ActionType.CLICK:
            await page.click(intent.selector)
            result["selector"] = intent.selector

        case ActionType.FILL:
            await page.fill(intent.selector, intent.value)
            result["selector"] = intent.selector

        case ActionType.SELECT:
            await page.select_option(intent.selector, intent.value)
            result["selector"] = intent.selector

        case ActionType.SUBMIT:
            await page.click(intent.selector)
            result["selector"] = intent.selector

        case ActionType.HOVER:
            await page.hover(intent.selector)
            result["selector"] = intent.selector

        case ActionType.SCROLL:
            await page.evaluate("window.scrollBy(0, 300)")
            result["scrolled"] = True

        case ActionType.WAIT:
            await page.wait_for_timeout(1000)
            result["waited"] = True

    return result


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

async def execute_step(
    step: Step,
    page: Page,
    sanitized: SanitizedDOM,
    *,
    task_id: str = "",
) -> ExecutionResult:
    """Execute a single step with full defense pipeline.

    Pipeline:  Step → Intent → OPA check → Risk score → (HitL?) → Playwright
    """
    intent = _step_to_intent(step, page_url=page.url)

    # --- OPA policy check ---
    opa_result = await evaluate_action(intent=intent)
    if not opa_result.allow:
        logger.warning("OPA DENIED step %d: %s", step.step_number, opa_result.reasons)
        return ExecutionResult(
            step=step,
            intent=intent,
            opa_allow=False,
            risk=RiskAssessment(
                score=1.0,
                level=RiskLevel.HIGH,
                threat_likelihood=1.0,
                vulnerability_severity=1.0,
                impact_assessment=1.0,
            ),
            executed=False,
            error=f"OPA denied: {opa_result.reasons}",
        )

    # --- Risk assessment ---
    risk = assess_risk(
        intent,
        sanitized,
        low_max=settings.risk_low_max,
        medium_max=settings.risk_medium_max,
    )

    # --- HitL pause for HIGH risk ---
    if risk.level == RiskLevel.HIGH:
        logger.warning("HIGH risk — pausing for human review (step %d)", step.step_number)
        hitl_req = await hitl.pause_for_human(
            task_id=task_id,
            intent=intent,
            risk=risk,
            sanitized=sanitized,
        )
        if hitl_req.decision != hitl.HitLDecision.APPROVED:
            return ExecutionResult(
                step=step,
                intent=intent,
                opa_allow=True,
                risk=risk,
                executed=False,
                error=f"HitL denied (decision={hitl_req.decision.value})",
            )

    # --- Execute the Playwright action ---
    try:
        result_data = await _run_playwright_action(page, intent)
        logger.info("Step %d executed successfully: %s", step.step_number, result_data)
        return ExecutionResult(
            step=step,
            intent=intent,
            opa_allow=True,
            risk=risk,
            executed=True,
            result_data=result_data,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Playwright error on step %d: %s", step.step_number, exc)
        return ExecutionResult(
            step=step,
            intent=intent,
            opa_allow=True,
            risk=risk,
            executed=False,
            error=str(exc),
        )
