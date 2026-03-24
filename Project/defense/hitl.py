"""Human-in-the-Loop (HitL) pause mechanism with Explainable AI.

When an action triggers HIGH risk, execution is suspended via an
``asyncio.Event``.  An XAI prompt generates a plain-English explanation
of *why* the action was blocked so the human operator can make an
informed approve/deny decision.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from defense.dom_sanitizer import SanitizedDOM
from defense.intent_schema import ActionIntent
from defense.risk_scorer import RiskAssessment

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

class HitLDecision(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class HitLRequest(BaseModel):
    """A pending Human-in-the-Loop review request."""

    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    task_id: str = ""
    action_intent: ActionIntent
    risk_assessment: RiskAssessment
    xai_explanation: str = Field(
        default="",
        description="Human-readable explanation of why the action was flagged",
    )
    decision: HitLDecision = HitLDecision.PENDING


# ------------------------------------------------------------------
# XAI explanation generator
# ------------------------------------------------------------------

def generate_xai_explanation(
    intent: ActionIntent,
    risk: RiskAssessment,
    sanitized: SanitizedDOM,
) -> str:
    """Build a human-readable explanation of why an action was blocked.

    In production this could call an LLM; here we use a deterministic
    template so that the defence layer has zero LLM dependency.
    """
    lines: list[str] = []
    lines.append(
        f"⚠️  HIGH-RISK ACTION DETECTED (score {risk.score:.2f}/{1.0:.2f})"
    )
    lines.append(f"Action: {intent.action.value} on selector '{intent.selector}'")

    # Threat factors
    threat = risk.factors.get("threat", {})
    if threat.get("cross_origin"):
        lines.append(
            "• Cross-origin target detected — the action targets a different "
            f"domain than the current page ({intent.current_page_origin})."
        )
    if threat.get("hidden_element"):
        lines.append(
            "• The target element was flagged as HIDDEN by the DOM sanitizer. "
            "This may indicate a clickjacking overlay (e.g., an invisible form "
            "with opacity:0 placed over the real button)."
        )

    # Vulnerability factors
    vuln = risk.factors.get("vulnerability", {})
    if vuln.get("hidden_elements_removed", 0) > 0:
        lines.append(
            f"• {vuln['hidden_elements_removed']} hidden element(s) were removed "
            "from the DOM during sanitization — the page may be attempting "
            "prompt injection via invisible content."
        )
    if vuln.get("dangerous_tags_removed", 0) > 0:
        lines.append(
            f"• {vuln['dangerous_tags_removed']} dangerous tag(s) (script/iframe/etc.) "
            "were stripped from the DOM."
        )
    if vuln.get("iframes_found", 0) > 0:
        lines.append(
            f"• {vuln['iframes_found']} iframe(s) detected — potential clickjacking vector."
        )

    # Impact factors
    impact = risk.factors.get("impact", {})
    if impact.get("password_field"):
        lines.append("• The target involves a PASSWORD field — data sensitivity is high.")
    if impact.get("form_interaction"):
        lines.append("• The action interacts with a FORM element — data may be submitted.")
    if impact.get("file_upload"):
        lines.append("• The action involves a FILE UPLOAD — exfiltration risk.")

    # Removed elements preview
    hidden_elements = [
        r for r in sanitized.removed_elements if r.reason != "dangerous-tag"
    ]
    if hidden_elements:
        lines.append("\nExamples of removed hidden elements:")
        for el in hidden_elements[:3]:
            lines.append(
                f"  – <{el.tag}> removed because: {el.reason}  "
                f"preview: {el.outer_html_preview[:80]}…"
            )

    return "\n".join(lines)


# ------------------------------------------------------------------
# Pending-request store (in-memory; swap for Redis/DB in production)
# ------------------------------------------------------------------

_pending: dict[str, tuple[HitLRequest, asyncio.Event]] = {}


async def pause_for_human(
    *,
    task_id: str,
    intent: ActionIntent,
    risk: RiskAssessment,
    sanitized: SanitizedDOM,
    timeout: float = 300.0,
) -> HitLRequest:
    """Suspend execution until a human approves or denies the action.

    Parameters
    ----------
    task_id:
        Identifier of the parent browsing task.
    intent / risk / sanitized:
        Context for the XAI explanation.
    timeout:
        Max seconds to wait before auto-denying.

    Returns
    -------
    HitLRequest
        With ``decision`` set to APPROVED, DENIED, or DENIED (on timeout).
    """
    explanation = generate_xai_explanation(intent, risk, sanitized)

    req = HitLRequest(
        task_id=task_id,
        action_intent=intent,
        risk_assessment=risk,
        xai_explanation=explanation,
    )

    event = asyncio.Event()
    _pending[req.request_id] = (req, event)

    logger.warning(
        "HitL PAUSE  request_id=%s  task=%s\n%s",
        req.request_id,
        task_id,
        explanation,
    )

    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        req.decision = HitLDecision.DENIED
        logger.warning("HitL TIMEOUT — auto-denied request %s", req.request_id)
    finally:
        _pending.pop(req.request_id, None)

    return req


def approve(request_id: str) -> bool:
    """Mark a pending HitL request as APPROVED and resume execution."""
    entry = _pending.get(request_id)
    if not entry:
        return False
    req, event = entry
    req.decision = HitLDecision.APPROVED
    event.set()
    logger.info("HitL APPROVED  request_id=%s", request_id)
    return True


def deny(request_id: str) -> bool:
    """Mark a pending HitL request as DENIED and resume execution."""
    entry = _pending.get(request_id)
    if not entry:
        return False
    req, event = entry
    req.decision = HitLDecision.DENIED
    event.set()
    logger.info("HitL DENIED   request_id=%s", request_id)
    return True


def get_pending(task_id: str | None = None) -> list[HitLRequest]:
    """Return all pending HitL requests, optionally filtered by task."""
    results = [req for req, _ in _pending.values()]
    if task_id:
        results = [r for r in results if r.task_id == task_id]
    return results
