"""Dynamic risk scoring for browser actions.

Calculates a composite risk score from three weighted factors:
  - Threat Likelihood  (weight 0.40)
  - Vulnerability Severity (weight 0.35)
  - Impact Assessment  (weight 0.25)

Each factor is scored 0.0 – 1.0.  The composite score is mapped to a
risk level (LOW / MEDIUM / HIGH) that drives downstream behaviour:
  LOW    → auto-approve
  MEDIUM → log + strict OPA validation
  HIGH   → pause execution for Human-in-the-Loop review
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from defense.dom_sanitizer import SanitizedDOM
from defense.intent_schema import ActionIntent, ActionType

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

_W_THREAT = 0.40
_W_VULN = 0.35
_W_IMPACT = 0.25

# Action-type base threat scores
_ACTION_THREAT: dict[ActionType, float] = {
    ActionType.NAVIGATE: 0.30,
    ActionType.CLICK: 0.35,
    ActionType.HOVER: 0.10,
    ActionType.SCROLL: 0.05,
    ActionType.WAIT: 0.02,
    ActionType.FILL: 0.50,
    ActionType.SELECT: 0.40,
    ActionType.SUBMIT: 0.80,
}


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskAssessment(BaseModel):
    """Full risk assessment for a single action."""

    score: float = Field(ge=0.0, le=1.0)
    level: RiskLevel
    threat_likelihood: float = Field(ge=0.0, le=1.0)
    vulnerability_severity: float = Field(ge=0.0, le=1.0)
    impact_assessment: float = Field(ge=0.0, le=1.0)
    factors: dict[str, Any] = Field(
        default_factory=dict,
        description="Breakdown of what contributed to each sub-score",
    )


# ------------------------------------------------------------------
# Sub-score calculators
# ------------------------------------------------------------------

def _threat_likelihood(intent: ActionIntent) -> tuple[float, dict[str, Any]]:
    """Score threat likelihood (0–1) based on action type and flags."""
    base = _ACTION_THREAT.get(intent.action, 0.5)
    factors: dict[str, Any] = {"action_base": base}

    # Cross-origin bump
    if intent.target_url and intent.current_page_origin:
        from urllib.parse import urlparse
        target_origin = f"{urlparse(intent.target_url).scheme}://{urlparse(intent.target_url).netloc}"
        if target_origin != intent.current_page_origin:
            base = min(base + 0.25, 1.0)
            factors["cross_origin"] = True

    # Hidden-element bump
    if intent.is_hidden_element:
        base = min(base + 0.30, 1.0)
        factors["hidden_element"] = True

    return round(base, 4), factors


def _vulnerability_severity(sanitized: SanitizedDOM) -> tuple[float, dict[str, Any]]:
    """Score vulnerability severity (0–1) from DOM sanitization results."""
    score = 0.0
    factors: dict[str, Any] = {}

    hidden_count = sum(
        1 for r in sanitized.removed_elements if r.reason != "dangerous-tag"
    )
    dangerous_count = sum(
        1 for r in sanitized.removed_elements if r.reason == "dangerous-tag"
    )

    factors["hidden_elements_removed"] = hidden_count
    factors["dangerous_tags_removed"] = dangerous_count

    # Each hidden element adds 0.05, capped at 0.5
    score += min(hidden_count * 0.05, 0.50)
    # Each dangerous tag adds 0.08, capped at 0.4
    score += min(dangerous_count * 0.08, 0.40)

    # Check for iframes specifically (strong signal)
    iframe_count = sum(1 for r in sanitized.removed_elements if r.tag == "iframe")
    if iframe_count:
        score = min(score + 0.15, 1.0)
        factors["iframes_found"] = iframe_count

    return round(min(score, 1.0), 4), factors


def _impact_assessment(intent: ActionIntent) -> tuple[float, dict[str, Any]]:
    """Score impact (0–1) based on data sensitivity signals."""
    score = 0.0
    factors: dict[str, Any] = {}

    selector_lower = intent.selector.lower()

    # Password fields
    if "password" in selector_lower or "passwd" in selector_lower:
        score += 0.40
        factors["password_field"] = True

    # Form submissions
    if intent.action in (ActionType.SUBMIT, ActionType.CLICK) and "form" in selector_lower:
        score += 0.30
        factors["form_interaction"] = True

    # File upload
    if "file" in selector_lower or "upload" in selector_lower:
        score += 0.25
        factors["file_upload"] = True

    # Fill action on any input (moderate risk)
    if intent.action == ActionType.FILL:
        score += 0.15
        factors["fill_action"] = True

    return round(min(score, 1.0), 4), factors


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def assess_risk(
    intent: ActionIntent,
    sanitized: SanitizedDOM,
    *,
    low_max: float = 0.3,
    medium_max: float = 0.7,
) -> RiskAssessment:
    """Calculate the composite risk score for an action.

    Parameters
    ----------
    intent:
        The LLM's structured action intent.
    sanitized:
        DOM sanitization results for the current page.
    low_max / medium_max:
        Threshold boundaries imported from settings.

    Returns
    -------
    RiskAssessment
    """
    tl, tl_factors = _threat_likelihood(intent)
    vs, vs_factors = _vulnerability_severity(sanitized)
    ia, ia_factors = _impact_assessment(intent)

    score = round((_W_THREAT * tl) + (_W_VULN * vs) + (_W_IMPACT * ia), 4)
    score = min(max(score, 0.0), 1.0)  # clamp

    if score <= low_max:
        level = RiskLevel.LOW
    elif score <= medium_max:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH

    assessment = RiskAssessment(
        score=score,
        level=level,
        threat_likelihood=tl,
        vulnerability_severity=vs,
        impact_assessment=ia,
        factors={
            "threat": tl_factors,
            "vulnerability": vs_factors,
            "impact": ia_factors,
        },
    )

    logger.info(
        "Risk assessment: score=%.4f level=%s (TL=%.2f VS=%.2f IA=%.2f)",
        score,
        level.value,
        tl,
        vs,
        ia,
    )
    return assessment
