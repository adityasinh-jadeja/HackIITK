"""Unit tests for defense.risk_scorer."""

from __future__ import annotations

import pytest

from defense.intent_schema import ActionIntent, ActionType
from defense.dom_sanitizer import SanitizedDOM, RemovedElement
from defense.risk_scorer import RiskLevel, assess_risk


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _intent(
    action: ActionType = ActionType.CLICK,
    selector: str = "#btn",
    value: str = "",
    target_url: str = "",
    origin: str = "https://example.com",
    hidden: bool = False,
) -> ActionIntent:
    return ActionIntent(
        action=action,
        selector=selector,
        value=value,
        target_url=target_url,
        current_page_origin=origin,
        is_hidden_element=hidden,
    )


def _sanitized(
    hidden_count: int = 0,
    dangerous_count: int = 0,
    iframe_count: int = 0,
) -> SanitizedDOM:
    removed = []
    for _ in range(hidden_count):
        removed.append(RemovedElement(tag="div", reason="display:none"))
    for _ in range(dangerous_count):
        removed.append(RemovedElement(tag="script", reason="dangerous-tag"))
    for _ in range(iframe_count):
        removed.append(RemovedElement(tag="iframe", reason="dangerous-tag"))
    return SanitizedDOM(removed_elements=removed)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestRiskScorer:
    """Test suite for the risk scoring function."""

    def test_low_risk_simple_click(self):
        """A simple click on a clean page should be LOW risk."""
        result = assess_risk(_intent(), _sanitized())
        assert result.level == RiskLevel.LOW
        assert result.score <= 0.3

    def test_high_risk_submit_with_hidden_elements(self):
        """Submit action + many hidden elements + password → HIGH."""
        intent = _intent(
            action=ActionType.SUBMIT,
            selector="form#login input[type=password]",
            hidden=True,
        )
        sanitized = _sanitized(hidden_count=10, dangerous_count=5, iframe_count=2)
        result = assess_risk(intent, sanitized)
        assert result.level == RiskLevel.HIGH
        assert result.score > 0.7

    def test_medium_risk_fill_action(self):
        """Fill action on a moderately suspicious page → MEDIUM."""
        intent = _intent(action=ActionType.FILL, selector="input#email", value="test@x.com")
        sanitized = _sanitized(hidden_count=3, dangerous_count=1)
        result = assess_risk(intent, sanitized)
        assert result.level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
        assert result.score > 0.3

    def test_all_zero_factors(self):
        """All-zero factors → score 0, LOW risk."""
        intent = _intent(action=ActionType.WAIT)
        sanitized = _sanitized()
        result = assess_risk(intent, sanitized)
        assert result.level == RiskLevel.LOW
        assert result.score < 0.1

    def test_boundary_at_0_3(self):
        """Score exactly at 0.3 should be LOW (boundary is inclusive)."""
        # Navigate (base 0.30) on a clean page, no other factors
        intent = _intent(action=ActionType.NAVIGATE, value="https://example.com")
        sanitized = _sanitized()
        result = assess_risk(intent, sanitized)
        # threat = 0.30, vuln = 0, impact = 0 → score = 0.12
        assert result.level == RiskLevel.LOW

    def test_cross_origin_bumps_threat(self):
        """Cross-origin target should increase threat likelihood."""
        intent = _intent(
            action=ActionType.NAVIGATE,
            target_url="https://evil.com/phish",
            origin="https://example.com",
        )
        sanitized = _sanitized()
        result_cross = assess_risk(intent, sanitized)

        intent_same = _intent(action=ActionType.NAVIGATE)
        result_same = assess_risk(intent_same, _sanitized())

        assert result_cross.threat_likelihood > result_same.threat_likelihood

    def test_factors_included_in_assessment(self):
        """The returned assessment includes factor breakdowns."""
        intent = _intent(action=ActionType.FILL, selector="input.password-field")
        sanitized = _sanitized(hidden_count=2)
        result = assess_risk(intent, sanitized)
        assert "threat" in result.factors
        assert "vulnerability" in result.factors
        assert "impact" in result.factors

    def test_custom_thresholds(self):
        """Custom low/medium thresholds are respected."""
        intent = _intent(action=ActionType.CLICK)
        sanitized = _sanitized()
        # With an extremely low threshold, even a click becomes MEDIUM+
        result = assess_risk(intent, sanitized, low_max=0.01, medium_max=0.05)
        assert result.level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
