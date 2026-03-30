"""
Policy Engine — Makes final security decisions by aggregating multiple signals.

Inputs:
  - DOM Scanner risk score (0-100)
  - Guard LLM verdict (classification, confidence)
  - Heuristic signals (domain reputation, URL patterns)

Output:
  - PolicyDecision: ALLOW | WARN | REQUIRE_APPROVAL | BLOCK

Risk formula:
  aggregate_risk = dom_score × 0.4 + llm_score × 0.4 + heuristic_score × 0.2

Thresholds (configurable via .env):
  - 0-39: ALLOW
  - 40-64: WARN
  - 65-84: REQUIRE_APPROVAL (triggers HITL)
  - 85-100: BLOCK
"""

from urllib.parse import urlparse
import re
from app.models.schemas import ThreatReport, GuardLLMVerdict, PolicyDecision
from app.config import settings


class PolicyEngine:
    """
    Aggregates risk signals and produces a final security decision.
    """

    # Domain allowlist — always allow these
    DOMAIN_ALLOWLIST = [
        "google.com", "github.com", "stackoverflow.com",
        "wikipedia.org", "amazon.com", "microsoft.com",
    ]

    # Domain blocklist — always block these
    DOMAIN_BLOCKLIST = [
        "evil.com", "malware.example.com", "phishing.test",
    ]

    def evaluate(
        self,
        url: str,
        threat_report: ThreatReport,
        llm_verdict: GuardLLMVerdict,
    ) -> PolicyDecision:
        """
        Produce a final security decision.
        """
        domain = urlparse(url).netloc.lower()

        # Hard rules — bypass scoring
        if any(allowed in domain for allowed in self.DOMAIN_ALLOWLIST):
            return PolicyDecision(
                action="ALLOW",
                aggregate_risk=0.0,
                dom_score=0.0,
                llm_score=0.0,
                heuristic_score=0.0,
                reason=f"Domain {domain} is in the allowlist.",
                requires_hitl=False,
            )

        if any(blocked in domain for blocked in self.DOMAIN_BLOCKLIST):
            return PolicyDecision(
                action="BLOCK",
                aggregate_risk=100.0,
                dom_score=threat_report.dom_risk_score,
                llm_score=100.0,
                heuristic_score=100.0,
                reason=f"Domain {domain} is in the blocklist.",
                requires_hitl=False,
            )

        # Score calculation
        dom_score = threat_report.dom_risk_score
        llm_score = self._llm_verdict_to_score(llm_verdict)
        heuristic_score = self._heuristic_score(url, threat_report)

        aggregate = (dom_score * 0.4) + (llm_score * 0.4) + (heuristic_score * 0.2)

        # Apply thresholds
        if aggregate >= settings.RISK_THRESHOLD_BLOCK:
            action = "BLOCK"
        elif aggregate >= settings.RISK_THRESHOLD_APPROVAL:
            action = "REQUIRE_APPROVAL"
        elif aggregate >= settings.RISK_THRESHOLD_WARN:
            action = "WARN"
        else:
            action = "ALLOW"

        return PolicyDecision(
            action=action,
            aggregate_risk=round(aggregate, 2),
            dom_score=round(dom_score, 2),
            llm_score=round(llm_score, 2),
            heuristic_score=round(heuristic_score, 2),
            reason=self._build_reason(action, dom_score, llm_score, heuristic_score, llm_verdict),
            requires_hitl=(action == "REQUIRE_APPROVAL"),
        )

    def _llm_verdict_to_score(self, verdict: GuardLLMVerdict) -> float:
        """Convert LLM classification to a 0-100 score."""
        base_scores = {"safe": 10, "suspicious": 55, "malicious": 90}
        base = base_scores.get(verdict.classification, 50)
        # Adjust by confidence — high confidence amplifies the score
        return base * verdict.confidence

    def _heuristic_score(self, url: str, report: ThreatReport) -> float:
        """
        Rule-based scoring from URL and page characteristics.
        """
        score = 0.0
        parsed = urlparse(url)

        # HTTPS check
        if parsed.scheme != 'https':
            score += 15

        # IP address instead of domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
            score += 25

        # Very long URL (common in phishing)
        if len(url) > 200:
            score += 10

        # Number of critical threats
        critical_count = sum(1 for t in report.threats if t.severity == "critical")
        score += critical_count * 15

        return min(100.0, score)

    def _build_reason(self, action, dom, llm, heuristic, verdict) -> str:
        parts = [f"Aggregate risk: DOM={dom:.0f}, LLM={llm:.0f}, Heuristic={heuristic:.0f}."]
        parts.append(f"Guard LLM: {verdict.classification} ({verdict.explanation})")
        return " ".join(parts)
