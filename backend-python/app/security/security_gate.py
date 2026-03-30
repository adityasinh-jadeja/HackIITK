"""
Security Gate — Orchestrates the full security pipeline.
Chains: DOM Scanner → Guard LLM → Policy Engine
This is the single entry point for all security checks.
"""

import time
import uuid
from app.security.dom_scanner import DOMScanner
from app.security.guard_llm import GuardLLM
from app.security.policy_engine import PolicyEngine
from app.security.page_renderer import render_and_extract
from app.models.schemas import PolicyDecision, ThreatReport, GuardLLMVerdict
from app.database.repositories import log_threat, log_policy_decision
from app.websocket.handler import ws_manager


class SecurityGate:
    def __init__(self):
        self.scanner = DOMScanner()
        self.guard = GuardLLM()
        self.policy = PolicyEngine()

    async def evaluate_url(self, url: str, agent_goal: str) -> dict:
        """
        Full security evaluation of a URL.
        """
        start = time.time()

        # Broadcast: Step 1 starting
        await ws_manager.broadcast({
            "type": "DASHBOARD_UPDATE",
            "data": {"agentStatus": "rendering", "currentGoal": agent_goal, "url": url}
        })

        # Step 1: Render page
        page_data = await render_and_extract(url)

        # Broadcast: Step 2 starting
        await ws_manager.broadcast({
            "type": "DASHBOARD_UPDATE",
            "data": {"agentStatus": "scanning"}
        })

        # Step 2: DOM scan
        threat_report = await self.scanner.scan(page_data["html"], page_data["final_url"])

        # Broadcast: Step 3 starting
        await ws_manager.broadcast({
            "type": "DASHBOARD_UPDATE",
            "data": {"agentStatus": "llm_analysis"}
        })

        # Step 3: Guard LLM analysis
        page_summary = self.guard._summarize_dom(page_data["html"])
        llm_verdict = await self.guard.analyze(agent_goal, page_summary, threat_report)

        # Step 4: Policy decision (instant, no broadcast needed)
        policy_decision = self.policy.evaluate(url, threat_report, llm_verdict)

        total_latency = (time.time() - start) * 1000

        # For allowlisted/ALLOW domains, suppress irrelevant DOM threats
        # DOM scanner finds legitimate display:none/aria-hidden on real sites
        broadcast_threats = []
        if policy_decision.action in ("BLOCK", "REQUIRE_APPROVAL", "WARN"):
            broadcast_threats = [t.model_dump() for t in threat_report.threats]
            # Persist only real threats
            for threat in threat_report.threats:
                await log_threat(threat.model_dump())
        
        await log_policy_decision(policy_decision.model_dump())

        # Generate request ID for HITL tracking
        request_id = str(uuid.uuid4())

        # Broadcast to dashboard
        await ws_manager.broadcast({
            "type": "SECURITY_EVALUATION",
            "data": {
                "url": url,
                "overallRisk": policy_decision.aggregate_risk,
                "action": policy_decision.action,
                "threats": broadcast_threats,
                "llmVerdict": llm_verdict.model_dump(),
                "policyDecision": policy_decision.model_dump(),
                "latency": total_latency,
                "requestId": request_id,
                "agentStatus": "evaluation_complete",
            }
        })

        return {
            "threat_report": threat_report,
            "llm_verdict": llm_verdict,
            "policy_decision": policy_decision,
            "total_latency_ms": total_latency,
            "request_id": request_id,
        }

    async def handle_hitl_response(self, request_id: str, approved: bool):
        """Handle a Human-in-the-Loop approval or rejection."""
        await ws_manager.broadcast({
            "type": "HITL_RESOLVED",
            "data": {
                "requestId": request_id,
                "approved": approved,
                "action": "ALLOW" if approved else "BLOCK",
            }
        })
        return approved
