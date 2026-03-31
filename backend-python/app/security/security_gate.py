"""
Security Gate — Orchestrates the full security pipeline.
Chains: Page Render (Sandbox) → DOM Scanner → Guard LLM → Policy Engine
This is the single entry point for all security checks.

Phase 4: Now supports optional sandbox_manager + session_id for isolated rendering.
"""

import time
import uuid
from app.security.dom_scanner import DOMScanner
from app.security.guard_llm import GuardLLM
from app.security.policy_engine import PolicyEngine
from app.security.page_renderer import render_and_extract
from app.models.schemas import PolicyDecision, ThreatReport, GuardLLMVerdict
from app.database.repositories import log_threat, log_policy_decision, get_cached_llm_verdict, cache_llm_verdict
from app.websocket.handler import ws_manager


class SecurityGate:
    def __init__(self):
        self.scanner = DOMScanner()
        self.guard = GuardLLM()
        self.policy = PolicyEngine()

    async def evaluate_url(self, url: str, agent_goal: str, sandbox_manager=None, session_id: str = None) -> dict:
        """
        Full security evaluation of a URL.
        
        Phase 4: When sandbox_manager and session_id are provided, uses the
        sandboxed browser context for page rendering (isolated cookies, storage,
        network interception). Falls back to standalone page_renderer otherwise.
        """
        start = time.time()

        # Broadcast: Step 1 starting
        await ws_manager.broadcast({
            "type": "DASHBOARD_UPDATE",
            "data": {"agentStatus": "rendering", "currentGoal": agent_goal, "url": url}
        })

        # Step 1: Render page — use sandbox if available, otherwise legacy renderer
        if sandbox_manager and session_id:
            # Phase 4: Sandboxed rendering with network interception
            page_data = await sandbox_manager.navigate(session_id, url)
            # Normalize the key names (sandbox uses 'url', legacy uses 'final_url')
            if "final_url" not in page_data:
                page_data["final_url"] = page_data.get("url", url)
        else:
            # Legacy: standalone Playwright rendering (backward compatible)
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

        # Step 3: Guard LLM analysis (with Cache fallback)
        cached_record = await get_cached_llm_verdict(url, agent_goal, threat_report.dom_risk_score)

        if cached_record:
            llm_verdict = GuardLLMVerdict(**cached_record["verdict"])
        else:
            page_summary = self.guard._summarize_dom(page_data["html"])
            llm_verdict = await self.guard.analyze(agent_goal, page_summary, threat_report)
            # Only cache if it's not a generic fallback failure
            if llm_verdict.explanation != "Guard LLM analysis failed.":
                await cache_llm_verdict(url, agent_goal, threat_report.dom_risk_score, llm_verdict.model_dump())

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

        # Build evaluation broadcast data
        eval_data = {
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
        
        # Phase 4: Include sandbox info if available
        if sandbox_manager and session_id:
            eval_data["sandboxed"] = True
            eval_data["sessionId"] = session_id

        # Broadcast to dashboard
        await ws_manager.broadcast({
            "type": "SECURITY_EVALUATION",
            "data": eval_data
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
