from pydantic import BaseModel
from datetime import datetime
from typing import List

class Threat(BaseModel):
    type: str                       # "prompt_injection" | "hidden_text" | "deceptive_form" | "phishing" | "dynamic_injection"
    severity: str                   # "low" | "medium" | "high" | "critical"
    element_xpath: str              # XPath to the suspicious element
    element_html: str               # Raw HTML of the element
    description: str                # Human-readable explanation
    confidence: float               # 0.0 - 1.0

class ThreatReport(BaseModel):
    page_url: str
    scan_timestamp: datetime
    threats: List[Threat]           # Individual threats found
    dom_risk_score: float           # 0.0 - 100.0
    scan_duration_ms: float

class GuardLLMVerdict(BaseModel):
    classification: str             # "safe" | "suspicious" | "malicious"
    explanation: str                # Human-readable reasoning
    confidence: float               # 0.0 - 1.0
    goal_alignment: float           # How well page aligns with agent's goal
    recommended_action: str         # "allow" | "warn" | "block"

class PolicyDecision(BaseModel):
    action: str                     # "ALLOW" | "WARN" | "REQUIRE_APPROVAL" | "BLOCK"
    aggregate_risk: float           # Weighted score 0-100
    dom_score: float
    llm_score: float
    heuristic_score: float
    reason: str
    requires_hitl: bool

class ActionLog(BaseModel):
    action_type: str
    target: str
    timestamp: datetime
    success: bool

class SessionLog(BaseModel):
    session_id: str
    start_time: datetime
    goal: str
    actions: List[ActionLog]
    threats_detected: List[ThreatReport]
    policy_decisions: List[PolicyDecision]
    outcome: str                    # "completed" | "blocked" | "aborted"
