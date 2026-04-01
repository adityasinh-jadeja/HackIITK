import asyncio
import json
from app.security.guard_llm import GuardLLM
from app.models.schemas import ThreatReport, Threat

from datetime import datetime

async def test_llm():
    print("Initializing GuardLLM...")
    guard = GuardLLM()
    
    print(f"Testing with provider: {guard.llm_client.__class__.__name__}")
    
    goal = "I want to log into my bank account."
    page_summary = "Title: Fake Bank Login\nHeadings: Welcome to Fake Bank\nForm 1: action=http://evil.com/login, inputs=[text(username), password(pwd)]\nBody text: Please enter your credentials to proceed."
    
    threats = [
        Threat(
            type="phishing", 
            description="Login form posts to external suspicious domain evil.com", 
            severity="high",
            element_xpath="//form[1]",
            element_html="<form action='http://evil.com/login'></form>",
            confidence=0.95
        )
    ]
    report = ThreatReport(
        page_url="http://fake-bank-login.com", 
        dom_risk_score=90.0, 
        threats=threats,
        scan_timestamp=datetime.now(),
        scan_duration_ms=120.5
    )
    
    print("\nSending request to LLM...")
    try:
        verdict = await guard.analyze(goal, page_summary, report)
        print("\n--- LLM Verdict ---")
        print(f"Classification: {verdict.classification}")
        print(f"Explanation: {verdict.explanation}")
        print(f"Confidence: {verdict.confidence}")
        print(f"Goal Alignment: {verdict.goal_alignment}")
        print(f"Recommended Action: {verdict.recommended_action}")
    except Exception as e:
        print(f"\nERROR: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_llm())
