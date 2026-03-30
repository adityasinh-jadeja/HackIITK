"""
FastAPI entry point for the Secure Agentic Browser backend.
Handles REST endpoints, WebSocket connections, and app lifecycle.
"""
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.database.connection import connect_db, close_db
from app.websocket.handler import ws_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()

app = FastAPI(title="Secure Agentic Browser", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}

@app.get("/api/dashboard")
async def get_dashboard():
    return ws_manager.get_current_state()

@app.post("/api/agent/start")
async def start_agent(body: dict):
    goal = body.get("goal")
    if not goal:
        return {"error": "No goal provided"}, 400
    # Phase 5 will implement the actual agent pipeline
    await ws_manager.broadcast({"type": "AGENT_STARTED", "goal": goal})
    return {"message": "Agent started", "goal": goal}

@app.post("/api/agent/stop")
async def stop_agent():
    await ws_manager.broadcast({"type": "AGENT_STOPPED"})
    return {"message": "Agent stopped"}

# --- PHASE 2: DOM Scanner Endpoint ---
from app.security.dom_scanner import DOMScanner
from app.security.page_renderer import render_and_extract
from app.database.repositories import log_threat

scanner = DOMScanner()

@app.post("/api/scan")
async def scan_url(body: dict):
    url = body.get("url")
    if not url:
        return {"error": "No URL provided"}, 400
    
    # Immediately clear the cached dashboard state
    await ws_manager.broadcast({
        "type": "SCAN_STARTED",
        "data": {
            "url": f"Scanning: {url} ...",
            "threats": [],
            "overallRisk": 0,
            "agentStatus": "scanning"
        }
    })

    # Render page with Playwright
    page_data = await render_and_extract(url)
    
    # Scan DOM
    report = await scanner.scan(page_data["html"], page_data["final_url"])
    
    # Persist threats
    for threat in report.threats:
        await log_threat(threat.model_dump())
    
    # Broadcast to dashboard
    await ws_manager.broadcast({
        "type": "SCAN_COMPLETE",
        "data": {
            "overallRisk": report.dom_risk_score,
            "threats": [t.model_dump() for t in report.threats],
            "scanDuration": report.scan_duration_ms,
            "url": url,
        }
    })
    
    return report.model_dump()

# --- PHASE 3: Guard LLM + Policy Engine Endpoints ---
from app.security.security_gate import SecurityGate

security_gate = SecurityGate()

@app.post("/api/evaluate")
async def evaluate_url(body: dict):
    """Full 3-layer security evaluation of a URL."""
    url = body.get("url")
    goal = body.get("goal", "General browsing")
    if not url:
        return {"error": "No URL provided"}, 400
    result = await security_gate.evaluate_url(url, goal)
    
    # Only return threats when the policy action is not ALLOW
    policy_action = result["policy_decision"].action
    threats = []
    if policy_action in ("BLOCK", "REQUIRE_APPROVAL", "WARN"):
        threats = [t.model_dump() for t in result["threat_report"].threats]
    
    return {
        "threats": threats,
        "llm_verdict": result["llm_verdict"].model_dump(),
        "policy_decision": result["policy_decision"].model_dump(),
        "latency_ms": result["total_latency_ms"],
        "request_id": result["request_id"],
    }

@app.post("/api/hitl/respond")
async def hitl_respond(body: dict):
    """Submit Human-in-the-Loop response."""
    request_id = body.get("requestId")
    approved = body.get("approved", False)
    result = await security_gate.handle_hitl_response(request_id, approved)
    return {"approved": result}

@app.websocket("/ws/dashboard")
async def dashboard_ws(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages from frontend (e.g., HITL responses)
            await ws_manager.handle_message(data)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
