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

# --- PHASE 4: Sandbox Manager ---
from app.sandbox.browser_context import SandboxManager

sandbox = SandboxManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await sandbox.shutdown()
    await close_db()

app = FastAPI(title="Secure Agentic Browser", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}

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
    """Full 3-layer security evaluation of a URL (uses sandbox automatically)."""
    url = body.get("url")
    goal = body.get("goal", "General browsing")
    if not url:
        return {"error": "No URL provided"}, 400
    
    # Phase 4: Auto-create sandbox for evaluation
    session_id = await sandbox.create_session()
    
    try:
        result = await security_gate.evaluate_url(url, goal, sandbox_manager=sandbox, session_id=session_id)
        
        # Broadcast network activity from the sandbox
        network_log = sandbox.network_proxy.get_log(session_id)
        network_stats = sandbox.network_proxy.get_stats(session_id)
        await ws_manager.broadcast({
            "type": "NETWORK_ACTIVITY",
            "data": {
                "session_id": session_id,
                "network_log": network_log[-50:],  # Last 50 entries
                "network_stats": network_stats,
            }
        })
        
        # Broadcast sandbox status
        await ws_manager.broadcast({
            "type": "SANDBOX_STATUS",
            "data": {
                "session_id": session_id,
                "active": True,
                "sessions": sandbox.get_active_sessions(),
                "permissions": sandbox.get_session_info(session_id)["permissions"] if sandbox.get_session_info(session_id) else {},
            }
        })
        
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
            "session_id": session_id,
            "network_stats": network_stats,
        }
    finally:
        # Cleanup sandbox after evaluation
        await sandbox.destroy_session(session_id)

@app.post("/api/hitl/respond")
async def hitl_respond(body: dict):
    """Submit Human-in-the-Loop response."""
    request_id = body.get("requestId")
    approved = body.get("approved", False)
    result = await security_gate.handle_hitl_response(request_id, approved)
    return {"approved": result}

# --- PHASE 4: Sandbox API Endpoints ---

@app.post("/api/sandbox/create")
async def create_sandbox():
    """Create a new sandboxed browsing session."""
    session_id = await sandbox.create_session()
    info = sandbox.get_session_info(session_id)
    
    await ws_manager.broadcast({
        "type": "SANDBOX_STATUS",
        "data": {
            "session_id": session_id,
            "active": True,
            "sessions": sandbox.get_active_sessions(),
            "permissions": info["permissions"] if info else {},
        }
    })
    
    return {"session_id": session_id, "permissions": info["permissions"] if info else {}}

@app.post("/api/sandbox/{session_id}/navigate")
async def sandbox_navigate(session_id: str, body: dict):
    """Navigate sandboxed session to a URL."""
    url = body.get("url")
    if not url:
        return {"error": "No URL provided"}, 400
    
    result = await sandbox.navigate(session_id, url)
    
    # Broadcast network activity
    network_log = sandbox.network_proxy.get_log(session_id)
    network_stats = sandbox.network_proxy.get_stats(session_id)
    await ws_manager.broadcast({
        "type": "NETWORK_ACTIVITY",
        "data": {
            "session_id": session_id,
            "network_log": network_log[-50:],
            "network_stats": network_stats,
        }
    })
    
    return result

@app.post("/api/sandbox/{session_id}/action")
async def sandbox_action(session_id: str, body: dict):
    """Execute an action in a sandboxed session."""
    result = await sandbox.execute_action(session_id, body)
    return result

@app.get("/api/sandbox/{session_id}/network")
async def sandbox_network(session_id: str):
    """Get network log for a sandboxed session."""
    return {
        "log": sandbox.network_proxy.get_log(session_id),
        "blocked_count": sandbox.network_proxy.get_blocked_count(session_id),
        "stats": sandbox.network_proxy.get_stats(session_id),
    }

@app.delete("/api/sandbox/{session_id}")
async def destroy_sandbox(session_id: str):
    """Destroy a sandboxed session and clean up."""
    await sandbox.destroy_session(session_id)
    
    await ws_manager.broadcast({
        "type": "SANDBOX_STATUS",
        "data": {
            "session_id": None,
            "active": False,
            "sessions": sandbox.get_active_sessions(),
            "permissions": {},
        }
    })
    
    return {"message": f"Session {session_id} destroyed"}

@app.get("/api/sandbox/sessions")
async def list_sandbox_sessions():
    """List all active sandbox sessions."""
    sessions = sandbox.get_active_sessions()
    return {
        "sessions": sessions,
        "count": len(sessions),
    }

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
