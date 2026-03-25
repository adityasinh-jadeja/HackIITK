"""
FastAPI entry point for the Secure Agentic Browser backend.
Handles REST endpoints, WebSocket connections, and app lifecycle.
"""
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
