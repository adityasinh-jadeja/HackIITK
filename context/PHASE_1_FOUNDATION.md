# Phase 1: Foundation & Infrastructure

> **Duration**: Days 1–2 | **Parallel tracks**: Backend + Frontend + Electron
> **Prerequisites**: None — this is the starting phase
> **Outcome**: FastAPI server running, MongoDB connected, frontend wired to Python backend via WebSocket

---

## 📖 Context for This Phase

Read `PROJECT_CONTEXT.md` first for full architecture and data models.

**What exists today:**
- Electron shell (`main.js`, `preload.js`) — connects to a Node.js backend on `ws://localhost:5000`
- React frontend (`BrowserUI.jsx`, `Dashboard.jsx`) — uses Socket.IO to a Node.js server
- Node.js backend (`server.js`) — Express + Socket.IO + MongoDB, imports a non-existent `agent.js`

**What this phase does:**
- Replace the Node.js backend with a Python FastAPI server
- Set up MongoDB with proper document models
- Rewire Electron + React to connect to the new Python backend
- Establish the WebSocket protocol between all layers

---

## 🔧 Backend Track (Python)

### 1.1 — Create FastAPI Project Structure

Create `Project/backend-python/` with this structure:

```
backend-python/
├── app/
│   ├── __init__.py
│   ├── main.py              ← FastAPI app, CORS, WebSocket endpoint, lifespan
│   ├── config.py             ← Pydantic Settings (env vars)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── schemas.py        ← All Pydantic models from PROJECT_CONTEXT.md
│   │   └── db_models.py      ← MongoDB document schemas
│   ├── database/
│   │   ├── __init__.py
│   │   ├── connection.py     ← Motor async MongoDB client
│   │   └── repositories.py   ← CRUD for sessions, threats, logs
│   ├── websocket/
│   │   ├── __init__.py
│   │   └── handler.py        ← WebSocket manager, broadcast to all connected clients
│   ├── security/              ← Empty placeholders for Phase 2-3
│   │   └── __init__.py
│   ├── agent/                 ← Empty placeholders for Phase 5
│   │   └── __init__.py
│   └── sandbox/               ← Empty placeholders for Phase 4
│       └── __init__.py
├── tests/
│   ├── __init__.py
│   └── test_health.py         ← Basic health check test
├── requirements.txt
├── .env
└── .gitignore
```

### 1.2 — `app/main.py`

```python
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
```

### 1.3 — `app/config.py`

```python
"""
Application configuration loaded from environment variables.
"""
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GEMINI_API_KEY: str = ""
    MONGODB_URI: str = "mongodb://localhost:27017/secure-browser"
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    MAX_PAGE_LOAD_TIMEOUT: int = 30000
    RISK_THRESHOLD_WARN: int = 40
    RISK_THRESHOLD_APPROVAL: int = 65
    RISK_THRESHOLD_BLOCK: int = 85
    PLAYWRIGHT_HEADLESS: bool = True
    MAX_CONCURRENT_CONTEXTS: int = 5

    class Config:
        env_file = ".env"

settings = Settings()
```

### 1.4 — `app/database/connection.py`

```python
"""
Async MongoDB connection using Motor.
"""
from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

client: AsyncIOMotorClient = None
db = None

async def connect_db():
    global client, db
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client.get_database("secure_browser")
    print("✅ MongoDB connected")

async def close_db():
    global client
    if client:
        client.close()
        print("🔌 MongoDB disconnected")

def get_db():
    return db
```

### 1.5 — `app/database/repositories.py`

```python
"""
CRUD operations for MongoDB collections.
Collections: sessions, threats, policy_decisions, network_logs
"""
from datetime import datetime, timezone
from app.database.connection import get_db

async def create_session(session_data: dict) -> str:
    db = get_db()
    session_data["created_at"] = datetime.now(timezone.utc)
    result = await db.sessions.insert_one(session_data)
    return str(result.inserted_id)

async def log_threat(threat_data: dict):
    db = get_db()
    threat_data["detected_at"] = datetime.now(timezone.utc)
    await db.threats.insert_one(threat_data)

async def log_policy_decision(decision_data: dict):
    db = get_db()
    decision_data["decided_at"] = datetime.now(timezone.utc)
    await db.policy_decisions.insert_one(decision_data)

async def get_sessions(limit: int = 50):
    db = get_db()
    cursor = db.sessions.find().sort("created_at", -1).limit(limit)
    return await cursor.to_list(length=limit)

async def get_threats(session_id: str = None, limit: int = 100):
    db = get_db()
    query = {"session_id": session_id} if session_id else {}
    cursor = db.threats.find(query).sort("detected_at", -1).limit(limit)
    return await cursor.to_list(length=limit)
```

### 1.6 — `app/websocket/handler.py`

```python
"""
WebSocket connection manager for real-time dashboard updates.
"""
import json
from fastapi import WebSocket

class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.current_state = {
            "overallRisk": 0,
            "metrics": {"blocked": 0, "allowed": 0, "overrides": 0, "latency": 0.0},
            "threats": [],
            "currentGoal": "Waiting for agent command...",
            "agentStatus": "idle",
        }

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        await websocket.send_json({"type": "DASHBOARD_UPDATE", "data": self.current_state})

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        self.current_state.update(data.get("data", data))
        message = json.dumps({"type": data.get("type", "DASHBOARD_UPDATE"), "data": data})
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

    async def handle_message(self, raw: str):
        data = json.loads(raw)
        msg_type = data.get("type")
        if msg_type == "HITL_RESPONSE":
            # Phase 3 will handle this
            pass

    def get_current_state(self):
        return self.current_state

ws_manager = WebSocketManager()
```

### 1.7 — `app/models/schemas.py`

Implement all the Pydantic models from `PROJECT_CONTEXT.md` (ThreatReport, Threat, GuardLLMVerdict, PolicyDecision, SessionLog). These are the shared data contracts used by every other phase.

### 1.8 — `requirements.txt`

```
fastapi==0.115.0
uvicorn[standard]==0.30.0
motor==3.6.0
pydantic==2.9.0
pydantic-settings==2.5.0
python-dotenv==1.0.1
google-generativeai==0.8.0
playwright==1.48.0
beautifulsoup4==4.12.3
lxml==5.3.0
httpx==0.27.0
pytest==8.3.0
pytest-asyncio==0.24.0
```

### 1.9 — `.env`

```env
GEMINI_API_KEY=your_key_here
MONGODB_URI=mongodb://localhost:27017/secure-browser
PORT=8000
HOST=0.0.0.0
RISK_THRESHOLD_WARN=40
RISK_THRESHOLD_APPROVAL=65
RISK_THRESHOLD_BLOCK=85
PLAYWRIGHT_HEADLESS=true
```

---

## 🎨 Frontend Track (React)

### 1.10 — Replace Socket.IO with Native WebSocket

The React frontend currently uses `socket.io-client` to connect to the Node.js backend. Replace it with a native WebSocket connection to the Python FastAPI backend.

**File: `src/hooks/useWebSocket.js`** (NEW)

```javascript
/**
 * Custom React hook for WebSocket connection to the Python backend.
 * Replaces socket.io-client.
 * 
 * Usage:
 *   const { connected, dashboardData, sendMessage } = useWebSocket();
 */
import { useState, useEffect, useRef, useCallback } from 'react';

const WS_URL = 'ws://localhost:8000/ws/dashboard';

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const [dashboardData, setDashboardData] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Auto-reconnect after 3 seconds
      setTimeout(() => {
        wsRef.current = new WebSocket(WS_URL);
      }, 3000);
    };
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'DASHBOARD_UPDATE') {
        setDashboardData(msg.data);
      }
    };

    return () => ws.close();
  }, []);

  const sendMessage = useCallback((type, payload) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type, ...payload }));
    }
  }, []);

  return { connected, dashboardData, sendMessage };
}
```

### 1.11 — Update `BrowserUI.jsx`

Replace all `socket.io-client` usage with the `useWebSocket` hook. Replace the `fetch('http://localhost:5000/...')` calls with `fetch('http://localhost:8000/...')`. Key changes:

- Import and use `useWebSocket` hook
- Replace `io()` connection with `useWebSocket()`
- Use `connected` state for the status indicator
- Use `dashboardData` for risk badge
- Update agent start/stop to call the new FastAPI endpoints

### 1.12 — Update `Dashboard.jsx`

Remove ALL mock data. Wire every section to real `dashboardData` from the WebSocket hook:

- Risk gauge → `dashboardData.overallRisk`
- Threat list → `dashboardData.threats`
- Metrics → `dashboardData.metrics`
- Goal display → `dashboardData.currentGoal`
- Agent status → `dashboardData.agentStatus`

---

## ⚡ Electron Track

### 1.13 — Update `main.js` WebSocket Target

Change the WebSocket connection in the Electron main process from `ws://localhost:5000` to `ws://localhost:8000/ws/dashboard`. The Electron shell communicates with the backend via:
- IPC from renderer → main process
- HTTP/WebSocket from main process → Python backend

Update the `send-goal` IPC handler to POST to `http://localhost:8000/api/agent/start`.
Update the `stop-agent` IPC handler to POST to `http://localhost:8000/api/agent/stop`.

### 1.14 — Update `preload.js`

No structural changes needed — the IPC channel whitelist is already correct. Just verify the channels match what the updated `main.js` expects.

---

## ✅ Verification Checklist

- [ ] `cd backend-python && pip install -r requirements.txt` — no errors
- [ ] `cd backend-python && uvicorn app.main:app --reload --port 8000` — server starts
- [ ] `curl http://localhost:8000/api/health` → `{"status": "ok"}`
- [ ] `curl http://localhost:8000/api/dashboard` → returns JSON state
- [ ] MongoDB is running and backend connects without errors
- [ ] Frontend `npm run dev` → loads without console errors
- [ ] Dashboard shows "Online" when backend WebSocket is connected
- [ ] Dashboard shows "Offline" when backend is stopped
- [ ] Electron `npm run dev` opens window, BrowserView loads a page
- [ ] Agent start button sends POST to FastAPI and gets response
- [ ] WebSocket message appears in dashboard when agent starts

---

## 🔗 Interfaces for Next Phases

This phase establishes these contracts that later phases depend on:

| Interface | Used By | Description |
|---|---|---|
| `ws_manager.broadcast()` | Phase 2, 3, 5 | Send real-time updates to dashboard |
| `schemas.ThreatReport` | Phase 2 | DOM scanner will produce these |
| `schemas.GuardLLMVerdict` | Phase 3 | Guard LLM will produce these |
| `schemas.PolicyDecision` | Phase 3 | Policy engine will produce these |
| `repositories.log_threat()` | Phase 2, 3 | Persist detected threats |
| `repositories.create_session()` | Phase 5 | Create session when agent starts |
| `useWebSocket` hook | Phase 2, 3, 6 | All new frontend components use this |
| `/ws/dashboard` | All phases | Real-time data channel |

---

## 🧪 Manual Testing Steps

### Prerequisites
- Python 3.10+ installed
- MongoDB running locally (`mongod` service started)
- Node.js 18+ installed (for frontend & Electron)

### Test 1: Backend Starts Without Errors

```bash
# Terminal 1 — Start the Python backend
cd Project/backend-python
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**✅ Expected**: Terminal shows:
```
✅ MongoDB connected
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

**❌ If it fails**: Check MongoDB is running (`mongod --version`), check `.env` file exists.

---

### Test 2: Health Endpoint

```bash
# Terminal 2 — Test the health endpoint
curl http://localhost:8000/api/health
```

**✅ Expected**: `{"status":"ok","version":"0.1.0"}`

---

### Test 3: Dashboard REST Endpoint

```bash
curl http://localhost:8000/api/dashboard
```

**✅ Expected**:
```json
{
  "overallRisk": 0,
  "metrics": {"blocked": 0, "allowed": 0, "overrides": 0, "latency": 0.0},
  "threats": [],
  "currentGoal": "Waiting for agent command...",
  "agentStatus": "idle"
}
```

---

### Test 4: WebSocket Connection

Open a browser and go to: `http://localhost:8000/docs` (FastAPI auto-docs).
Or test WebSocket manually with a Python script:

```python
# Save as test_ws.py and run: python test_ws.py
import asyncio
import websockets
import json

async def test():
    async with websockets.connect("ws://localhost:8000/ws/dashboard") as ws:
        msg = await ws.recv()
        data = json.loads(msg)
        print("Received:", json.dumps(data, indent=2))
        assert data["type"] == "DASHBOARD_UPDATE"
        print("✅ WebSocket connection works!")

asyncio.run(test())
```

**✅ Expected**: Prints received dashboard state and "✅ WebSocket connection works!"

---

### Test 5: Agent Start Endpoint

```bash
curl -X POST http://localhost:8000/api/agent/start \
  -H "Content-Type: application/json" \
  -d '{"goal": "Test goal"}'
```

**✅ Expected**: `{"message":"Agent started","goal":"Test goal"}`

---

### Test 6: MongoDB Has Data

```bash
# Open MongoDB shell
mongosh
use secure_browser
db.sessions.find().pretty()
```

**✅ Expected**: At least sees the database is created and accessible (sessions may be empty until Phase 5).

---

### Test 7: Frontend Connects to Backend

```bash
# Terminal 3 — Start the frontend
cd Project/frontend-react
npm install
npm run dev
```

Open `http://localhost:5173` in a browser.

**✅ Expected**:
- Page loads without console errors (open DevTools → Console)
- Status indicator shows "Online" (green) when backend is running
- Status indicator shows "Offline" (red) when you stop the backend (Ctrl+C in Terminal 1)

---

### Test 8: Electron Shell

```bash
# Terminal 4 — first build the React app, then start Electron
cd Project/frontend-react
npm run build

cd ../electron-shell
npm install
npm run dev
```

**✅ Expected**:
- Electron window opens
- BrowserView loads a web page
- Command bar is visible at the top
- No crash or error dialogs

---

### Test 9: End-to-End Data Flow

1. Start backend (Terminal 1)
2. Start frontend (Terminal 3)
3. Open browser to `http://localhost:5173`
4. Open Dashboard page
5. In a separate terminal, send:
   ```bash
   curl -X POST http://localhost:8000/api/agent/start \
     -H "Content-Type: application/json" \
     -d '{"goal": "Buy a laptop"}'
   ```
6. Check the dashboard — the goal text should update in real-time

**✅ Expected**: Dashboard updates to show "Buy a laptop" as the current goal.

---

### Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again |
| MongoDB connection refused | Start MongoDB: `mongod` or `net start MongoDB` (Windows) |
| CORS error in browser | Verify `CORSMiddleware` is configured with `allow_origins=["*"]` |
| WebSocket won't connect | Check port 8000 is not blocked; verify backend is running |
| Frontend shows blank page | Check `npm run dev` output for errors; check console in DevTools |
