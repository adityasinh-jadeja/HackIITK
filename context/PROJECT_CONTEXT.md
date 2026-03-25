# 🛡️ Secure Agentic Browser — Project Context

> **Read this file first.** It gives any AI agent or human the full context needed to work on any phase of this project.

---

## What Is This Project?

A **Secure Agentic Browser** built for the IIT Kanpur hackathon. It protects AI-driven browser agents from malicious web interactions (prompt injection, hidden instructions, phishing, deceptive forms) while letting legitimate tasks complete efficiently.

---

## Tech Stack (Final Decisions)

| Layer | Technology | Purpose |
|---|---|---|
| **Desktop Shell** | Electron 33 | Window management, BrowserView for web content |
| **Frontend** | React 19 + Vite 8 | Command bar, security dashboard, HITL approval UI |
| **Backend** | **Python (FastAPI)** | Security pipeline, agent orchestrator, API server |
| **Browser Automation** | Playwright (Python) | Sandboxed page loading, DOM extraction, action execution |
| **Guard LLM** | Google Gemini | Threat reasoning, intent classification |
| **Database** | MongoDB | Session logs, threat events, forensics data |
| **Real-time Comms** | WebSocket (FastAPI) | Live dashboard updates, agent status streaming |
| **Evaluation** | Python (pytest + custom) | F1-score, precision, recall, latency benchmarks |

---

## Directory Structure (Current → Target)

```
ABS_HACKIITK/
├── Project/
│   ├── backend-python/              ← [NEW] FastAPI backend (replaces backend-node)
│   │   ├── app/
│   │   │   ├── main.py              ← FastAPI app entry, WebSocket endpoint
│   │   │   ├── config.py            ← Environment config, API keys
│   │   │   ├── models/
│   │   │   │   ├── schemas.py       ← Pydantic models (ThreatReport, RiskScore, etc.)
│   │   │   │   └── db_models.py     ← MongoDB document models
│   │   │   ├── security/
│   │   │   │   ├── dom_scanner.py   ← DOM tree analysis, hidden element detection
│   │   │   │   ├── guard_llm.py     ← Gemini-based threat reasoning
│   │   │   │   ├── policy_engine.py ← Risk scoring, allow/block decisions
│   │   │   │   └── network_proxy.py ← Request interception, domain blocking
│   │   │   ├── agent/
│   │   │   │   ├── pipeline.py      ← Goal → Plan → Execute → Verify loop
│   │   │   │   ├── actions.py       ← Browser action definitions (click, type, navigate)
│   │   │   │   └── planner.py       ← LLM-based task decomposition
│   │   │   ├── sandbox/
│   │   │   │   ├── browser_context.py ← Playwright isolated context manager
│   │   │   │   └── permissions.py   ← Permission policies per context
│   │   │   ├── database/
│   │   │   │   ├── connection.py    ← MongoDB connection manager
│   │   │   │   └── repositories.py  ← CRUD operations for sessions, threats, logs
│   │   │   └── websocket/
│   │   │       └── handler.py       ← WebSocket event handlers for dashboard
│   │   ├── tests/
│   │   │   ├── test_dom_scanner.py
│   │   │   ├── test_guard_llm.py
│   │   │   ├── test_policy_engine.py
│   │   │   └── test_pages/          ← HTML files simulating attack scenarios
│   │   ├── evaluate.py              ← Evaluation runner (F1, precision, recall)
│   │   ├── requirements.txt
│   │   ├── .env
│   │   └── Dockerfile
│   │
│   ├── electron-shell/              ← [MODIFY] Update to connect to Python backend
│   │   ├── main.js
│   │   └── preload.js
│   │
│   ├── frontend-react/              ← [MODIFY] Wire to real data, add new components
│   │   ├── src/
│   │   │   ├── components/
│   │   │   │   ├── BrowserUI.jsx    ← Modify: connect to Python backend WS
│   │   │   │   ├── Dashboard.jsx    ← Modify: replace mock data with real feeds
│   │   │   │   ├── ThreatHeatmap.jsx    ← [NEW] Visual overlay for threats
│   │   │   │   ├── HITLApproval.jsx     ← [NEW] Human approval dialog
│   │   │   │   ├── NetworkLog.jsx       ← [NEW] Network activity display
│   │   │   │   ├── AttackReplay.jsx     ← [NEW] Re-play recorded attacks
│   │   │   │   ├── HoneypotRunner.jsx   ← [NEW] Built-in test suite runner
│   │   │   │   └── ForensicsExport.jsx  ← [NEW] Export attack reports
│   │   │   └── ...
│   │   └── ...
│   │
│   └── honeypot-pages/              ← [NEW] Built-in attack simulation pages
│       ├── prompt_injection.html
│       ├── hidden_css.html
│       ├── phishing_login.html
│       ├── deceptive_form.html
│       ├── dynamic_injection.html
│       └── benign_shopping.html
│
├── PS_4_SS.pdf                      ← Problem statement
├── SecureBrowser_Deployment_Guide.docx
├── PROJECT_CONTEXT.md               ← THIS FILE
├── MASTER_PLAN.md                   ← Timeline & phase overview
├── PHASE_1_FOUNDATION.md
├── PHASE_2_DOM_SCANNER.md
├── PHASE_3_GUARD_LLM.md
├── PHASE_4_SANDBOXING.md
├── PHASE_5_AGENT_EVAL.md
└── PHASE_6_DEMO_POLISH.md
```

---

## Architecture Diagram

```
USER types goal: "Buy a laptop under $500"
         │
         ▼
┌─────────────────────────────────┐
│     ELECTRON SHELL              │
│  ┌────────────┐ ┌────────────┐  │
│  │ React UI   │ │ BrowserView│  │
│  │ (Renderer) │ │ (Web Page) │  │
│  └─────┬──────┘ └────────────┘  │
│        │ IPC                     │
└────────┼────────────────────────┘
         │ WebSocket
         ▼
┌─────────────────────────────────────────────────────┐
│              PYTHON BACKEND (FastAPI)                │
│                                                     │
│  ┌──────────┐    ┌─────────────┐    ┌────────────┐  │
│  │  Agent    │───▶│  Security   │───▶│  Sandbox   │  │
│  │ Pipeline  │    │    Gate     │    │  (Playwright│  │
│  │          │    │             │    │   Context)  │  │
│  └──────────┘    └──────┬──────┘    └────────────┘  │
│                         │                           │
│           ┌─────────────┼─────────────┐             │
│           ▼             ▼             ▼             │
│    ┌────────────┐ ┌───────────┐ ┌──────────┐       │
│    │ DOM Scanner│ │ Guard LLM │ │  Policy  │       │
│    │            │ │ (Gemini)  │ │  Engine  │       │
│    └────────────┘ └───────────┘ └──────────┘       │
│           │             │             │             │
│           └─────────────┼─────────────┘             │
│                         ▼                           │
│              ┌────────────────┐                     │
│              │   MongoDB      │                     │
│              │ (logs, threats │                     │
│              │  forensics)    │                     │
│              └────────────────┘                     │
└─────────────────────────────────────────────────────┘
```

---

## Security Pipeline (Per Action)

Every browser action the agent wants to execute passes through this pipeline:

```
Agent wants to: click(#buy-button)
         │
         ▼
    ┌─────────┐     Extract full DOM tree, styles, visibility
    │   DOM   │──── Detect hidden text, suspicious forms, injection patterns
    │ Scanner │──── Output: ThreatReport{threats[], risk_score: 0-100}
    └────┬────┘
         │
         ▼
    ┌─────────┐     Send sanitized DOM summary + agent goal to Gemini
    │  Guard  │──── Compare page intent vs stated goal
    │   LLM   │──── Output: {classification, explanation, confidence}
    └────┬────┘
         │
         ▼
    ┌─────────┐     Aggregate: DOM(0.4) + LLM(0.4) + Heuristic(0.2)
    │ Policy  │──── Apply domain allowlist/blocklist
    │ Engine  │──── Decision: ALLOW / WARN / REQUIRE_APPROVAL / BLOCK
    └────┬────┘
         │
         ▼
    ┌─────────┐
    │ Execute │──── If ALLOW: proceed in sandbox
    │   or    │──── If REQUIRE_APPROVAL: send HITL request to dashboard
    │  Block  │──── If BLOCK: log reason, skip action, notify agent
    └─────────┘
```

---

## Data Models (Pydantic)

```python
class ThreatReport(BaseModel):
    page_url: str
    scan_timestamp: datetime
    threats: list[Threat]           # Individual threats found
    dom_risk_score: float           # 0.0 - 100.0
    scan_duration_ms: float

class Threat(BaseModel):
    type: str                       # "prompt_injection" | "hidden_text" | "deceptive_form" | "phishing" | "dynamic_injection"
    severity: str                   # "low" | "medium" | "high" | "critical"
    element_xpath: str              # XPath to the suspicious element
    element_html: str               # Raw HTML of the element
    description: str                # Human-readable explanation
    confidence: float               # 0.0 - 1.0

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

class SessionLog(BaseModel):
    session_id: str
    start_time: datetime
    goal: str
    actions: list[ActionLog]
    threats_detected: list[ThreatReport]
    policy_decisions: list[PolicyDecision]
    outcome: str                    # "completed" | "blocked" | "aborted"
```

---

## API Endpoints (FastAPI)

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/agent/start` | Start agent with a goal |
| `POST` | `/api/agent/stop` | Stop running agent |
| `GET` | `/api/dashboard` | Get current dashboard state |
| `GET` | `/api/sessions` | List all session logs |
| `GET` | `/api/sessions/{id}` | Get detailed session with forensics |
| `POST` | `/api/hitl/respond` | Submit HITL approval/rejection |
| `GET` | `/api/threats` | List all detected threats |
| `POST` | `/api/scan` | Manually scan a URL |
| `GET` | `/api/honeypot/run` | Run all honeypot tests |
| `GET` | `/api/evaluate` | Run evaluation framework |
| `WebSocket` | `/ws/dashboard` | Real-time dashboard updates |

---

## Environment Variables

```env
# LLM
GEMINI_API_KEY=your_key_here

# Database
MONGODB_URI=mongodb://localhost:27017/secure-browser

# Server
PORT=8000
HOST=0.0.0.0

# Security
MAX_PAGE_LOAD_TIMEOUT=30000
RISK_THRESHOLD_WARN=40
RISK_THRESHOLD_APPROVAL=65
RISK_THRESHOLD_BLOCK=85

# Sandbox
PLAYWRIGHT_HEADLESS=true
MAX_CONCURRENT_CONTEXTS=5
```

---

## Key Decisions Log

| Decision | Choice | Reasoning |
|---|---|---|
| Backend language | Python (FastAPI) | PS requires `evaluate.py`, NLP/ML libs are Python-native, Playwright Python API |
| Guard LLM | Google Gemini | Cost-effective, fast, good reasoning capability, already has API key configured |
| Sandboxing approach | Playwright browser context isolation + network proxy | Achievable in timeline, provides real isolation without container overhead |
| Database | MongoDB with full integration | Session logs, threat events, forensics all need persistent storage for demo + evaluation |
| Frontend framework | Keep React 19 + Vite | Already built, just needs to be wired to real Python backend |
| Electron shell | Keep, modify WebSocket target | Already works well, just point to FastAPI WS instead of Node.js |

---

## How to Use This Context

1. **Starting a new phase?** Read this file first, then the specific `PHASE_X_*.md` file.
2. **Different agent working?** This file has everything: architecture, data models, API surface, directory structure.
3. **Confused about a decision?** Check the "Key Decisions Log" table above.
4. **Need the problem statement?** See `PS_4_SS.pdf` — key points are attack scenarios and evaluation criteria listed in this file's "What Is This Project" section plus the `MASTER_PLAN.md`.
