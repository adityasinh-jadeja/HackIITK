# Phase 6: Honeypot Testing, Demo Video Prep & Polish

> **Duration**: Days 8–10 | **Parallel tracks**: Backend (Honeypot + Forensics) + Frontend (Attack Replay + Heatmap + Polish)
> **Prerequisites**: Phases 1-5 complete (full pipeline working, evaluation producing scores)
> **Outcome**: Demo-ready product with built-in attack tests, visual threat overlays, forensics export, polished UI, and everything needed for the 5-10 minute demo video

---

## 📖 Context for This Phase

Read `PROJECT_CONTEXT.md` first for full architecture and data models.

**What all previous phases gave you:**
- Complete security pipeline: DOM Scanner → Guard LLM → Policy Engine (Phases 2-3)
- Sandboxed browser contexts with network proxy (Phase 4)
- Agent pipeline: goal → plan → secure-execute → verify (Phase 5)
- Evaluation harness with F1/precision/recall (Phase 5)
- Real-time dashboard with threat display, HITL approval, network logs (Phases 1-5)
- MongoDB storing all sessions, threats, and decisions (Phase 1)

**What this phase builds:**
- Built-in honeypot test pages that simulate all 5 attacks
- One-click "Run Security Test" feature
- Visual threat heatmap overlay
- Attack replay and forensics export
- UI polish, animations, and demo readiness
- Documentation for the submission

---

## 🔧 Backend Track — Honeypot Test Suite

### 6.1 — Create Honeypot Pages

Create `Project/honeypot-pages/` with HTML files simulating each attack type. These are **more realistic** than the Phase 2 test pages — they're full pages that look real but contain hidden attacks.

**`Project/honeypot-pages/prompt_injection.html`**:
A realistic e-commerce product page with prompt injection hidden in a product description.

**`Project/honeypot-pages/hidden_css.html`**:
A news article page with hidden instructions in multiple CSS hiding techniques (display:none, opacity, tiny fonts, off-screen positioning).

**`Project/honeypot-pages/phishing_login.html`**:
A convincing Google login clone on a suspicious domain, with urgency messaging and fake security badges.

**`Project/honeypot-pages/deceptive_form.html`**:
A checkout page with hidden inputs exfiltrating session tokens and misleading button labels.

**`Project/honeypot-pages/dynamic_injection.html`**:
A blog page where JavaScript modifies the DOM after 2 seconds to inject malicious instructions.

**`Project/honeypot-pages/benign_shopping.html`**:
A completely safe e-commerce page to verify no false positives.

> Each page should look visually professional — they're part of the demo video.

### 6.2 — Honeypot API Endpoint

Add to `app/main.py`:

```python
from pathlib import Path
import os

HONEYPOT_DIR = Path(__file__).parent.parent.parent / "honeypot-pages"

@app.get("/api/honeypot/list")
async def list_honeypots():
    """List all available honeypot test pages."""
    pages = []
    for f in sorted(HONEYPOT_DIR.glob("*.html")):
        pages.append({
            "name": f.stem.replace("_", " ").title(),
            "filename": f.name,
            "url": f"file:///{f.resolve().as_posix()}",
            "expected": "malicious" if f.stem != "benign_shopping" else "safe",
        })
    return {"pages": pages}

@app.get("/api/honeypot/run")
async def run_honeypots():
    """
    Run the full security pipeline against ALL honeypot pages.
    Returns results for each page.
    """
    results = []
    for f in sorted(HONEYPOT_DIR.glob("*.html")):
        url = f"file:///{f.resolve().as_posix()}"
        try:
            evaluation = await security_gate.evaluate_url(url, "General browsing test")
            results.append({
                "page": f.stem,
                "url": url,
                "expected": "malicious" if f.stem != "benign_shopping" else "safe",
                "threats_found": len(evaluation["threat_report"].threats),
                "dom_risk": evaluation["threat_report"].dom_risk_score,
                "llm_verdict": evaluation["llm_verdict"].classification,
                "policy_action": evaluation["policy_decision"].action,
                "latency_ms": evaluation["total_latency_ms"],
                "passed": (
                    (evaluation["policy_decision"].action in ["BLOCK", "REQUIRE_APPROVAL"] and f.stem != "benign_shopping")
                    or
                    (evaluation["policy_decision"].action == "ALLOW" and f.stem == "benign_shopping")
                ),
            })
        except Exception as e:
            results.append({"page": f.stem, "error": str(e), "passed": False})

    passed = sum(1 for r in results if r.get("passed"))
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }
```

### 6.3 — Forensics Export

**File: `app/forensics/exporter.py`** (NEW)

```python
"""
Forensics Exporter — Generates comprehensive reports for security events.
Can export as JSON (machine-readable) or produce data for the dashboard.
"""

from app.database.repositories import get_sessions, get_threats
from datetime import datetime, timezone
import json


class ForensicsExporter:
    async def export_session(self, session_id: str) -> dict:
        """
        Export complete forensics data for a session.
        Includes: goals, actions, threats, policy decisions, network logs, timelines.
        """
        from app.database.connection import get_db
        db = get_db()

        session = await db.sessions.find_one({"session_id": session_id})
        threats = await get_threats(session_id=session_id)
        decisions = await db.policy_decisions.find({"session_id": session_id}).to_list(100)
        network = await db.network_logs.find({"session_id": session_id}).to_list(1000)

        report = {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "session": {
                "id": session_id,
                "goal": session.get("goal", "Unknown") if session else "Unknown",
                "start_time": str(session.get("created_at", "")),
                "status": session.get("status", "unknown"),
            },
            "security_summary": {
                "total_threats": len(threats),
                "critical_threats": sum(1 for t in threats if t.get("severity") == "critical"),
                "total_policy_decisions": len(decisions),
                "blocked_actions": sum(1 for d in decisions if d.get("action") == "BLOCK"),
            },
            "threats": threats,
            "policy_decisions": decisions,
            "network_activity": {
                "total_requests": len(network),
                "blocked_requests": sum(1 for n in network if n.get("action") == "BLOCK"),
                "log": network[:100],  # Cap at 100 for readability
            },
        }

        return report

    async def export_all_sessions(self) -> list:
        """Get summary of all sessions for the forensics panel."""
        sessions = await get_sessions(limit=50)
        summaries = []
        for s in sessions:
            threat_count = len(await get_threats(session_id=s.get("session_id")))
            summaries.append({
                "session_id": s.get("session_id"),
                "goal": s.get("goal", ""),
                "created_at": str(s.get("created_at", "")),
                "status": s.get("status", ""),
                "threat_count": threat_count,
            })
        return summaries
```

Add endpoints:

```python
from app.forensics.exporter import ForensicsExporter

forensics = ForensicsExporter()

@app.get("/api/sessions")
async def list_sessions():
    return {"sessions": await forensics.export_all_sessions()}

@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str):
    return await forensics.export_session(session_id)
```

---

## 🎨 Frontend Track — Demo-Ready UI Components

### 6.4 — `HoneypotRunner.jsx` (NEW Component)

A visual test runner panel that shows honeypot results in real time.

```
┌──────────────────────────────────────────────────────────┐
│  🍯 Honeypot Security Test Suite                         │
│                                                           │
│  [▶ Run All Tests]              Passed: 5/6  ⏱ 12.3s    │
│                                                           │
│  ┌──────────────────────────────────────────────────┐    │
│  │ ✅ Prompt Injection     BLOCKED   Risk: 92  1.8s │    │
│  │    3 threats found | LLM: malicious (0.95)       │    │
│  │ ✅ Hidden CSS           BLOCKED   Risk: 87  2.1s │    │
│  │    5 threats found | LLM: malicious (0.88)       │    │
│  │ ✅ Phishing Login       BLOCKED   Risk: 95  1.9s │    │
│  │    4 threats found | LLM: malicious (0.97)       │    │
│  │ ✅ Deceptive Form       REQUIRE   Risk: 72  2.3s │    │
│  │    2 threats found | LLM: suspicious (0.78)      │    │
│  │ ✅ Dynamic Injection    BLOCKED   Risk: 85  3.1s │    │
│  │    6 threats found | LLM: malicious (0.91)       │    │
│  │ ✅ Benign Shopping      ALLOW     Risk: 3   1.1s │    │
│  │    0 threats found | LLM: safe (0.96)            │    │
│  └──────────────────────────────────────────────────┘    │
│                                                           │
│  Metrics:  Precision: 100%  Recall: 100%  F1: 1.00      │
└──────────────────────────────────────────────────────────┘
```

Behavior:
- Fetches page list from `GET /api/honeypot/list`
- "Run All Tests" calls `GET /api/honeypot/run`
- Individual results stream in as they complete
- Color-coded pass/fail with expandable detail rows
- Metrics computed and displayed at the bottom

### 6.5 — `ThreatHeatmap.jsx` (NEW Component)

An overlay that visually highlights threats on the browsed page. This component renders on top of the BrowserView.

Concept:
- When a scan completes, receive threat XPaths
- Use Electron's `executeJavascript` to inject highlight CSS on the page
- Semi-transparent red overlays on deceptive elements
- Yellow borders on suspicious forms
- Tooltip on hover showing threat type and confidence

Implementation approach:
- Create a `heatmap-inject.js` script that receives threat data and adds overlay divs
- Inject via `browserView.webContents.executeJavaScript(script)`
- Toggle on/off with a button in BrowserUI

```javascript
// Simplified injection script concept:
function applyThreatHeatmap(threats) {
    threats.forEach(threat => {
        try {
            // Use XPath to find the element
            const result = document.evaluate(
                threat.element_xpath,
                document,
                null,
                XPathResult.FIRST_ORDERED_NODE_TYPE
            );
            const el = result.singleNodeValue;
            if (el) {
                el.style.outline = threat.severity === 'critical'
                    ? '3px solid rgba(255,0,0,0.8)'
                    : '2px solid rgba(255,165,0,0.7)';
                el.style.backgroundColor = threat.severity === 'critical'
                    ? 'rgba(255,0,0,0.1)'
                    : 'rgba(255,165,0,0.05)';
                el.title = `[${threat.type}] ${threat.description}`;
            }
        } catch(e) {}
    });
}
```

### 6.6 — `AttackReplay.jsx` (NEW Component)

Replay a recorded session step-by-step showing how the security pipeline defended against attacks.

```
┌──────────────────────────────────────────────────────┐
│  🔄 Attack Replay — Session abc-123                  │
│                                                       │
│  Timeline:                                            │
│  ├─ 14:23:01  Agent started: "Buy a laptop"          │
│  ├─ 14:23:02  Navigate → amazon.com ✅ SAFE          │
│  ├─ 14:23:05  Navigate → phishing-amazon.com         │
│  │            ├─ DOM: 3 threats (2 critical)          │
│  │            ├─ LLM: MALICIOUS (0.95)               │
│  │            └─ 🚫 BLOCKED — Phishing detected      │
│  ├─ 14:23:06  Navigate → real-amazon.com ✅ SAFE     │
│  └─ 14:23:15  Task completed                         │
│                                                       │
│  [◀ Prev] [▶ Next] [⏯ Auto-play]  Step 3/7          │
└──────────────────────────────────────────────────────┘
```

Data source: `GET /api/sessions/{session_id}` to load forensics data.

### 6.7 — `ForensicsExport.jsx` (NEW Component)

A button/panel that exports the full forensics report.

- "📥 Export JSON" → downloads the full session forensics as a `.json` file
- Session picker dropdown to select which session to export
- Summary stats before export (threats found, actions taken, etc.)

### 6.8 — Dashboard Sidebar Navigation

Update the dashboard to have proper tabbed navigation:

```
┌──────┬──────────────────────────────────────────────┐
│ SIDE │  Content Area                                │
│ BAR  │                                              │
│      │                                              │
│ 📊   │  (Changes based on selected tab)             │
│ Over │                                              │
│ view │                                              │
│      │                                              │
│ 🤖   │                                              │
│ Agent│                                              │
│      │                                              │
│ 🛡️   │                                              │
│ Thrt.│                                              │
│      │                                              │
│ 🌐   │                                              │
│ Net. │                                              │
│      │                                              │
│ 🍯   │                                              │
│ Test │                                              │
│      │                                              │
│ 🔄   │                                              │
│ Rep. │                                              │
│      │                                              │
│ 📥   │                                              │
│ Exp. │                                              │
└──────┴──────────────────────────────────────────────┘
```

Tabs:
1. **Overview** — Risk gauge, quick metrics, recent threats (existing Dashboard)
2. **Agent** — Step-by-step agent pipeline view (Phase 5)
3. **Threats** — Full threat list with filters (Phase 2)
4. **Network** — Network activity log (Phase 4)
5. **Honeypot** — Test suite runner (this phase)
6. **Replay** — Attack replay viewer (this phase)
7. **Export** — Forensics export (this phase)

---

## 🎨 UI Polish & Animations

### 6.9 — Global UI Enhancements

Apply to the entire application:

**Color System:**
```css
:root {
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1e293b;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --accent-blue: #3b82f6;
    --accent-green: #22c55e;
    --accent-yellow: #eab308;
    --accent-orange: #f97316;
    --accent-red: #ef4444;
    --accent-purple: #a855f7;
    --border: rgba(255, 255, 255, 0.08);
    --glass: rgba(255, 255, 255, 0.03);
}
```

**Animations:**
- Risk gauge needle animation (smooth rotation)
- Threat card slide-in with stagger
- WebSocket connection pulse (subtle heartbeat when connected)
- Step completion checkmark animation
- Risk score counter animation (count up/down)
- Sidebar tab switch with fade transition
- Honeypot test results appear one-by-one with cascade effect

**Typography:**
- Use Google Font: `Inter` (or `JetBrains Mono` for code/technical data)
- Risk numbers: large, bold, with the right color
- Timestamps: small, monospace, muted color

**Glassmorphism:**
- Card backgrounds with backdrop-filter blur
- Subtle gradient borders
- Frosted glass effect on the sidebar

---

## 📄 Documentation

### 6.10 — `README.md`

Create a comprehensive README at the project root:

```markdown
# 🛡️ Secure Agentic Browser

A multi-layered security system that protects AI-driven browser agents from 
malicious web interactions including prompt injection, phishing, hidden 
instructions, deceptive forms, and dynamic content injection.

## Architecture
[Include the ASCII architecture diagram from PROJECT_CONTEXT.md]

## Features
- 5-detector DOM Scanner
- Guard LLM (Gemini) threat reasoning
- Policy Engine with configurable thresholds
- Sandboxed browser contexts (Playwright)
- Network request interception and filtering
- Real-time security dashboard
- Human-in-the-Loop approval system
- Built-in honeypot test suite
- Attack replay and forensics export
- F1/Precision/Recall evaluation framework

## Quick Start
[Setup instructions]

## Running Evaluation
```bash
python evaluate.py --verbose
```

## Demo Video
[Link]
```

### 6.11 — Technical Documentation

Create `TechnicalDocumentation.pdf` (can be generated from a markdown file):
- System architecture
- Threat model (the 5 attack types)
- Detection logic per attack type
- Policy engine algorithm
- Guard LLM prompt design
- Evaluation results
- Performance benchmarks

---

## ✅ Final Verification Checklist

- [ ] All 6 honeypot pages render correctly in the browser
- [ ] "Run All Tests" detects all 5 attack pages and passes the benign page
- [ ] F1 score ≥ 0.8 on the evaluation framework
- [ ] Threat heatmap visually highlights threats on a page
- [ ] Attack replay plays through a recorded session step-by-step
- [ ] Forensics export produces a valid, detailed JSON file
- [ ] Dashboard sidebar navigation works across all tabs
- [ ] UI looks polished — dark theme, animations, proper typography
- [ ] README.md is complete with setup instructions
- [ ] Technical documentation covers architecture + threat model
- [ ] Agent can complete a simple legitimate task end-to-end
- [ ] Demo video scenario works: start task → encounter attack → detect → block → explain → complete
- [ ] Full system starts with one command (or documented multi-command startup)
- [ ] `evaluate.py --verbose --output report.json` produces clean output
- [ ] No console errors in the frontend
- [ ] WebSocket reconnects automatically if backend restarts

---

## 🧪 Manual Testing Steps

### Prerequisites
- Phases 1-5 complete (full pipeline working, evaluate.py produces results)
- Backend running on port 8000
- Frontend running on port 5173
- MongoDB running
- Honeypot HTML pages created in `Project/honeypot-pages/`

### Test 1: Honeypot Pages Render Correctly

Open each honeypot page directly in Chrome to verify they look professional:

```bash
# Open each in the browser
start file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/Project/honeypot-pages/prompt_injection.html
start file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/Project/honeypot-pages/hidden_css.html
start file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/Project/honeypot-pages/phishing_login.html
start file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/Project/honeypot-pages/deceptive_form.html
start file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/Project/honeypot-pages/dynamic_injection.html
start file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/Project/honeypot-pages/benign_shopping.html
```

**✅ Expected**: Each page looks like a real website — professional layout, realistic content. The hidden attacks are NOT visible to the naked eye (except for the benign page which should look completely normal).

---

### Test 2: Honeypot List API

```bash
curl http://localhost:8000/api/honeypot/list
```

**✅ Expected**:
```json
{
  "pages": [
    {"name": "Benign Shopping", "filename": "benign_shopping.html", "url": "file:///...", "expected": "safe"},
    {"name": "Deceptive Form", "filename": "deceptive_form.html", "url": "file:///...", "expected": "malicious"},
    ...
  ]
}
```

All 6 pages listed with correct `expected` classification.

---

### Test 3: Run All Honeypot Tests

```bash
curl http://localhost:8000/api/honeypot/run
```

**✅ Expected**:
```json
{
  "total": 6,
  "passed": 6,
  "failed": 0,
  "results": [
    {"page": "prompt_injection", "expected": "malicious", "policy_action": "BLOCK", "passed": true, ...},
    {"page": "benign_shopping", "expected": "safe", "policy_action": "ALLOW", "passed": true, ...},
    ...
  ]
}
```

- All 5 malicious pages have `policy_action` = BLOCK or REQUIRE_APPROVAL → `passed: true`
- Benign page has `policy_action` = ALLOW → `passed: true`
- `passed: 6, failed: 0`

---

### Test 4: Honeypot Runner UI

1. Open the dashboard at `http://localhost:5173`
2. Navigate to the Honeypot / Test tab
3. Click "▶ Run All Tests"

**✅ Expected**:
- Test results appear one-by-one with cascade animation
- Each result shows: pass/fail icon, page name, action, risk score, latency
- Expandable rows show threat details
- Bottom metrics show Precision / Recall / F1
- Total time displayed at the top

---

### Test 5: Forensics Session List

```bash
curl http://localhost:8000/api/sessions
```

**✅ Expected**:
```json
{
  "sessions": [
    {"session_id": "uuid", "goal": "...", "created_at": "...", "status": "completed", "threat_count": 5},
    ...
  ]
}
```

At least one session from previous agent runs.

---

### Test 6: Forensics Session Detail

Pick a session_id from Test 5 and fetch its details:

```bash
curl http://localhost:8000/api/sessions/YOUR_SESSION_ID_HERE
```

**✅ Expected**: Complete forensics report with:
- `session` — goal, start time, status
- `security_summary` — total threats, critical count, blocked actions
- `threats` — full array of threat objects
- `policy_decisions` — all policy decisions during the session
- `network_activity` — total requests, blocked requests, and log entries

---

### Test 7: Forensics Export (Frontend)

1. Open the dashboard → Export tab
2. Select a session from the dropdown
3. Click "📥 Export JSON"

**✅ Expected**:
- Browser downloads a `.json` file
- Open the file — it contains the same data as Test 6
- File is well-formatted JSON (not minified)

---

### Test 8: Threat Heatmap Overlay

1. Navigate to a test attack page in the BrowserView (Electron)
2. Run a scan on that page
3. Toggle the heatmap overlay button

**✅ Expected**:
- Red outlines appear around malicious elements (hidden divs, deceptive forms)
- Orange outlines around suspicious elements
- Hover over outlined elements → tooltip shows threat type and description
- Toggle button turns heatmap on/off
- Heatmap clears when navigating to a new page

---

### Test 9: Attack Replay

1. Run the agent against a phishing test page (agent navigates, gets blocked)
2. Open the dashboard → Replay tab
3. Select the session from the dropdown
4. Click Play or step through manually

**✅ Expected**:
- Timeline shows all steps in chronological order
- Blocked steps highlighted in red with reason
- Security gate details expandable per step (DOM threats, LLM verdict, policy action)
- Prev/Next buttons work
- Auto-play steps through with a 2-second delay per step

---

### Test 10: Dashboard Sidebar Navigation

Click through each tab in the sidebar:

| Tab | What Should Show |
|---|---|
| 📊 Overview | Risk gauge, quick metrics, recent threats |
| 🤖 Agent | Agent pipeline steps, current goal, status |
| 🛡️ Threats | Full threat list with severity filter |
| 🌐 Network | Network activity log, blocked requests |
| 🍯 Honeypot | Test runner with Run All button |
| 🔄 Replay | Session picker + timeline player |
| 📥 Export | Session picker + download button |

**✅ Expected**:
- Each tab renders its correct content
- Fade/slide transition between tabs
- Active tab highlighted in sidebar
- No console errors when switching tabs
- Content updates in real-time via WebSocket

---

### Test 11: UI Polish Checks

Open the dashboard and verify the following visual elements:

**Color System**:
- [ ] Dark background (`#0a0e17` primary, `#111827` secondary)
- [ ] Cards have glassmorphism effect (frosted glass look)
- [ ] Proper color coding: green=safe, yellow=warn, orange=approval, red=block

**Animations**:
- [ ] Risk gauge animates smoothly when value changes
- [ ] Threat cards slide in with stagger animation
- [ ] Step completion has checkmark animation
- [ ] Tab switch has fade transition
- [ ] Honeypot results cascade in one-by-one

**Typography**:
- [ ] Main font is `Inter` (not browser default)
- [ ] Code/technical data uses `JetBrains Mono` or monospace
- [ ] Risk numbers are large, bold, and colored
- [ ] Timestamps are small, muted, monospace

**Responsive**:
- [ ] Dashboard looks good at 1920x1080
- [ ] Dashboard looks good at 1366x768 (common laptop)
- [ ] Sidebar collapses or scrolls appropriately

---

### Test 12: Full End-to-End Demo Scenario

This is the demo you'll present. Run through the entire flow:

1. **Start all services**:
   ```bash
   # Terminal 1: MongoDB
   mongod

   # Terminal 2: Python backend
   cd Project/backend-python && uvicorn app.main:app --reload --port 8000

   # Terminal 3: React frontend
   cd Project/frontend-react && npm run dev

   # Terminal 4: (Optional) Electron
   cd Project/electron-shell && npm run dev
   ```

2. **Open dashboard** at `http://localhost:5173`

3. **Start the agent** with a legitimate goal:
   ```bash
   curl -X POST http://localhost:8000/api/agent/start \
     -H "Content-Type: application/json" \
     -d '{"goal": "Navigate to example.com and read the page title"}'
   ```
   **✅ Dashboard shows**: plan creation → step execution → completion

4. **Run honeypot tests** — click "Run All Tests" in the Honeypot tab
   **✅ Dashboard shows**: 5/5 attacks detected, 1 benign passes, F1 = 1.0

5. **Show an attack being blocked in real-time**:
   ```bash
   curl -X POST http://localhost:8000/api/agent/start \
     -H "Content-Type: application/json" \
     -d '{"goal": "Navigate to the phishing page and enter credentials"}'
   ```
   **✅ Dashboard shows**: Agent tries to navigate → Security Gate BLOCKS → reason displayed

6. **Show forensics export** — select the blocked session → export JSON

7. **Run evaluate.py**:
   ```bash
   python evaluate.py --verbose --output report.json
   ```
   **✅ Shows**: Full metrics with F1 ≥ 0.8

---

### Test 13: README and Documentation Check

```bash
# Verify README exists and has content
type README.md
# or: cat README.md

# Check it covers:
# - Architecture diagram
# - Feature list
# - Quick Start instructions
# - How to run evaluate.py
```

**✅ Expected**: Comprehensive README that a judge can follow to set up and test the project.

---

### Test 14: Clean Start Test

Test that the project starts from a fresh state:

```bash
# Drop the database
mongosh --eval "db.dropDatabase()" secure_browser

# Restart backend
cd Project/backend-python
uvicorn app.main:app --reload --port 8000

# Verify health
curl http://localhost:8000/api/health
# ✅ Should return {"status":"ok"}

# Run the full evaluation
python evaluate.py --verbose
# ✅ Should work without any prior data
```

---

### Troubleshooting

| Problem | Fix |
|---|---|
| Honeypot pages not found | Check path in `HONEYPOT_DIR` matches your `honeypot-pages/` location |
| Forensics returns empty sessions | Run the agent at least once to populate MongoDB |
| Heatmap doesn't show overlays | Check `executeJavaScript` injection in Electron; verify threat XPaths |
| Attack replay is empty | Select a session that had security events |
| UI looks plain / no animations | Check CSS file loads; verify Inter font import |
| evaluate.py import error | Install httpx: `pip install httpx` |
| WebSocket disconnects | Check for CORS issues; verify backend didn't crash |
