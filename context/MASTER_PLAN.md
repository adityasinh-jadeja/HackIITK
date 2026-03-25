# 🛡️ Secure Agentic Browser — Master Plan

> **Timeline**: 10 days (March 25 – April 4, 2026)
> **Hackathon**: IIT Kanpur

---

## Phase Overview

| Phase | Name | Days | Backend Focus | Frontend Focus | Key Deliverable |
|---|---|---|---|---|---|
| **1** | Foundation | 1–2 | FastAPI + MongoDB + WebSocket | Replace Socket.IO, wire to Python backend | Server running, dashboard connected |
| **2** | DOM Scanner | 2–4 | 5 detector engines + Playwright renderer | Threat display cards, scan button | All 5 attack types detected |
| **3** | Guard LLM + Policy | 4–6 | Gemini integration + risk scoring engine | HITL approval modal, policy panels | Full 3-layer security gate |
| **4** | Sandboxing | 5–7 | Browser context isolation + network proxy | Network activity log, sandbox indicator | Isolated execution + traffic filtering |
| **5** | Agent + Evaluation | 7–8 | Agent pipeline + `evaluate.py` | Agent step-by-step UI | F1 > 0.8 on test suite |
| **6** | Demo & Polish | 8–10 | Honeypot pages + forensics export | Heatmap, replay, sidebar nav, animations | Demo-ready product |

---

## 10-Day Timeline (Gantt)

```
Day  1  ████████████████  Phase 1: FastAPI setup, MongoDB, WebSocket
Day  2  ████████████████  Phase 1 (finish) + Phase 2 (start DOM scanner)
Day  3  ████████████████  Phase 2: Build all 5 detectors
Day  4  ████████████████  Phase 2 (finish) + Phase 3 (start Guard LLM)
Day  5  ████████████████  Phase 3: Policy Engine + Phase 4 (start sandbox)
Day  6  ████████████████  Phase 3 (HITL UI) + Phase 4 (network proxy)
Day  7  ████████████████  Phase 4 (finish) + Phase 5 (start agent pipeline)
Day  8  ████████████████  Phase 5: Agent pipeline + evaluate.py
Day  9  ████████████████  Phase 6: Honeypot tests, heatmap, replay
Day 10  ████████████████  Phase 6: UI polish, documentation, demo video
```

---

## Parallel Work Streams

### Backend Engineer(s)
```
Day 1-2:  FastAPI server, MongoDB models, WebSocket handler
Day 2-4:  DOM Scanner (5 detectors), Playwright page renderer
Day 4-6:  Guard LLM (Gemini), Policy Engine, Security Gate
Day 5-7:  Sandbox Manager, Network Proxy
Day 7-8:  Agent Pipeline, evaluate.py
Day 8-10: Honeypot pages, Forensics exporter, documentation
```

### Frontend Engineer(s)
```
Day 1-2:  Replace Socket.IO with WebSocket hook, wire dashboard
Day 2-4:  Threat display cards, scan button, risk gauge
Day 4-6:  HITL approval modal, LLM verdict panel, policy display
Day 5-7:  Network log component, sandbox status indicator
Day 7-8:  Agent step-by-step UI, evaluation results display
Day 8-10: Heatmap overlay, attack replay, sidebar nav, polish
```

### Electron Engineer
```
Day 1-2:  Rewire main.js to Python backend WebSocket
Day 6:    Wire heatmap injection into BrowserView
Day 10:   Final integration testing
```

---

## File List (In Order of Creation)

### Phase 1 Files
- `backend-python/app/__init__.py`
- `backend-python/app/main.py`
- `backend-python/app/config.py`
- `backend-python/app/models/schemas.py`
- `backend-python/app/models/db_models.py`
- `backend-python/app/database/connection.py`
- `backend-python/app/database/repositories.py`
- `backend-python/app/websocket/handler.py`
- `backend-python/requirements.txt`
- `backend-python/.env`
- `frontend-react/src/hooks/useWebSocket.js` (NEW)
- `frontend-react/src/components/BrowserUI.jsx` (MODIFY)
- `frontend-react/src/components/Dashboard.jsx` (MODIFY)
- `electron-shell/main.js` (MODIFY)

### Phase 2 Files
- `backend-python/app/security/dom_scanner.py`
- `backend-python/app/security/page_renderer.py`
- `backend-python/tests/test_pages/*.html` (6 test files)
- `backend-python/tests/test_dom_scanner.py`
- `frontend-react/src/components/Dashboard.jsx` (MODIFY — threat cards)
- `frontend-react/src/components/BrowserUI.jsx` (MODIFY — scan button)

### Phase 3 Files
- `backend-python/app/security/guard_llm.py`
- `backend-python/app/security/policy_engine.py`
- `backend-python/app/security/security_gate.py`
- `backend-python/tests/test_guard_llm.py`
- `backend-python/tests/test_policy_engine.py`
- `frontend-react/src/components/HITLApproval.jsx` (NEW)
- `frontend-react/src/components/Dashboard.jsx` (MODIFY — LLM + policy panels)

### Phase 4 Files
- `backend-python/app/sandbox/browser_context.py`
- `backend-python/app/sandbox/permissions.py`
- `backend-python/app/security/network_proxy.py`
- `frontend-react/src/components/NetworkLog.jsx` (NEW)
- `frontend-react/src/components/BrowserUI.jsx` (MODIFY — sandbox indicator)

### Phase 5 Files
- `backend-python/app/agent/planner.py`
- `backend-python/app/agent/actions.py`
- `backend-python/app/agent/pipeline.py`
- `backend-python/evaluate.py`
- `frontend-react/src/components/Dashboard.jsx` (MODIFY — agent pipeline view)

### Phase 6 Files
- `honeypot-pages/*.html` (6 realistic pages)
- `backend-python/app/forensics/exporter.py`
- `frontend-react/src/components/HoneypotRunner.jsx` (NEW)
- `frontend-react/src/components/ThreatHeatmap.jsx` (NEW)
- `frontend-react/src/components/AttackReplay.jsx` (NEW)
- `frontend-react/src/components/ForensicsExport.jsx` (NEW)
- `README.md`
- `TechnicalDocumentation.md`

---

## Critical Path

The **minimum viable demo** requires these in order:
1. FastAPI running ← Phase 1
2. DOM Scanner working ← Phase 2
3. Guard LLM + Policy Engine ← Phase 3
4. Agent pipeline ← Phase 5
5. evaluate.py producing F1 > 0.8 ← Phase 5

Everything else (sandboxing, heatmap, replay, polish) adds points but isn't blocking.

> [!IMPORTANT]
> If time gets tight, **cut Phase 4 (sandboxing) to just Playwright context isolation** (skip network proxy), and **cut Phase 6 features** down to honeypot runner + README only. The judges care most about attack detection accuracy and evaluation metrics.

---

## How to Use These Phase Files

1. **Pick a phase** → Open the corresponding `PHASE_X_*.md` file
2. **Read `PROJECT_CONTEXT.md` first** — it has the full architecture, data models, and API surface
3. **Each phase is self-contained** — includes code blueprints, file paths, verification checklists, and interface contracts for the next phase
4. **Hand off to any AI agent** — give it `PROJECT_CONTEXT.md` + the specific phase file
5. **Track progress** — use the verification checklist at the bottom of each phase
6. **Check interfaces** — each phase lists what it provides to subsequent phases
