"""FastAPI orchestration API for the Secure Agentic Browser.

Endpoints
---------
POST /task             — Start a new browsing task
GET  /task/{id}/status — Poll task state and step history
POST /task/{id}/approve — Approve a HitL-paused action
POST /task/{id}/deny   — Deny a HitL-paused action
WS   /ws/{id}          — Stream live updates (future)
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from agents.orchestrator import Orchestrator, TaskRecord, TaskState
from browser.sandbox import BrowserSandbox
from defense import hitl

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Application state
# ------------------------------------------------------------------

_sandbox: BrowserSandbox | None = None
_tasks: dict[str, TaskRecord] = {}
_running: dict[str, asyncio.Task] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    global _sandbox
    _sandbox = BrowserSandbox()
    await _sandbox.__aenter__()
    logger.info("BrowserSandbox started.")
    yield
    await _sandbox.__aexit__(None, None, None)
    from defense.opa_client import close as opa_close
    await opa_close()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="Secure Agentic Browser",
    version="0.1.0",
    description="Backend API for a secure agentic browser with Dual-LLM safety architecture.",
    lifespan=lifespan,
)


# ------------------------------------------------------------------
# Request / response models
# ------------------------------------------------------------------

class TaskCreateRequest(BaseModel):
    goal: str = Field(description="Natural-language browsing objective")
    max_iterations: int = Field(default=10, ge=1, le=50)


class TaskStatusResponse(BaseModel):
    task_id: str
    state: str
    iteration: int
    steps_total: int
    steps_executed: int
    current_plan_steps: int
    hitl_pending: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class HitLActionRequest(BaseModel):
    request_id: str = Field(default="", description="Optional specific HitL request ID")


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@app.post("/task", response_model=TaskStatusResponse)
async def create_task(body: TaskCreateRequest):
    """Start a new browsing task."""
    if _sandbox is None:
        raise HTTPException(status_code=503, detail="Browser sandbox not ready")

    orchestrator = Orchestrator(_sandbox)

    # Run in background so the API returns immediately
    async def _run():
        record = await orchestrator.run(body.goal, max_iterations=body.max_iterations)
        _tasks[record.task_id] = record
        _running.pop(record.task_id, None)

    # Create a placeholder record
    placeholder = TaskRecord(goal=body.goal, max_iterations=body.max_iterations)
    _tasks[placeholder.task_id] = placeholder

    bg = asyncio.create_task(_run())
    # Patch: store the actual task_id once orchestrator assigns it
    # For now, the background task will overwrite _tasks when done.
    _running[placeholder.task_id] = bg

    return _to_status_response(placeholder)


@app.get("/task/{task_id}/status", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """Get the current status of a task."""
    record = _tasks.get(task_id)
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    return _to_status_response(record)


@app.post("/task/{task_id}/approve")
async def approve_task(task_id: str, body: HitLActionRequest | None = None):
    """Approve a HitL-paused action."""
    pending = hitl.get_pending(task_id)
    if not pending:
        raise HTTPException(status_code=404, detail="No pending HitL request for this task")

    request_id = body.request_id if body and body.request_id else pending[0].request_id
    if not hitl.approve(request_id):
        raise HTTPException(status_code=404, detail="HitL request not found")

    return {"status": "approved", "request_id": request_id}


@app.post("/task/{task_id}/deny")
async def deny_task(task_id: str, body: HitLActionRequest | None = None):
    """Deny a HitL-paused action."""
    pending = hitl.get_pending(task_id)
    if not pending:
        raise HTTPException(status_code=404, detail="No pending HitL request for this task")

    request_id = body.request_id if body and body.request_id else pending[0].request_id
    if not hitl.deny(request_id):
        raise HTTPException(status_code=404, detail="HitL request not found")

    return {"status": "denied", "request_id": request_id}


@app.websocket("/ws/{task_id}")
async def task_websocket(ws: WebSocket, task_id: str):
    """Stream live task updates (placeholder — sends status every 2s)."""
    await ws.accept()
    try:
        while True:
            record = _tasks.get(task_id)
            if record:
                await ws.send_json(_to_status_response(record).model_dump())
                if record.state in (TaskState.DONE, TaskState.FAILED):
                    break
            else:
                await ws.send_json({"error": "task not found"})
                break
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for task %s", task_id)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _to_status_response(record: TaskRecord) -> TaskStatusResponse:
    pending = hitl.get_pending(record.task_id)
    return TaskStatusResponse(
        task_id=record.task_id,
        state=record.state.value,
        iteration=record.iteration,
        steps_total=len(record.step_history),
        steps_executed=sum(1 for s in record.step_history if s.executed),
        current_plan_steps=len(record.current_plan.steps) if record.current_plan else 0,
        hitl_pending=[
            {
                "request_id": p.request_id,
                "explanation": p.xai_explanation,
                "risk_score": p.risk_assessment.score,
            }
            for p in pending
        ],
        error=record.error,
    )
