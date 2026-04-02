"""
Browser Agent — Autonomous ReAct loop that drives the sandboxed browser.

Live Streaming Architecture:
  - On task start, we activate CDP Page.startScreencast which pushes JPEG
    frames to the frontend continuously (like a video stream) — the user
    sees the page load, scroll, and react in real-time.
  - Agent reasoning steps are broadcast as thin JSON events so the UI
    can show them alongside the live video.

Flow per step:
  1. Get current DOM from the sandbox
  2. Ask the Task LLM for the next action
  3. If destructive -> pause for HITL approval
  4. If navigate -> run through SecurityGate first
  5. Execute the action in the sandbox
  6. Broadcast step metadata (reasoning, action) to the frontend
     (screenshots are streamed automatically by CDP screencast)
"""

import asyncio
import uuid
import logging
from app.sandbox.browser_context import SandboxManager
from app.security.security_gate import SecurityGate
from app.websocket.handler import ws_manager
from app.agent.task_llm import TaskLLM

log = logging.getLogger("browser_agent")

# Keywords that suggest a destructive action needing human approval
DESTRUCTIVE_KEYWORDS = [
    "buy", "purchase", "pay", "submit", "send",
    "checkout", "login", "sign in", "confirm", "order",
]


class BrowserAgent:
    """
    Autonomous browser agent that reasons and acts to fulfill user goals.
    Spawned as an asyncio background task from the /api/agent/start endpoint.
    
    Uses CDP screencast for real-time live video streaming to the frontend,
    instead of taking a screenshot after each step.
    """

    def __init__(self, sandbox: SandboxManager, security_gate: SecurityGate):
        self.sandbox = sandbox
        self.security_gate = security_gate
        self.task_llm = TaskLLM()
        self.max_steps = 15
        self.is_running = False
        self._current_url = "about:blank"
        self._steps_log = []  # Accumulates step history for the frontend
        self._async_loop = None  # Reference to the event loop for screencast callback

    def _on_screencast_frame(self, session_id, frame_b64, metadata):
        """
        Called from the Playwright thread whenever CDP pushes a new frame.
        We schedule a WebSocket broadcast on the asyncio event loop.
        """
        if self._async_loop and self._async_loop.is_running():
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast({
                    "type": "LIVE_FRAME",
                    "data": {
                        "frame": frame_b64,
                        "timestamp": metadata.get("timestamp", 0),
                    }
                }),
                self._async_loop,
            )

    async def _broadcast_step(self, session_id, step, goal, status, reasoning="", action_type="", detail=""):
        """Broadcast a thin AGENT_STEP event (no screenshot — that's handled by screencast)."""
        # Get current page URL from the sandbox
        try:
            page_url = await self.sandbox.get_page_url(session_id)
            self._current_url = page_url
        except Exception:
            page_url = self._current_url

        step_info = {
            "step": step,
            "maxSteps": self.max_steps,
            "status": status,
            "reasoning": reasoning,
            "actionType": action_type,
            "detail": detail,
            "url": page_url,
        }
        self._steps_log.append(step_info)

        await ws_manager.broadcast({
            "type": "AGENT_STEP",
            "data": {
                "agentStatus": status,
                "currentGoal": goal,
                "currentUrl": page_url,
                "stepInfo": step_info,
                "stepsLog": self._steps_log[-10:],  # Last 10 steps
            }
        })

    async def run_task(self, session_id: str, goal: str):
        self.is_running = True
        self._current_url = "about:blank"
        self._steps_log = []
        self._async_loop = asyncio.get_running_loop()
        step = 0

        # --- Start live screencast stream ---
        try:
            await self.sandbox.start_screencast(session_id, self._on_screencast_frame)
            log.info("[Agent] CDP Screencast started — live streaming to frontend")
        except Exception as e:
            log.warning(f"[Agent] Could not start screencast: {e}")

        try:
            while self.is_running and step < self.max_steps:
                step += 1
                log.info(f"=== STEP {step}/{self.max_steps} ===")

                # --- Step A: Get current DOM ---
                try:
                    html = await self.sandbox.get_page_content(session_id)
                except Exception:
                    html = "<html><body>Blank page - no URL loaded yet.</body></html>"

                # --- Step B: Broadcast "planning" ---
                await self._broadcast_step(
                    session_id, step, goal,
                    status="planning",
                    reasoning="Analyzing current page and deciding next action...",
                    action_type="think",
                )

                # --- Step C: Ask the Task LLM (with retry) ---
                action = None
                for llm_attempt in range(3):
                    try:
                        action = await self.task_llm.decide_next_action(
                            goal, html, self._current_url
                        )
                        break  # Success
                    except Exception as e:
                        if llm_attempt < 2:
                            wait = 5 * (llm_attempt + 1)
                            log.warning(f"  LLM attempt {llm_attempt+1} failed: {e}. Retrying in {wait}s...")
                            await self._broadcast_step(
                                session_id, step, goal,
                                status="planning",
                                reasoning=f"LLM rate limited. Retrying in {wait}s... (attempt {llm_attempt+2}/3)",
                                action_type="think",
                            )
                            await asyncio.sleep(wait)
                        else:
                            await self._broadcast_step(
                                session_id, step, goal,
                                status="error",
                                reasoning=f"LLM failed after 3 attempts: {e}",
                                action_type="error",
                            )

                if action is None:
                    break

                log.info(f"  LLM chose: {action.action} | reasoning: {action.reasoning[:100]}")

                # --- Step D: If finished -> stop ---
                if action.action == "finish":
                    await self._broadcast_step(
                        session_id, step, f"[DONE] {action.result or 'Goal achieved'}",
                        status="finished",
                        reasoning=action.reasoning,
                        action_type="finish",
                        detail=action.result or "",
                    )
                    break

                # --- Step E: HITL guard for destructive actions ---
                if action.action in ("click", "type"):
                    combined = (
                        (action.selector or "") + " " + (action.text or "")
                    ).lower()
                    if any(kw in combined for kw in DESTRUCTIVE_KEYWORDS):
                        await self._broadcast_step(
                            session_id, step, goal,
                            status="awaiting_approval",
                            reasoning=f"This looks like a destructive action. Waiting for your approval...",
                            action_type=action.action,
                            detail=action.selector or "",
                        )
                        approved = await self._request_hitl_approval(
                            f"Agent wants to {action.action} on "
                            f"'{action.selector}'. Approve?"
                        )
                        if not approved:
                            await self._broadcast_step(
                                session_id, step, "[BLOCKED] Aborted by user",
                                status="failed",
                                reasoning="User denied the destructive action.",
                                action_type="blocked",
                            )
                            break

                # --- Step F: Execute the action ---
                detail = action.selector or action.url or ""

                if action.action == "navigate" and action.url:
                    await self._broadcast_step(
                        session_id, step, goal,
                        status="navigating",
                        reasoning=action.reasoning,
                        action_type="navigate",
                        detail=action.url,
                    )
                    # Navigation goes through SecurityGate first
                    result = await self.security_gate.evaluate_url(
                        action.url, goal, self.sandbox, session_id
                    )
                    policy_action = result["policy_decision"].action
                    if policy_action == "BLOCK":
                        await self._broadcast_step(
                            session_id, step, "[BLOCKED] Security Policy blocked navigation",
                            status="failed",
                            reasoning=f"Security Gate blocked {action.url}",
                            action_type="blocked",
                            detail=action.url,
                        )
                        break
                    elif policy_action == "REQUIRE_APPROVAL":
                        req_id = result["request_id"]
                        ws_manager.hitl_events[req_id] = asyncio.Event()
                        try:
                            await asyncio.wait_for(
                                ws_manager.hitl_events[req_id].wait(), timeout=60
                            )
                        except asyncio.TimeoutError:
                            pass
                        approved = ws_manager.hitl_results.pop(req_id, False)
                        ws_manager.hitl_events.pop(req_id, None)
                        if not approved:
                            break

                    self._current_url = action.url

                elif action.action == "click":
                    await self.sandbox.execute_action(session_id, {
                        "type": "click",
                        "selector": action.selector,
                    })

                elif action.action == "type":
                    await self.sandbox.execute_action(session_id, {
                        "type": "type",
                        "selector": action.selector,
                        "text": action.text or "",
                    })

                elif action.action == "scroll":
                    await self.sandbox.execute_action(session_id, {
                        "type": "scroll",
                        "direction": action.direction or "down",
                        "amount": action.amount or 300,
                    })

                elif action.action == "wait":
                    await self.sandbox.execute_action(session_id, {
                        "type": "wait",
                        "ms": action.ms or 1000,
                    })

                # --- Step G: Broadcast action result ---
                await asyncio.sleep(1.5)  # let page settle and screencast push frames
                await self._broadcast_step(
                    session_id, step, goal,
                    status="executing",
                    reasoning=action.reasoning,
                    action_type=action.action,
                    detail=detail,
                )

                await asyncio.sleep(0.5)

            # If we exhausted all steps
            if step >= self.max_steps and self.is_running:
                await self._broadcast_step(
                    session_id, step, "[TIMEOUT] Max steps exceeded",
                    status="failed",
                    reasoning="Reached the maximum number of steps without completing the goal.",
                    action_type="timeout",
                )

        except asyncio.CancelledError:
            pass
        except Exception as e:
            try:
                await self._broadcast_step(
                    session_id, step, f"[ERROR] {e}",
                    status="error",
                    reasoning=str(e),
                    action_type="error",
                )
            except Exception:
                pass
        finally:
            # --- Stop live screencast stream ---
            try:
                await self.sandbox.stop_screencast(session_id)
                log.info("[Agent] CDP Screencast stopped")
            except Exception:
                pass
            self.is_running = False

    # ------------------------------------------------------------------
    async def _request_hitl_approval(self, reason: str) -> bool:
        """Broadcast a REQUIRE_APPROVAL event and block until the user responds."""
        req_id = str(uuid.uuid4())
        ws_manager.hitl_events[req_id] = asyncio.Event()

        await ws_manager.broadcast({
            "type": "SECURITY_EVALUATION",
            "data": {
                "url": "Agent Action Request",
                "action": "REQUIRE_APPROVAL",
                "overallRisk": 75,
                "policyDecision": {"reason": reason, "action": "REQUIRE_APPROVAL"},
                "llmVerdict": {
                    "classification": "suspicious",
                    "explanation": reason,
                    "confidence": 1.0,
                },
                "threats": [],
                "requestId": req_id,
            }
        })

        try:
            await asyncio.wait_for(ws_manager.hitl_events[req_id].wait(), timeout=60)
        except asyncio.TimeoutError:
            pass

        approved = ws_manager.hitl_results.pop(req_id, False)
        ws_manager.hitl_events.pop(req_id, None)
        return approved

    def stop(self):
        self.is_running = False
