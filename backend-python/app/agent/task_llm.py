"""
Task LLM — Decides the next browser action for the agent loop.

Uses the same LLM client factory (Groq / Gemini / Ollama) as the Guard LLM,
but with a completely different system prompt designed for agentic browsing.
"""

import json
import re
import logging
from pydantic import BaseModel, Field
from typing import Optional
from bs4 import BeautifulSoup
from app.security.llm_client import get_llm_client

log = logging.getLogger("task_llm")
logging.basicConfig(level=logging.INFO)


class AgentAction(BaseModel):
    reasoning: str = Field(description="Step-by-step reasoning for the chosen action.")
    action: str = Field(description="Action type: click, type, scroll, navigate, wait, finish.")
    selector: Optional[str] = Field(None, description="CSS selector for click/type.")
    text: Optional[str] = Field(None, description="Text to type for 'type' action.")
    url: Optional[str] = Field(None, description="URL for 'navigate' action.")
    direction: Optional[str] = Field(None, description="'up' or 'down' for scroll.")
    amount: Optional[int] = Field(None, description="Pixels to scroll.")
    ms: Optional[int] = Field(None, description="Milliseconds to wait.")
    result: Optional[str] = Field(None, description="Final answer when action is 'finish'.")


class TaskLLM:
    """Decides the next browser action given a goal and the current DOM state."""

    SYSTEM_PROMPT = """You are an autonomous browser agent. Your job is to achieve the user's GOAL by interacting with a real web browser, one action at a time.

AVAILABLE ACTIONS (pick exactly one):
  navigate  — Go to a URL.  Requires: "url"
  click     — Click an element.  Requires: "selector" (CSS)
  type      — Type into an input.  Requires: "selector", "text"
  scroll    — Scroll the viewport.  Requires: "direction" (up|down), "amount" (pixels)
  wait      — Wait for dynamic content.  Requires: "ms"
  finish    — Goal is done or impossible.  Requires: "result" (your answer / summary)

STRATEGY RULES:
1. If CURRENT URL is "about:blank":
   - If the goal explicitly contains a fully qualified URL (e.g., "https://example.com"), navigate to it.
   - Otherwise, your FIRST action MUST be "navigate" to "https://www.google.com" so you can search for the best website for the task. Do NOT guess domains (like 'expedia.com') without searching.
2. After navigating, if you can already see the answer in the DOM, immediately use "finish" with the answer in "result".
3. Never repeat the same action twice in a row — if something didn't work, try a different approach.
4. Prefer finishing quickly. Do NOT scroll or wait unless absolutely necessary.
5. If you are stuck after 3 attempts, use "finish" with an explanation of what went wrong.

OUTPUT FORMAT — raw JSON, no markdown fences:
{
  "reasoning": "...",
  "action": "navigate|click|type|scroll|wait|finish",
  "selector": "...",
  "text": "...",
  "url": "...",
  "direction": "...",
  "amount": 0,
  "ms": 0,
  "result": "..."
}
Only include fields relevant to your chosen action. Always include "reasoning" and "action".
"""

    def __init__(self):
        self.client = get_llm_client()

    def _simplify_dom(self, raw_html: str, max_chars: int = 6000) -> str:
        """
        Condense raw HTML into a readable summary of interactive elements
        and visible text so the LLM can reason efficiently.
        """
        try:
            soup = BeautifulSoup(raw_html, "html.parser")
        except Exception:
            return raw_html[:max_chars]

        parts = []

        # Page title
        title_tag = soup.find("title")
        if title_tag:
            parts.append(f"PAGE TITLE: {title_tag.get_text(strip=True)}")

        # Headings
        for tag in soup.find_all(["h1", "h2", "h3"], limit=10):
            parts.append(f"<{tag.name}>{tag.get_text(strip=True)}</{tag.name}>")

        # Links
        for a in soup.find_all("a", href=True, limit=20):
            text = a.get_text(strip=True) or "[link]"
            parts.append(f'<a href="{a["href"]}">{text}</a>')

        # Buttons
        for btn in soup.find_all("button", limit=10):
            text = btn.get_text(strip=True) or "[button]"
            css_id = f'#{btn["id"]}' if btn.get("id") else ""
            css_class = f'.{btn["class"][0]}' if btn.get("class") else ""
            selector = css_id or css_class or "button"
            parts.append(f'<button selector="{selector}">{text}</button>')

        # Inputs
        for inp in soup.find_all("input", limit=15):
            attrs = {k: v for k, v in inp.attrs.items() if k in ("type", "name", "id", "placeholder", "value")}
            attr_str = " ".join(f'{k}="{v}"' for k, v in attrs.items())
            parts.append(f"<input {attr_str}/>")

        # Forms
        for form in soup.find_all("form", limit=5):
            action = form.get("action", "")
            method = form.get("method", "GET")
            parts.append(f'<form action="{action}" method="{method}">...</form>')

        # Paragraphs (first few for context)
        for p in soup.find_all("p", limit=5):
            text = p.get_text(strip=True)
            if text:
                parts.append(f"<p>{text[:200]}</p>")

        summary = "\n".join(parts)
        if len(summary) < 100:
            # Fallback: just send truncated raw text
            return soup.get_text(" ", strip=True)[:max_chars]
        return summary[:max_chars]

    async def decide_next_action(self, goal: str, raw_html: str, current_url: str) -> AgentAction:
        dom_summary = self._simplify_dom(raw_html)

        prompt = f"""GOAL: {goal}
CURRENT URL: {current_url}

CURRENT PAGE CONTENT:
{dom_summary}

What is the single next best action?"""

        log.info(f"[TaskLLM] Asking LLM (url={current_url})")
        response_text = await self.client.generate_json(prompt, self.SYSTEM_PROMPT)

        # Strip markdown fences if present
        response_text = response_text.strip()
        if response_text.startswith("```"):
            response_text = re.sub(r"^```(?:json)?\s*", "", response_text)
            response_text = re.sub(r"\s*```$", "", response_text)

        data = json.loads(response_text)
        action = AgentAction(**data)
        log.info(f"[TaskLLM] Decision: action={action.action}, reasoning={action.reasoning[:80]}...")
        return action
