"""Critique / Filter Agent — Dual LLM isolation boundary.

This agent has **zero access to execution tools**.  It never imports
Playwright, never holds a page reference, and never calls any browser API.

Its sole responsibility is "Tool Result Parsing":
  1. Receive raw scraped data (HTML / accessibility tree / text).
  2. Sanitize it (strip prompt-injection markers, scripts, data URIs).
  3. Extract only the data matching a strict JSON schema.
  4. Return the clean data to the Planner for the next planning cycle.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Strict output schema that the Critic will extract data into
# ------------------------------------------------------------------

class PageDataExtract(BaseModel):
    """Clean, schema-validated data extracted from a page."""

    title: str = ""
    url: str = ""
    main_text: str = Field(
        default="",
        description="Primary textual content on the page (sanitized)",
    )
    headings: list[str] = Field(default_factory=list)
    links: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of {text, href} dicts",
    )
    forms: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Summarised form structures (fields, actions)",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------------
# Sanitization helpers
# ------------------------------------------------------------------

# Patterns commonly used for prompt injection
_PROMPT_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"<\s*prompt\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"```\s*(system|instruction)", re.IGNORECASE),
]

_DATA_URI_RE = re.compile(r"data:[^;]+;base64,[A-Za-z0-9+/=]+", re.IGNORECASE)
_SCRIPT_TAG_RE = re.compile(r"<\s*script[^>]*>.*?</\s*script\s*>", re.IGNORECASE | re.DOTALL)
_STYLE_TAG_RE = re.compile(r"<\s*style[^>]*>.*?</\s*style\s*>", re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _sanitize_text(raw: str) -> str:
    """Strip dangerous content from raw text/HTML."""
    text = raw

    # Remove script and style tags
    text = _SCRIPT_TAG_RE.sub("", text)
    text = _STYLE_TAG_RE.sub("", text)

    # Remove data URIs
    text = _DATA_URI_RE.sub("[DATA_URI_REMOVED]", text)

    # Flag / remove prompt injections
    for pattern in _PROMPT_INJECTION_PATTERNS:
        text = pattern.sub("[PROMPT_INJECTION_REMOVED]", text)

    # Strip remaining HTML tags
    text = _HTML_TAG_RE.sub(" ", text)

    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


def _extract_headings_from_tree(tree: dict[str, Any]) -> list[str]:
    """Walk an accessibility tree and collect heading text."""
    headings: list[str] = []

    def _walk(node: dict[str, Any]) -> None:
        role = node.get("role", "")
        if role == "heading":
            name = node.get("name", "")
            if name:
                headings.append(_sanitize_text(name))
        for child in node.get("children", []):
            _walk(child)

    _walk(tree)
    return headings


def _extract_links_from_tree(tree: dict[str, Any]) -> list[dict[str, str]]:
    """Walk an accessibility tree and collect link targets."""
    links: list[dict[str, str]] = []

    def _walk(node: dict[str, Any]) -> None:
        role = node.get("role", "")
        if role == "link":
            name = _sanitize_text(node.get("name", ""))
            href = node.get("value", node.get("url", ""))
            if name or href:
                links.append({"text": name, "href": str(href)})
        for child in node.get("children", []):
            _walk(child)

    _walk(tree)
    return links


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def critique_and_extract(
    *,
    raw_html: str = "",
    accessible_tree: dict[str, Any] | None = None,
    url: str = "",
    title: str = "",
) -> PageDataExtract:
    """Sanitize raw page data and extract structured information.

    This function is intentionally synchronous and I/O-free — the
    Critique agent must never perform network or browser operations.

    Parameters
    ----------
    raw_html:
        The cleaned HTML from ``dom_sanitizer`` (post-hidden-element removal).
    accessible_tree:
        The Playwright Accessibility Tree snapshot.
    url / title:
        Page metadata.

    Returns
    -------
    PageDataExtract
        Schema-validated, sanitized page data.
    """
    logger.info("Critic processing page data for %s", url)

    sanitized_html = _sanitize_text(raw_html) if raw_html else ""

    tree = accessible_tree or {}
    headings = _extract_headings_from_tree(tree)
    links = _extract_links_from_tree(tree)

    extract = PageDataExtract(
        title=_sanitize_text(title),
        url=url,
        main_text=sanitized_html[:5000],  # cap to avoid LLM token waste
        headings=headings,
        links=links[:50],  # cap
    )

    logger.info(
        "Critic extracted: %d headings, %d links, %d chars of text",
        len(extract.headings),
        len(extract.links),
        len(extract.main_text),
    )
    return extract
