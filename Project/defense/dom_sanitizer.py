"""Pre-execution DOM sanitization pipeline.

Runs *before* any LLM sees page data.  The pipeline:
1. Removes hidden / invisible elements from the live DOM.
2. Strips dangerous tags (<script>, <style>, <iframe>, etc.).
3. Extracts the Accessibility Tree for a semantic, safe representation.

Returns a ``SanitizedDOM`` object that the Planner / Critique agents consume.
"""

from __future__ import annotations

import logging
from dataclasses import field
from typing import Any

from pydantic import BaseModel, Field
from playwright.async_api import Page

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------

class RemovedElement(BaseModel):
    """Audit record for a single removed DOM element."""

    tag: str
    reason: str
    outer_html_preview: str = Field(
        default="",
        description="First 200 chars of outerHTML for XAI explanations",
    )


class SanitizedDOM(BaseModel):
    """Result of the full sanitization pipeline."""

    accessible_tree: dict[str, Any] = Field(
        default_factory=dict,
        description="Playwright Accessibility Tree snapshot",
    )
    cleaned_html: str = Field(
        default="",
        description="DOM innerHTML after sanitization (scripts/hidden nodes removed)",
    )
    removed_elements: list[RemovedElement] = Field(
        default_factory=list,
        description="Audit trail of every element that was removed",
    )
    original_url: str = ""


# ------------------------------------------------------------------
# JavaScript executed inside the page
# ------------------------------------------------------------------

_JS_REMOVE_HIDDEN = """
() => {
    const removed = [];
    const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_ELEMENT,
        null,
    );

    const toRemove = [];
    while (walker.nextNode()) {
        const el = walker.currentNode;
        const style = window.getComputedStyle(el);
        let reason = null;

        if (style.display === 'none') {
            reason = 'display:none';
        } else if (style.visibility === 'hidden') {
            reason = 'visibility:hidden';
        } else if (parseFloat(style.opacity) === 0) {
            reason = 'opacity:0';
        } else {
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) {
                reason = 'zero-size bounding rect';
            }
        }

        if (reason) {
            toRemove.push({
                el,
                tag: el.tagName.toLowerCase(),
                reason,
                preview: el.outerHTML.substring(0, 200),
            });
        }
    }

    // Remove in reverse-DOM-order so indices stay stable
    for (let i = toRemove.length - 1; i >= 0; i--) {
        const entry = toRemove[i];
        removed.push({
            tag: entry.tag,
            reason: entry.reason,
            outer_html_preview: entry.preview,
        });
        entry.el.remove();
    }

    return removed;
}
"""

_JS_STRIP_DANGEROUS_TAGS = """
() => {
    const tags = ['script', 'style', 'noscript', 'iframe', 'object', 'embed', 'applet'];
    const removed = [];
    for (const tag of tags) {
        for (const el of [...document.querySelectorAll(tag)]) {
            removed.push({
                tag: el.tagName.toLowerCase(),
                reason: 'dangerous-tag',
                outer_html_preview: el.outerHTML.substring(0, 200),
            });
            el.remove();
        }
    }
    return removed;
}
"""

_JS_GET_BODY_HTML = "() => document.body ? document.body.innerHTML : ''"


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

async def sanitize_dom(page: Page) -> SanitizedDOM:
    """Run the full sanitization pipeline on the current page.

    Parameters
    ----------
    page:
        A Playwright ``Page`` that has already navigated to the target URL.

    Returns
    -------
    SanitizedDOM
        Contains the cleaned HTML, accessibility tree, and audit trail.
    """
    url = page.url
    logger.info("Starting DOM sanitization for %s", url)

    # Step 1 — Remove hidden / invisible elements
    hidden_removed: list[dict] = await page.evaluate(_JS_REMOVE_HIDDEN)
    logger.info("Removed %d hidden elements.", len(hidden_removed))

    # Step 2 — Strip dangerous tags
    dangerous_removed: list[dict] = await page.evaluate(_JS_STRIP_DANGEROUS_TAGS)
    logger.info("Stripped %d dangerous tags.", len(dangerous_removed))

    # Step 3 — Extract the Accessibility Tree
    accessible_tree: dict[str, Any] | None = await page.accessibility.snapshot()  # type: ignore[attr-defined]
    if accessible_tree is None:
        accessible_tree = {}
        logger.warning("Accessibility snapshot returned None for %s", url)

    # Step 4 — Grab the cleaned HTML
    cleaned_html: str = await page.evaluate(_JS_GET_BODY_HTML)

    # Build audit trail
    all_removed = [
        RemovedElement(**entry)
        for entry in (hidden_removed + dangerous_removed)
    ]

    result = SanitizedDOM(
        accessible_tree=accessible_tree,
        cleaned_html=cleaned_html,
        removed_elements=all_removed,
        original_url=url,
    )
    logger.info(
        "DOM sanitization complete — %d elements removed, a11y tree has %d keys.",
        len(all_removed),
        len(accessible_tree),
    )
    return result
