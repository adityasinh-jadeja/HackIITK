"""Unit tests for defense.dom_sanitizer."""

from __future__ import annotations

import pytest
import pytest_asyncio
from playwright.async_api import async_playwright, Page


@pytest_asyncio.fixture
async def page():
    """Provide a fresh Playwright page for each test."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        pg = await context.new_page()
        yield pg
        await context.close()
        await browser.close()


# ------------------------------------------------------------------
# Crafted HTML payloads
# ------------------------------------------------------------------

HTML_WITH_HIDDEN = """
<!DOCTYPE html>
<html>
<body>
  <div id="visible">Hello World</div>
  <div id="hidden-display" style="display:none">SECRET DISPLAY NONE</div>
  <div id="hidden-visibility" style="visibility:hidden">SECRET VISIBILITY</div>
  <div id="hidden-opacity" style="opacity:0">SECRET OPACITY ZERO</div>
  <script>alert('xss')</script>
  <style>.evil { color: red; }</style>
  <iframe src="https://evil.com"></iframe>
</body>
</html>
"""

HTML_CLEAN = """
<!DOCTYPE html>
<html>
<body>
  <h1>Clean Page</h1>
  <p>This page has no hidden elements or dangerous tags.</p>
  <a href="https://example.com">Link</a>
</body>
</html>
"""


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_removes_hidden_elements(page: Page):
    """Hidden elements (display:none, visibility:hidden, opacity:0) are removed."""
    from defense.dom_sanitizer import sanitize_dom

    await page.set_content(HTML_WITH_HIDDEN)
    result = await sanitize_dom(page)

    # The cleaned HTML should NOT contain the hidden content
    assert "SECRET DISPLAY NONE" not in result.cleaned_html
    assert "SECRET VISIBILITY" not in result.cleaned_html
    assert "SECRET OPACITY ZERO" not in result.cleaned_html

    # The visible content must survive
    assert "Hello World" in result.cleaned_html

    # Audit trail should record the removals
    hidden_reasons = {r.reason for r in result.removed_elements}
    assert "display:none" in hidden_reasons
    assert "visibility:hidden" in hidden_reasons
    assert "opacity:0" in hidden_reasons


@pytest.mark.asyncio
async def test_strips_dangerous_tags(page: Page):
    """<script>, <style>, <iframe> tags are removed."""
    from defense.dom_sanitizer import sanitize_dom

    await page.set_content(HTML_WITH_HIDDEN)
    result = await sanitize_dom(page)

    assert "<script" not in result.cleaned_html.lower()
    assert "<style" not in result.cleaned_html.lower()
    assert "<iframe" not in result.cleaned_html.lower()

    dangerous_tags = {
        r.tag for r in result.removed_elements if r.reason == "dangerous-tag"
    }
    assert "script" in dangerous_tags
    assert "style" in dangerous_tags
    assert "iframe" in dangerous_tags


@pytest.mark.asyncio
async def test_accessibility_tree_extraction(page: Page):
    """Accessibility tree is returned with meaningful structure."""
    from defense.dom_sanitizer import sanitize_dom

    await page.set_content(HTML_CLEAN)
    result = await sanitize_dom(page)

    assert result.accessible_tree  # non-empty
    assert isinstance(result.accessible_tree, dict)


@pytest.mark.asyncio
async def test_clean_page_no_removals(page: Page):
    """A clean page produces zero removed elements."""
    from defense.dom_sanitizer import sanitize_dom

    await page.set_content(HTML_CLEAN)
    result = await sanitize_dom(page)

    # No hidden elements or dangerous tags
    assert len(result.removed_elements) == 0
    assert "Clean Page" in result.cleaned_html


@pytest.mark.asyncio
async def test_original_url_captured(page: Page):
    """SanitizedDOM records the page's URL."""
    from defense.dom_sanitizer import sanitize_dom

    await page.set_content(HTML_CLEAN)
    result = await sanitize_dom(page)
    assert result.original_url  # should be about:blank or similar
