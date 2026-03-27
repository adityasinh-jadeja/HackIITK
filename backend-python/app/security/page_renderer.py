"""
Renders a URL using Playwright and extracts the full DOM after JS execution.
Uses sync_playwright in a thread pool to avoid Windows event loop subprocess issues.
"""
from playwright.sync_api import sync_playwright
from app.config import settings
import asyncio


def _render_sync(url: str) -> dict:
    """Synchronous rendering function, executed in a thread pool."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            java_script_enabled=True,
            ignore_https_errors=True,
            permissions=[],
        )

        page = context.new_page()
        network_log = []
        console_log = []

        page.on("request", lambda req: network_log.append({
            "url": req.url,
            "method": req.method,
            "resource_type": req.resource_type,
        }))

        page.on("console", lambda msg: console_log.append({
            "type": msg.type,
            "text": msg.text,
        }))

        try:
            is_local = url.startswith("file://")
            wait_cond = "load" if is_local else "networkidle"
            timeout_ms = 10000 if is_local else 30000

            response = page.goto(url, wait_until=wait_cond, timeout=timeout_ms)
            page.wait_for_timeout(1000)

            html = page.content()
            title = page.title()
            final_url = page.url

            return {
                "html": html,
                "title": title,
                "final_url": final_url,
                "status_code": response.status if response and not is_local else 200,
                "network_log": network_log,
                "console_log": console_log,
            }
        finally:
            context.close()
            browser.close()


async def render_and_extract(url: str) -> dict:
    """
    Navigate to a URL, wait for JS execution, extract data.
    Runs sync Playwright in a thread pool to avoid Windows asyncio subprocess issues.
    """
    return await asyncio.to_thread(_render_sync, url)
