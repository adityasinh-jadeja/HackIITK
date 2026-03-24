"""Sandboxed Playwright Chromium launcher with ephemeral browser contexts.

Every browsing task receives a fresh, non-persistent context so that cookies,
storage, and any other state are discarded on close — preventing cross-task
state leakage.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

from config import settings

logger = logging.getLogger(__name__)


class BrowserSandbox:
    """Async context-manager that owns a sandboxed Chromium instance.

    Usage::

        async with BrowserSandbox() as sandbox:
            async with sandbox.new_task_context() as ctx:
                page = ctx.page
                await page.goto("https://example.com")
    """

    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "BrowserSandbox":
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=settings.browser_args,
        )
        logger.info(
            "Chromium launched (pid=%s) with args: %s",
            self._browser.contexts,
            settings.browser_args,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        if self._browser:
            await self._browser.close()
            logger.info("Chromium browser closed.")
        if self._playwright:
            await self._playwright.stop()
            logger.info("Playwright stopped.")

    # ------------------------------------------------------------------
    # Per-task ephemeral context
    # ------------------------------------------------------------------

    @asynccontextmanager
    async def new_task_context(self) -> AsyncGenerator["TaskContext", None]:
        """Create a completely new, non-persistent browser context.

        The context (and all its pages) is destroyed when the block exits,
        ensuring zero state leakage between tasks.
        """
        if self._browser is None:
            raise RuntimeError("BrowserSandbox is not initialised. Use `async with`.")

        context: BrowserContext = await self._browser.new_context(
            java_script_enabled=True,
            bypass_csp=False,          # honour Content-Security-Policy
            ignore_https_errors=False, # enforce TLS
            locale="en-US",
            timezone_id="UTC",
            # Deny all permissions by default
            permissions=[],
        )
        logger.info("New ephemeral browser context created.")

        page: Page = await context.new_page()

        try:
            yield TaskContext(context=context, page=page)
        finally:
            await context.close()
            logger.info("Ephemeral browser context destroyed.")


class TaskContext:
    """Thin wrapper around one ephemeral BrowserContext + its Page."""

    __slots__ = ("context", "page")

    def __init__(self, *, context: BrowserContext, page: Page) -> None:
        self.context = context
        self.page = page

    async def navigate(self, url: str) -> None:
        """Navigate the page to *url*, waiting for DOM content to load."""
        await self.page.goto(url, wait_until="domcontentloaded")
        logger.info("Navigated to %s", url)
