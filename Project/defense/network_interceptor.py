"""Playwright ``page.route`` interceptor for outbound network requests.

Intercepts every network request from the sandboxed page, converts it into
a ``NetworkRequest`` model, and evaluates it against OPA policies. Denied
requests are aborted; allowed requests are forwarded transparently.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from playwright.async_api import Page, Route, Request as PlaywrightRequest

from defense.intent_schema import NetworkRequest
from defense import opa_client

logger = logging.getLogger(__name__)


async def install(page: Page) -> None:
    """Register the network interceptor on *page*.

    Must be called **before** any navigation so that all requests
    (including the initial document request) pass through OPA.
    """

    async def _handle_route(route: Route) -> None:
        request: PlaywrightRequest = route.request

        # Build the NetworkRequest model
        body: str | None = None
        body_size = 0
        if request.post_data:
            body = request.post_data
            body_size = len(request.post_data.encode("utf-8", errors="replace"))

        net_req = NetworkRequest(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            body=body,
            body_size=body_size,
            resource_type=request.resource_type,
        )

        logger.debug(
            "Intercepted %s %s (%s, %d bytes)",
            net_req.method,
            net_req.url,
            net_req.resource_type,
            net_req.body_size,
        )

        # Evaluate against OPA
        result = await opa_client.evaluate_action(network_request=net_req)

        if result.allow:
            logger.info("OPA ALLOW  %s %s", net_req.method, net_req.url)
            await route.continue_()
        else:
            logger.warning(
                "OPA DENY   %s %s — reasons: %s",
                net_req.method,
                net_req.url,
                result.reasons,
            )
            await route.abort("blockedbyclient")

    # Intercept ALL outbound requests
    await page.route("**/*", _handle_route)
    logger.info("Network interceptor installed on page.")


async def uninstall(page: Page) -> None:
    """Remove all route handlers from *page*."""
    await page.unroute("**/*")
    logger.info("Network interceptor removed from page.")
