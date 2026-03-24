"""Integration tests for the OPA action-validation policy.

These tests require a running OPA server.  To start one:

    docker run -d -p 8181:8181 openpolicyagent/opa:latest run --server

Then load the policy:

    curl -X PUT http://localhost:8181/v1/policies/browser \
         --data-binary @opa_policies/action_validation.rego

Run these tests with:

    pytest tests/test_opa_integration.py -v
"""

from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio

# Skip entire module if OPA is unreachable
OPA_URL = os.environ.get("SAB_OPA_URL", "http://localhost:8181")

pytestmark = pytest.mark.asyncio


async def _opa_available() -> bool:
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{OPA_URL}/health", timeout=2)
            return resp.status_code == 200
    except Exception:
        return False


@pytest_asyncio.fixture(autouse=True)
async def skip_if_no_opa():
    if not await _opa_available():
        pytest.skip("OPA server not available")


async def _evaluate(input_data: dict) -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{OPA_URL}/v1/data/browser/action",
            json={"input": input_data},
        )
        resp.raise_for_status()
        return resp.json().get("result", {})


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestOPAPolicies:
    """Test the Rego policies via OPA REST API."""

    async def test_same_origin_post_allowed(self):
        """POST to same origin should be allowed."""
        result = await _evaluate({
            "action_intent": {
                "action": "submit",
                "selector": "#submit-btn",
                "current_page_origin": "https://example.com",
                "is_hidden_element": False,
            },
            "network_request": {
                "method": "POST",
                "url": "https://example.com/api/submit",
                "resource_type": "fetch",
                "body_size": 100,
            },
            "allowed_domains": ["example.com"],
            "max_outbound_body_bytes": 4096,
        })
        assert result.get("allow") is True

    async def test_cross_origin_post_denied(self):
        """POST to a different origin should be denied."""
        result = await _evaluate({
            "action_intent": {
                "action": "submit",
                "selector": "#submit-btn",
                "current_page_origin": "https://example.com",
                "is_hidden_element": False,
            },
            "network_request": {
                "method": "POST",
                "url": "https://evil.com/steal",
                "resource_type": "fetch",
                "body_size": 100,
            },
            "allowed_domains": ["example.com"],
            "max_outbound_body_bytes": 4096,
        })
        assert result.get("allow") is False
        assert "cross-origin POST blocked" in result.get("reasons", [])

    async def test_navigation_to_disallowed_domain(self):
        """Document navigations to non-allowlisted domains are denied."""
        result = await _evaluate({
            "action_intent": None,
            "network_request": {
                "method": "GET",
                "url": "https://malicious-site.com/page",
                "resource_type": "document",
                "body_size": 0,
            },
            "allowed_domains": ["example.com", "safe.org"],
            "max_outbound_body_bytes": 4096,
        })
        assert result.get("allow") is False
        assert "navigation to disallowed domain" in result.get("reasons", [])

    async def test_hidden_element_interaction_denied(self):
        """Clicking on a hidden element should be denied."""
        result = await _evaluate({
            "action_intent": {
                "action": "click",
                "selector": "#hidden-btn",
                "current_page_origin": "https://example.com",
                "is_hidden_element": True,
            },
            "network_request": None,
            "allowed_domains": ["example.com"],
            "max_outbound_body_bytes": 4096,
        })
        assert result.get("allow") is False
        assert "interaction with hidden element blocked" in result.get("reasons", [])

    async def test_large_body_to_unknown_domain_denied(self):
        """Large outbound body to a non-allowlisted domain is denied."""
        result = await _evaluate({
            "action_intent": None,
            "network_request": {
                "method": "POST",
                "url": "https://unknown-domain.com/exfil",
                "resource_type": "fetch",
                "body_size": 10000,
            },
            "allowed_domains": ["example.com"],
            "max_outbound_body_bytes": 4096,
        })
        assert result.get("allow") is False
        assert "outbound body exceeds size limit to unknown domain" in result.get("reasons", [])

    async def test_allowed_domain_navigation(self):
        """Navigation to an allowlisted domain should be allowed."""
        result = await _evaluate({
            "action_intent": {
                "action": "navigate",
                "selector": "",
                "current_page_origin": "",
                "is_hidden_element": False,
            },
            "network_request": {
                "method": "GET",
                "url": "https://example.com/page",
                "resource_type": "document",
                "body_size": 0,
            },
            "allowed_domains": ["example.com"],
            "max_outbound_body_bytes": 4096,
        })
        assert result.get("allow") is True
