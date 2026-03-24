"""HTTP client for the local Open Policy Agent (OPA) server.

Sends ``OPAInput`` payloads to the OPA REST API and returns a structured
``OPAResult`` indicating whether the action is allowed or denied.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from config import settings
from defense.intent_schema import (
    ActionIntent,
    NetworkRequest,
    OPAInput,
    OPAResult,
)

logger = logging.getLogger(__name__)

# Re-usable async client (created once, shared across requests)
_client: httpx.AsyncClient | None = None


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=5.0)
    return _client


async def evaluate_action(
    *,
    intent: ActionIntent | None = None,
    network_request: NetworkRequest | None = None,
) -> OPAResult:
    """Evaluate an action intent and/or network request against OPA policies.

    Parameters
    ----------
    intent:
        The structured action the LLM wants to perform.
    network_request:
        An intercepted outbound network request.

    Returns
    -------
    OPAResult
        ``allow=True`` if OPA permits the action, ``allow=False`` otherwise.
    """
    opa_input = OPAInput(
        action_intent=intent,
        network_request=network_request,
        allowed_domains=settings.allowed_domains,
        max_outbound_body_bytes=settings.max_outbound_body_bytes,
    )

    url = f"{settings.opa_url}{settings.opa_policy_path}"
    payload: dict[str, Any] = {"input": opa_input.model_dump(mode="json")}

    logger.debug("OPA request → %s  payload=%s", url, payload)

    try:
        client = await _get_client()
        resp = await client.post(url, json=payload)
        resp.raise_for_status()

        data = resp.json()
        result_data = data.get("result", {})

        allow = bool(result_data.get("allow", False))
        reasons = list(result_data.get("reasons", []))

        result = OPAResult(allow=allow, reasons=reasons)
        logger.info("OPA decision: allow=%s  reasons=%s", allow, reasons)
        return result

    except httpx.HTTPStatusError as exc:
        logger.error("OPA HTTP error: %s", exc)
        return OPAResult(allow=False, reasons=[f"OPA HTTP error: {exc.response.status_code}"])

    except httpx.ConnectError:
        logger.error("Cannot reach OPA at %s — denying by default.", url)
        return OPAResult(allow=False, reasons=["OPA server unreachable — fail-closed"])

    except Exception as exc:  # noqa: BLE001
        logger.error("OPA evaluation failed: %s", exc)
        return OPAResult(allow=False, reasons=[f"OPA evaluation error: {exc}"])


async def close() -> None:
    """Shut down the shared httpx client."""
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None
