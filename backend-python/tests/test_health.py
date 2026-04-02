"""
Basic health check and integration tests for Phase 1.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.mark.anyio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.2.0"

@pytest.mark.anyio
async def test_dashboard_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "overallRisk" in data
    assert "metrics" in data
    assert "threats" in data
    assert "currentGoal" in data
    assert "agentStatus" in data

@pytest.mark.anyio
async def test_agent_start():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/agent/start", json={"goal": "Test goal"})
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Agent started"
    assert data["goal"] == "Test goal"

@pytest.mark.anyio
async def test_agent_stop():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/agent/stop")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Agent stopped"
