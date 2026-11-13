"""Test Suite for PhishGuard Health API Endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_health_endpoint_healthy(test_db_session):
    """Asserts that GET /api/v1/health returns 200 with status healthy and connected database."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "app_name" in data
        assert "version" in data
        assert "timestamp" in data
        assert data["database"]["status"] == "connected"
        assert data["database"]["error"] is None
