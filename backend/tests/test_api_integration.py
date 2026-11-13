"""End-to-End HTTP Integration Test Suite via httpx ASGITransport."""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.config import settings
from app.core.security import rate_tracker


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Resets the in-memory rate tracker before and after each integration test."""
    rate_tracker.reset()
    yield
    rate_tracker.reset()


@pytest.mark.asyncio
async def test_health_http_pipeline():
    """Asserts that GET /api/v1/health passes through the full ASGI pipeline."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert data["database"]["status"] == "connected"
        assert data["database"]["error"] is None

        # Verify Security Headers injected by middleware
        headers = response.headers
        assert "content-security-policy" in headers
        assert "default-src 'self'" in headers["content-security-policy"]
        assert headers.get("x-content-type-options") == "nosniff"
        assert headers.get("x-frame-options") == "DENY"
        assert headers.get("referrer-policy") == "no-referrer"
        assert "no-store" in headers.get("cache-control", "")


@pytest.mark.asyncio
async def test_host_header_validation_pipeline():
    """Asserts that requests with an unauthorized Host header receive HTTP 400 Bad Request."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        # Send request with spoofed/untrusted Host header
        response = await client.get(
            "/api/v1/health",
            headers={"Host": "attacker-dns-rebind.com"}
        )
        assert response.status_code == 400
        assert "Invalid host header" in response.text


@pytest.mark.asyncio
async def test_origin_restrictions_pipeline():
    """Asserts that state-changing requests with forbidden Origin receive HTTP 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        response = await client.post(
            "/api/v1/health",
            headers={
                "Origin": "https://malicious-phishing-site.com",
                settings.CSRF_CLIENT_HEADER: settings.CSRF_EXPECTED_VALUE,
            }
        )
        assert response.status_code == 403
        data = response.json()
        assert "Cross-Origin Request Forbidden" in data["detail"]


@pytest.mark.asyncio
async def test_custom_client_header_enforcement_pipeline():
    """Asserts that state-changing requests without custom client header receive HTTP 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        # POST without X-PhishGuard-Client header
        response = await client.post(
            "/api/v1/health",
            headers={"Origin": "http://127.0.0.1:5173"}
        )
        assert response.status_code == 403
        data = response.json()
        assert "Missing Required Client Header" in data["detail"]


@pytest.mark.asyncio
async def test_rate_limiting_pipeline():
    """Asserts that rapid requests exceeding the configured threshold receive HTTP 429."""
    original_limit = rate_tracker.limit
    rate_tracker.limit = 5
    rate_tracker.reset()

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
            # 5 allowed requests
            for _ in range(5):
                res = await client.get("/api/v1/health")
                assert res.status_code == 200

            # 6th request must trigger rate limit
            res_limit = await client.get("/api/v1/health")
            assert res_limit.status_code == 429
            data = res_limit.json()
            assert data["error"] == "Rate Limit Exceeded"
    finally:
        rate_tracker.limit = original_limit
        rate_tracker.reset()


@pytest.mark.asyncio
async def test_error_response_pipeline():
    """Asserts that requests to non-existent routes return structured 404 without stack traces."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8000") as client:
        response = await client.get("/api/v1/nonexistent-route")
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "Not Found" in data["detail"]
