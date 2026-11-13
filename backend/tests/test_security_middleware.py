"""Test Suite for PhishGuard Security Controls & Middleware Logic."""

from fastapi.responses import Response
from fastapi import status
from app.core.config import settings
from app.core.security import (
    validate_upload_size_header,
    validate_origin_and_csrf,
    SlidingWindowTracker,
    apply_security_headers,
)


def test_security_response_headers():
    """Asserts that apply_security_headers injects all required security headers."""
    resp = Response(content="OK", status_code=200)
    hardened = apply_security_headers(resp)

    headers = hardened.headers
    assert "default-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert "no-store" in headers["cache-control"]


def test_upload_size_limit_validation():
    """Asserts that oversized Content-Length is rejected while valid size passes."""
    oversized = str(settings.MAX_UPLOAD_SIZE_BYTES + 1024)
    valid, msg = validate_upload_size_header(oversized)
    assert valid is False
    assert "exceeds maximum limit" in msg

    valid_len = str(1024 * 1024)  # 1 MB
    valid, msg = validate_upload_size_header(valid_len)
    assert valid is True
    assert msg is None

    # Empty Content-Length header should pass
    valid, msg = validate_upload_size_header(None)
    assert valid is True


def test_csrf_custom_client_header_required_on_post():
    """Asserts that state-changing requests without custom client header receive HTTP 403."""
    # POST without custom client header
    valid, code, msg = validate_origin_and_csrf(
        method="POST",
        origin=None,
        referer=None,
        client_header_val=None,
    )
    assert valid is False
    assert code == status.HTTP_403_FORBIDDEN
    assert "Missing Required Client Header" in msg


def test_csrf_custom_client_header_accepted():
    """Asserts that state-changing requests with valid client header are approved."""
    valid, code, msg = validate_origin_and_csrf(
        method="POST",
        origin="http://127.0.0.1:5173",
        referer="http://127.0.0.1:5173/email-analyzer",
        client_header_val=settings.CSRF_EXPECTED_VALUE,
    )
    assert valid is True
    assert code == 200
    assert msg is None


def test_forbidden_origin_rejected():
    """Asserts that state-changing requests from untrusted origins receive HTTP 403."""
    valid, code, msg = validate_origin_and_csrf(
        method="POST",
        origin="https://malicious-phishing-site.com",
        referer=None,
        client_header_val=settings.CSRF_EXPECTED_VALUE,
    )
    assert valid is False
    assert code == status.HTTP_403_FORBIDDEN
    assert "Unauthorized Origin" in msg


def test_rate_limiter_exceeded():
    """Asserts that requests exceeding rate limit threshold are blocked."""
    tracker = SlidingWindowTracker(limit_per_minute=3)
    client_ip = "192.168.1.100"

    assert tracker.is_allowed(client_ip) is True
    assert tracker.is_allowed(client_ip) is True
    assert tracker.is_allowed(client_ip) is True
    # 4th request must fail
    assert tracker.is_allowed(client_ip) is False
