"""Security Middleware and Protection Controls for PhishGuard.

Provides:
- Security HTTP response headers (CSP, HSTS, NoSniff, FrameOptions)
- Streaming request body size limit enforcement (10 MB limit) via pure ASGI receive wrapper
- Origin and Referer validation on state-changing requests
- Custom client header verification (Local anti-drive-by CSRF mitigation)
- In-memory sliding window rate limiting
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp, Scope, Receive, Send, Message

from app.core.config import settings
from app.core.logging import logger

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class PayloadTooLargeException(Exception):
    """Raised when actual streamed bytes exceed the maximum permitted upload limit."""

    def __init__(self, received_bytes: int, max_bytes: int):
        self.received_bytes = received_bytes
        self.max_bytes = max_bytes
        super().__init__(f"Received {received_bytes} bytes which exceeds limit of {max_bytes} bytes")


def validate_upload_size_header(
    content_length: Optional[str], max_bytes: Optional[int] = None
) -> Tuple[bool, Optional[str]]:
    """Validates Content-Length header against maximum permitted threshold."""
    if not content_length:
        return True, None
    limit = max_bytes or settings.MAX_UPLOAD_SIZE_BYTES
    try:
        length = int(content_length)
        if length > limit:
            return (
                False,
                f"Request size ({length} bytes) exceeds maximum limit ({limit} bytes).",
            )
    except ValueError:
        pass
    return True, None


def validate_origin_and_csrf(
    method: str,
    origin: Optional[str] = None,
    referer: Optional[str] = None,
    client_header_val: Optional[str] = None,
) -> Tuple[bool, int, Optional[str]]:
    """Validates Origin, Referer, and Custom Client Header on state-changing requests.

    Returns:
        (is_valid, http_status_code, error_message)
    """
    if method in SAFE_METHODS:
        return True, 200, None

    # 1. Validate Origin header if present
    if origin and origin not in settings.ALLOWED_ORIGINS:
        return False, status.HTTP_403_FORBIDDEN, "Cross-Origin Request Forbidden: Unauthorized Origin."

    # 2. Validate Referer header if present
    if referer:
        matches = any(referer.startswith(allowed) for allowed in settings.ALLOWED_ORIGINS)
        if not matches:
            return False, status.HTTP_403_FORBIDDEN, "Forbidden Referer: Unauthorized Referer."

    # 3. Validate Custom Client Header
    if client_header_val != settings.CSRF_EXPECTED_VALUE:
        return (
            False,
            status.HTTP_403_FORBIDDEN,
            f"Missing Required Client Header: Must provide '{settings.CSRF_CLIENT_HEADER}: {settings.CSRF_EXPECTED_VALUE}'.",
        )

    return True, 200, None


class SlidingWindowTracker:
    """In-memory sliding window request timestamp tracker per client IP."""

    def __init__(self, limit_per_minute: int = 60):
        self.limit = limit_per_minute
        self.window = 60.0
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str, current_time: Optional[float] = None) -> bool:
        now = current_time or time.time()
        window_start = now - self.window
        self.requests[client_ip] = [ts for ts in self.requests[client_ip] if ts > window_start]
        if len(self.requests[client_ip]) >= self.limit:
            return False
        self.requests[client_ip].append(now)
        return True

    def reset(self):
        """Reset all tracked IP request histories (used in tests)."""
        self.requests.clear()


rate_tracker = SlidingWindowTracker(limit_per_minute=settings.RATE_LIMIT_PER_MINUTE)


def apply_security_headers(response: Response) -> Response:
    """Injects defensive HTTP headers into an existing Response."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        return apply_security_headers(response)


class StreamingUploadLimitMiddleware:
    """Pure ASGI Middleware enforcing strict upload size limit on actual streamed bytes.
    
    Prevents memory exhaustion attacks by counting arriving chunks in real-time,
    handling chunked transfers, missing Content-Length headers, and spoofed sizes.
    """

    def __init__(self, app: ASGIApp, max_bytes: Optional[int] = None):
        self.app = app
        self.max_bytes = max_bytes or settings.MAX_UPLOAD_SIZE_BYTES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Header-level fast check
        for raw_name, raw_value in scope.get("headers", []):
            if raw_name.lower() == b"content-length":
                valid, msg = validate_upload_size_header(
                    raw_value.decode("latin1", errors="ignore"),
                    max_bytes=self.max_bytes,
                )
                if not valid:
                    response = JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"error": "Payload Too Large", "detail": msg},
                    )
                    await response(scope, receive, send)
                    return

        # 2. Streaming byte counter wrapping receive()
        received_bytes = 0

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                received_bytes += len(chunk)
                if received_bytes > self.max_bytes:
                    raise PayloadTooLargeException(received_bytes, self.max_bytes)
            return message

        try:
            await self.app(scope, limited_receive, send)
        except PayloadTooLargeException as exc:
            logger.warning(
                f"Streaming upload blocked: received {exc.received_bytes} bytes exceeds {exc.max_bytes} limit"
            )
            response = JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "error": "Payload Too Large",
                    "detail": f"Streamed upload exceeded maximum allowed limit of {self.max_bytes} bytes.",
                },
            )
            await response(scope, receive, send)


class OriginAndCSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        valid, code, msg = validate_origin_and_csrf(
            method=request.method,
            origin=request.headers.get("origin"),
            referer=request.headers.get("referer"),
            client_header_val=request.headers.get(settings.CSRF_CLIENT_HEADER.lower()),
        )
        if not valid:
            logger.warning(f"CSRF/Origin check failed: {msg}")
            return JSONResponse(
                status_code=code,
                content={"error": "Forbidden Request", "detail": msg},
            )
        return await call_next(request)


class SlidingWindowRateLimiter(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, limit_per_minute: int = 60):
        super().__init__(app)
        self.tracker = rate_tracker

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        if not self.tracker.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for client {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate Limit Exceeded",
                    "detail": "Request threshold exceeded. Please retry after waiting.",
                },
            )
        return await call_next(request)
