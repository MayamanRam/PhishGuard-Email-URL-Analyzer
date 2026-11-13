"""Test Suite verifying Real-Time Streaming Upload Size Enforcement."""

import pytest
from starlette.requests import Request
from starlette.responses import Response
from fastapi import status

from app.core.security import StreamingUploadLimitMiddleware


@pytest.mark.asyncio
async def test_streaming_upload_below_limit():
    """Asserts that streams below the byte limit are received completely."""
    app_called = False

    async def dummy_app(scope, receive, send):
        nonlocal app_called
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body", False):
                break
        app_called = True
        response = Response(content="SUCCESS", status_code=200)
        await response(scope, receive, send)

    middleware = StreamingUploadLimitMiddleware(dummy_app, max_bytes=1000)

    chunks = [b"A" * 300, b"B" * 300, b"C" * 300]  # Total 900 bytes < 1000 limit
    chunk_idx = 0

    async def mock_receive():
        nonlocal chunk_idx
        if chunk_idx < len(chunks):
            chunk = chunks[chunk_idx]
            chunk_idx += 1
            return {"type": "http.request", "body": chunk, "more_body": chunk_idx < len(chunks)}
        return {"type": "http.request", "body": b"", "more_body": False}

    sent_messages = []

    async def mock_send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/emails/analyze",
        "headers": [(b"content-type", b"application/octet-stream")],
    }

    await middleware(scope, mock_receive, mock_send)
    assert app_called is True
    # Verify 200 response
    start_msg = next(m for m in sent_messages if m["type"] == "http.response.start")
    assert start_msg["status"] == 200


@pytest.mark.asyncio
async def test_streaming_upload_exceeds_limit_without_content_length():
    """Asserts that chunked/streamed uploads exceeding limit are cut off with HTTP 413.
    
    Verifies that the downstream application never buffers the oversized payload.
    """
    app_called = False

    async def dummy_app(scope, receive, send):
        nonlocal app_called
        app_called = True
        while True:
            msg = await receive()
            if not msg.get("more_body", False):
                break

    middleware = StreamingUploadLimitMiddleware(dummy_app, max_bytes=1000)

    # 4 chunks of 400 bytes = 1600 bytes > 1000 limit
    chunks = [b"A" * 400, b"B" * 400, b"C" * 400, b"D" * 400]
    chunk_idx = 0

    async def mock_receive():
        nonlocal chunk_idx
        if chunk_idx < len(chunks):
            chunk = chunks[chunk_idx]
            chunk_idx += 1
            return {"type": "http.request", "body": chunk, "more_body": chunk_idx < len(chunks)}
        return {"type": "http.request", "body": b"", "more_body": False}

    sent_messages = []

    async def mock_send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/emails/analyze",
        "headers": [
            (b"transfer-encoding", b"chunked"),  # Missing Content-Length
        ],
    }

    await middleware(scope, mock_receive, mock_send)
    # The downstream app should have aborted on third chunk
    start_msg = next(m for m in sent_messages if m["type"] == "http.response.start")
    assert start_msg["status"] == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


@pytest.mark.asyncio
async def test_header_content_length_exceeds_limit_immediate_rejection():
    """Asserts that oversized Content-Length is rejected before reading any stream bytes."""
    app_called = False

    async def dummy_app(scope, receive, send):
        nonlocal app_called
        app_called = True

    middleware = StreamingUploadLimitMiddleware(dummy_app, max_bytes=5000)
    sent_messages = []

    async def mock_send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/emails/analyze",
        "headers": [(b"content-length", b"10000")],
    }

    await middleware(scope, None, mock_send)
    assert app_called is False
    start_msg = next(m for m in sent_messages if m["type"] == "http.response.start")
    assert start_msg["status"] == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


@pytest.mark.asyncio
async def test_malformed_content_length_header_falls_back_to_streaming():
    """Asserts that non-numeric Content-Length falls back to streaming count without crashing."""
    middleware = StreamingUploadLimitMiddleware(lambda s, r, send: send({"type": "http.response.start", "status": 200}), max_bytes=1000)
    sent_messages = []

    async def mock_send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/emails/analyze",
        "headers": [(b"content-length", b"not-a-number")],
    }

    async def mock_receive():
        return {"type": "http.request", "body": b"valid", "more_body": False}

    await middleware(scope, mock_receive, mock_send)
    start_msg = next(m for m in sent_messages if m["type"] == "http.response.start")
    assert start_msg["status"] == 200
