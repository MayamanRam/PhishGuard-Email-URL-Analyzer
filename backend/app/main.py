"""PhishGuard FastAPI Application Entry Point."""

from contextlib import asynccontextmanager
import uuid
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging import setup_logging, logger
from app.core.security import (
    SecurityHeadersMiddleware,
    StreamingUploadLimitMiddleware,
    OriginAndCSRFMiddleware,
    SlidingWindowRateLimiter,
)
from app.database.base import Base
from app.database.session import engine
from app.api.v1.router import api_v1_router
# Import models to ensure registered on Base.metadata
import app.models  # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager handling startup and shutdown."""
    setup_logging("DEBUG" if settings.DEBUG else "INFO")
    logger.info(f"Initializing {settings.APP_NAME} v{settings.APP_VERSION}")

    # Ensure runtime directories exist
    settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    settings.PSL_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Ensure database schema is created
    Base.metadata.create_all(bind=engine)

    # Seed deterministic detection rules if needed
    try:
        from app.database.session import SessionLocal
        from app.database.seed import seed_detection_rules
        with SessionLocal() as db:
            seeded = seed_detection_rules(db)
            if seeded > 0:
                logger.info(f"Seeded {seeded} detection rules into database.")
    except Exception as e:
        logger.warning(f"Could not seed detection rules: {e}")

    logger.info("PhishGuard runtime directories verified.")

    yield

    logger.info("PhishGuard application shutdown complete.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Defensive Phishing Email and URL Threat Analysis Platform API",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# 1. Trusted Host Validation Middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)

# 2. Strict CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Length"],
)

# 3. Security HTTP Response Headers
app.add_middleware(SecurityHeadersMiddleware)

# 4. Request Body Size Limit (10MB Streaming Protection)
app.add_middleware(StreamingUploadLimitMiddleware)

# 5. Local Anti-Drive-by CSRF & Origin Validation
app.add_middleware(OriginAndCSRFMiddleware)

# 6. Sliding Window Rate Limiting
app.add_middleware(
    SlidingWindowRateLimiter,
    limit_per_minute=settings.RATE_LIMIT_PER_MINUTE,
)

# Mount API Routers
app.include_router(api_v1_router)


# Global Exception Handler (Safe sanitized error response without stack traces)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logger.error(f"Unhandled exception [error_id={error_id}] on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": "An internal error occurred while processing your request. Please contact support.",
            "error_id": error_id,
        },
    )

