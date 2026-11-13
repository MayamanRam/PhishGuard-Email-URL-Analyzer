"""Health Check API Router."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import get_db
from app.schemas.health import HealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Application and Database Health Check",
)
def get_health(db: Session = Depends(get_db)) -> HealthResponse:
    """Performs a live connectivity test against the SQLite database."""
    now_iso = datetime.now(timezone.utc).isoformat()
    db_status = "connected"
    db_error = None

    try:
        db.execute(text("SELECT 1;"))
    except Exception as exc:
        db_status = "error"
        db_error = str(exc)

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        timestamp=now_iso,
        database={"status": db_status, "error": db_error},
        environment=settings.PHISHGUARD_ENV,
    )
