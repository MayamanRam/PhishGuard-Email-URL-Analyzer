"""Error API Response Schemas conforming to RFC 7807 problem details style."""

from typing import Optional
from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Sanitized, standardized API error response."""

    error: str = Field(..., description="High-level error classification")
    detail: str = Field(..., description="Safe human-readable error description")
    error_id: Optional[str] = Field(default=None, description="Correlation identifier for troubleshooting")

