"""Health Check API Response Schemas."""

from typing import Dict, Any
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check status and connectivity details."""

    status: str = Field(default="healthy", description="Application status: healthy or degraded")
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")
    timestamp: str = Field(..., description="UTC ISO 8601 timestamp")
    database: Dict[str, Any] = Field(..., description="Database connection health check")
    environment: str = Field(..., description="Deployment environment")

