"""Pydantic Schemas for Report Generation."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReportCreateRequest(BaseModel):
    format: str = Field(..., pattern="^(json|csv|pdf|stix)$", description="Export file format.")
    analysis_run_id: str | None = Field(None, max_length=64)
    case_id: str | None = Field(None, max_length=64)

