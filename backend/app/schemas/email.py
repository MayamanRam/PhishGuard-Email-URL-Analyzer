"""Pydantic Schemas for Email and URL Analysis Requests and Responses."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class EmailAnalyzeTextRequest(BaseModel):
    raw_email: str = Field(..., min_length=5, description="Raw RFC 5322 email string or MIME data.")
    source_name: str = Field("pasted_email.eml", max_length=255)


class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="Target URL string to statically analyze.")

