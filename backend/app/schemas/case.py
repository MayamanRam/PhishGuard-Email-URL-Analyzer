"""Pydantic Schemas for Case Management."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str | None = Field(None, max_length=4000)
    severity: str = Field("medium", pattern="^(low|medium|high|critical)$")
    assigned_to: str | None = Field(None, max_length=100)


class CaseUpdateRequest(BaseModel):
    status: str | None = Field(None, pattern="^(open|investigating|closed|false_positive)$")
    severity: str | None = Field(None, pattern="^(low|medium|high|critical)$")
    assigned_to: str | None = Field(None, max_length=100)


class NoteCreateRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)
    author: str = Field("analyst", max_length=100)


class ArtifactAssociateRequest(BaseModel):
    artifact_type: str = Field(..., pattern="^(email|url|attachment|analysis_run)$")
    artifact_id: str = Field(..., min_length=1, max_length=64)

