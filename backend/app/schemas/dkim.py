"""Pydantic Schemas for Air-Gapped DKIM Cache Management."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DkimRecordImportItem(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255, description="Domain name (e.g., example.com)")
    selector: str = Field(..., min_length=1, max_length=64, description="DKIM selector (e.g., s1, default)")
    public_key_txt: str = Field(..., min_length=10, description="Raw DNS TXT record containing v=DKIM1; p=...")
    notes: str | None = Field(default="", max_length=500)


class DkimSnapshotImportRequest(BaseModel):
    source_snapshot: str = Field(..., min_length=1, max_length=255, description="Snapshot filename or identifier (e.g., corporate_dns_zone_2026.json)")
    records: list[DkimRecordImportItem] = Field(..., min_length=1, description="List of DKIM DNS records to cache")


class DkimRecordResponse(BaseModel):
    id: str
    domain: str
    selector: str
    public_key_txt: str
    source_snapshot: str
    imported_at: str
    notes: str | None = None

