"""PhishGuard API v1 Master Router."""

from fastapi import APIRouter

from app.api.v1.audit import router as audit_router
from app.api.v1.cases import router as cases_router
from app.api.v1.dkim_cache import router as dkim_cache_router
from app.api.v1.emails import router as emails_router
from app.api.v1.findings import router as findings_router
from app.api.v1.health import router as health_router
from app.api.v1.overview import router as overview_router
from app.api.v1.reports import router as reports_router
from app.api.v1.urls import router as urls_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(health_router)
api_v1_router.include_router(overview_router)
api_v1_router.include_router(emails_router)
api_v1_router.include_router(urls_router)
api_v1_router.include_router(cases_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(dkim_cache_router)
