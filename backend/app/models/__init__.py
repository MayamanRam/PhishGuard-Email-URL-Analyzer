"""PhishGuard SQLAlchemy Models Package."""

from app.database.base import Base
from app.models.analysis_run import AnalysisRun
from app.models.email_artifact import EmailArtifact
from app.models.url_artifact import UrlArtifact
from app.models.attachment_artifact import AttachmentArtifact
from app.models.detection_rule import DetectionRule
from app.models.finding import Finding
from app.models.investigation_case import InvestigationCase
from app.models.case_artifact_association import CaseArtifactAssociation
from app.models.investigation_note import InvestigationNote
from app.models.report import Report
from app.models.audit_event import AuditEvent
from app.models.app_setting import AppSetting
from app.models.dkim_dns_record import DkimDnsRecord

__all__ = [
    "Base",
    "AnalysisRun",
    "EmailArtifact",
    "UrlArtifact",
    "AttachmentArtifact",
    "DetectionRule",
    "Finding",
    "InvestigationCase",
    "CaseArtifactAssociation",
    "InvestigationNote",
    "Report",
    "AuditEvent",
    "AppSetting",
    "DkimDnsRecord",
]

