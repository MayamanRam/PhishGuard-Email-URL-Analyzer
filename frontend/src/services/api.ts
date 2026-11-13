/**
 * PhishGuard Frontend API Client Service.
 *
 * Implements hardened API communication with custom CSRF header enforcement
 * and structured error handling.
 */

import {
  AuditLogItem,
  DashboardStats,
  DkimDnsRecord,
  EmailAnalysisResponse,
  HealthStatus,
  InvestigationCaseDetail,
  InvestigationCaseSummary,
  ReportItem,
  RuleCatalogItem,
  TriggeredFinding,
  UrlAnalysisResponse,
} from "../types";

const API_BASE = "/api/v1";
const CSRF_HEADER = "X-PhishGuard-Client";
const CSRF_VALUE = "web-console";

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  headers.set(CSRF_HEADER, CSRF_VALUE);

  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = `Request failed with status ${response.status}`;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || errJson.error || errorDetail;
    } catch {
      // Keep default errorDetail
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

// -------------------------------------------------------------
// HEALTH & DASHBOARD
// -------------------------------------------------------------

export async function fetchHealth(): Promise<HealthStatus> {
  return request<HealthStatus>("/health");
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/overview/stats");
}

// -------------------------------------------------------------
// EMAIL ANALYSIS
// -------------------------------------------------------------

export async function analyzeEmailUpload(file: File): Promise<EmailAnalysisResponse> {
  const formData = new FormData();
  formData.append("file", file);

  return request<EmailAnalysisResponse>("/emails/analyze", {
    method: "POST",
    body: formData,
  });
}

export async function analyzeEmailText(
  rawEmail: string,
  sourceName: string = "pasted_email.eml"
): Promise<EmailAnalysisResponse> {
  return request<EmailAnalysisResponse>("/emails/analyze-text", {
    method: "POST",
    body: JSON.stringify({ raw_email: rawEmail, source_name: sourceName }),
  });
}

export async function fetchEmailAnalysis(runId: string): Promise<any> {
  return request<any>(`/emails/${runId}`);
}

// -------------------------------------------------------------
// URL ANALYSIS
// -------------------------------------------------------------

export async function analyzeUrl(url: string): Promise<UrlAnalysisResponse> {
  return request<UrlAnalysisResponse>("/urls/analyze", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

export async function fetchUrlAnalysis(runId: string): Promise<any> {
  return request<any>(`/urls/${runId}`);
}

// -------------------------------------------------------------
// CASES & INCIDENT RESPONSE
// -------------------------------------------------------------

export async function fetchCases(
  status?: string,
  severity?: string
): Promise<{ items: InvestigationCaseSummary[]; total: number }> {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  const q = params.toString() ? `?${params.toString()}` : "";
  return request<{ items: InvestigationCaseSummary[]; total: number }>(`/cases${q}`);
}

export async function createCase(payload: {
  title: string;
  description?: string;
  severity: string;
  assigned_to?: string;
}): Promise<InvestigationCaseSummary> {
  return request<InvestigationCaseSummary>("/cases", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchCaseDetail(caseId: string): Promise<InvestigationCaseDetail> {
  return request<InvestigationCaseDetail>(`/cases/${caseId}`);
}

export async function updateCase(
  caseId: string,
  payload: { status?: string; severity?: string; assigned_to?: string }
): Promise<InvestigationCaseSummary> {
  return request<InvestigationCaseSummary>(`/cases/${caseId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function addCaseNote(
  caseId: string,
  content: string,
  author: string = "analyst"
): Promise<any> {
  return request<any>(`/cases/${caseId}/notes`, {
    method: "POST",
    body: JSON.stringify({ content, author }),
  });
}

export async function associateArtifactToCase(
  caseId: string,
  artifactType: string,
  artifactId: string
): Promise<any> {
  return request<any>(`/cases/${caseId}/artifacts`, {
    method: "POST",
    body: JSON.stringify({ artifact_type: artifactType, artifact_id: artifactId }),
  });
}

// -------------------------------------------------------------
// FINDINGS & RULES
// -------------------------------------------------------------

export async function fetchFindings(
  severity?: string,
  category?: string,
  runId?: string
): Promise<{ items: TriggeredFinding[]; total: number }> {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (category) params.set("category", category);
  if (runId) params.set("run_id", runId);
  const q = params.toString() ? `?${params.toString()}` : "";
  return request<{ items: TriggeredFinding[]; total: number }>(`/findings${q}`);
}

export async function fetchRuleCatalog(): Promise<RuleCatalogItem[]> {
  return request<RuleCatalogItem[]>("/findings/rules");
}

// -------------------------------------------------------------
// REPORTS & EXPORTS
// -------------------------------------------------------------

export async function generateReport(payload: {
  format: "pdf" | "csv" | "json" | "stix";
  analysis_run_id?: string;
  case_id?: string;
}): Promise<ReportItem> {
  return request<ReportItem>("/reports", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchReports(): Promise<{ items: ReportItem[]; total: number }> {
  return request<{ items: ReportItem[]; total: number }>("/reports");
}

// -------------------------------------------------------------
// AIR-GAPPED DKIM CACHE
// -------------------------------------------------------------

export async function fetchDkimCache(
  domain?: string
): Promise<{ items: DkimDnsRecord[]; total: number }> {
  const q = domain ? `?domain=${encodeURIComponent(domain)}` : "";
  return request<{ items: DkimDnsRecord[]; total: number }>(`/dkim-cache${q}`);
}

export async function importDkimSnapshot(payload: {
  source_snapshot: string;
  records: Array<{
    domain: string;
    selector: string;
    public_key_txt: string;
    notes?: string;
  }>;
}): Promise<any> {
  return request<any>("/dkim-cache/import", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteDkimRecord(recordId: string): Promise<any> {
  return request<any>(`/dkim-cache/${recordId}`, {
    method: "DELETE",
  });
}

// -------------------------------------------------------------
// AUDIT LOGS
// -------------------------------------------------------------

export async function fetchAuditLogs(action?: string): Promise<{ items: AuditLogItem[]; total: number }> {
  const q = action ? `?action=${encodeURIComponent(action)}` : "";
  return request<{ items: AuditLogItem[]; total: number }>(`/audit${q}`);
}
