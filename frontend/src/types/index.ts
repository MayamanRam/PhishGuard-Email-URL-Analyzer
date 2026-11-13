/**
 * PhishGuard Frontend Shared TypeScript Interfaces.
 */

export type RiskLevel = "low" | "moderate" | "high" | "critical";

export interface HealthStatus {
  status: "healthy" | "degraded";
  app_name: string;
  version: string;
  timestamp: string;
  database: {
    status: string;
    error?: string | null;
  };
  environment: string;
}

export interface DashboardStats {
  total_analyses: number;
  email_analyses: number;
  url_analyses: number;
  open_cases: number;
  total_findings: number;
  severity_distribution: {
    low: number;
    moderate: number;
    high: number;
    critical: number;
  };
  recent_analyses: Array<{
    id: string;
    target_type: "email" | "url";
    target_identifier: string;
    risk_score: number;
    severity: RiskLevel;
    created_at: string;
  }>;
}

export interface TriggeredFinding {
  rule_id: string;
  rule_name: string;
  category: string;
  severity: RiskLevel;
  effective_score: number;
  evidence: Record<string, any>;
  remediation: string;
  mitre_id?: string | null;
}

export interface CategoryScoreDetail {
  category: string;
  category_cap: number;
  raw_rule_sum: number;
  diminishing_score: number;
  rules_triggered_count: number;
}

export interface RoutingHop {
  hop_number: number;
  raw_header: string;
  from_host: string;
  by_host: string;
  with_protocol: string;
  ip_address?: string | null;
  is_private_ip: boolean;
  timestamp_raw: string;
  timestamp_utc?: string | null;
  delay_seconds?: number | null;
  anomalies: string[];
}

export interface AuthClaimDetail {
  result: string;
  sender_domain?: string | null;
  client_ip?: string | null;
  raw_claim?: string;
  signing_domain?: string | null;
  selector?: string | null;
  header_from_domain?: string | null;
  action_taken?: string | null;
}

export interface EmailAnalysisResponse {
  run_id: string;
  target_type: "email";
  subject: string;
  risk_score: number;
  severity: RiskLevel;
  formula_explanation: string;
  category_scores: Record<string, number>;
  category_details: CategoryScoreDetail[];
  findings: TriggeredFinding[];
  email_metadata: {
    sha256: string;
    from: string;
    to: string;
    date: string;
    sender_analysis: {
      from_display_name: string;
      from_address: string;
      from_domain: string;
      reply_to_address?: string | null;
      reply_to_domain?: string | null;
      return_path_address?: string | null;
      return_path_domain?: string | null;
      has_from_reply_to_mismatch: boolean;
      has_from_return_path_mismatch: boolean;
      has_display_name_email_spoofing: boolean;
      has_brand_impersonation_in_name: boolean;
      detected_impersonated_brand?: string | null;
      anomalies: string[];
    };
    auth_report: {
      spf: AuthClaimDetail;
      dkim: AuthClaimDetail;
      dmarc: AuthClaimDetail;
      verdict: string;
      warnings: string[];
      disclaimer: string;
      dkim_offline_verification?: {
        status: string;
        verified: boolean;
        signing_domain?: string | null;
        selector?: string | null;
        algorithm?: string | null;
        canonicalization?: string | null;
        signed_headers?: string[];
        body_hash_status?: string | null;
        signature_status?: string | null;
        message: string;
        dns_source_snapshot?: string | null;
      } | null;
    };
    routing_hops: RoutingHop[];
  };
  extracted_urls: Array<{
    original_url: string;
    normalized_url: string;
    scheme: string;
    hostname: string;
    registrable_domain: string;
    has_ip_hostname: boolean;
    is_punycode: boolean;
    has_brand_impersonation: boolean;
    has_open_redirect_param: boolean;
    entropy: number;
    anomalies: string[];
  }>;
  attachments: Array<{
    filename: string;
    declared_content_type: string;
    size_bytes: number;
    sha256_hash: string;
    primary_extension: string;
    has_double_extension: boolean;
    is_executable_or_script: boolean;
    is_disk_image: boolean;
    is_macro_enabled: boolean;
    anomalies: string[];
    yara_matches?: Array<{
      rule_name: string;
      category: string;
      severity: string;
      description: string;
      tags: string[];
      matched_strings: string[];
      mitre_attack_id?: string | null;
    }>;
  }>;
  created_at: string;
}

export interface UrlAnalysisResponse {
  run_id: string;
  target_type: "url";
  url: string;
  risk_score: number;
  severity: RiskLevel;
  formula_explanation: string;
  category_scores: Record<string, number>;
  category_details: CategoryScoreDetail[];
  findings: TriggeredFinding[];
  url_analysis: {
    original_url: string;
    normalized_url: string;
    scheme: string;
    hostname: string;
    registrable_domain: string;
    public_suffix: string;
    has_ip_hostname: boolean;
    ip_type?: string | null;
    has_userinfo_spoof: boolean;
    userinfo?: string | null;
    is_punycode: boolean;
    decoded_punycode_host?: string | null;
    has_mixed_script_homoglyphs: boolean;
    homoglyph_details: string[];
    has_suspicious_tld: boolean;
    suspicious_tld_name?: string | null;
    has_open_redirect_param: boolean;
    open_redirect_target?: string | null;
    has_brand_impersonation: boolean;
    impersonated_brand_name?: string | null;
    entropy: number;
    total_length: number;
    anomalies: string[];
  };
  created_at: string;
}

export interface InvestigationCaseSummary {
  id: string;
  case_number: string;
  title: string;
  description?: string | null;
  status: "open" | "in_review" | "escalated" | "resolved" | "closed";
  severity: "low" | "medium" | "high" | "critical";
  classification?: string;
  created_at: string;
  updated_at: string;
}

export interface InvestigationCaseDetail extends InvestigationCaseSummary {
  notes: Array<{
    id: string;
    author: string;
    content: string;
    created_at: string;
  }>;
  artifacts: Array<{
    id: string;
    case_id: string;
    artifact_id: string;
    associated_at: string;
  }>;
}

export interface ReportItem {
  id: string;
  report_number: string;
  report_type: string;
  target_id: string;
  format: "pdf" | "csv" | "json" | "stix";
  sha256_hash: string;
  file_size_bytes: number;
  generated_by: string;
  created_at: string;
  download_url: string;
}

export interface DkimDnsRecord {
  id: string;
  domain: string;
  selector: string;
  public_key_txt: string;
  source_snapshot: string;
  imported_at: string;
  notes?: string | null;
}

export interface AuditLogItem {
  id: string;
  event_type: string;
  object_type: string;
  object_id: string;
  status: string;
  details: Record<string, any>;
  client_ip: string;
  timestamp: string;
}

export interface RuleCatalogItem {
  rule_id: string;
  rule_name: string;
  category: string;
  severity: string;
  base_weight: number;
  confidence_multiplier: number;
  description: string;
  remediation_advice: string;
  mitre_attack_id?: string | null;
}
