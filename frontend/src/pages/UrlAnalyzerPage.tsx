import React, { useState } from "react";
import {
  Globe,
  AlertTriangle,
  Send,
  Briefcase,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Layers,
  Search,
} from "lucide-react";
import { UrlAnalysisResponse } from "../types";
import { ScoreGauge } from "../components/ScoreGauge";
import { SeverityBadge } from "../components/SeverityBadge";
import { ScoreExplainerModal } from "../components/ScoreExplainerModal";
import { analyzeUrl, generateReport } from "../services/api";

interface UrlAnalyzerPageProps {
  onCreateCaseFromRun: (runId: string, title: string) => void;
}

export const UrlAnalyzerPage: React.FC<UrlAnalyzerPageProps> = ({ onCreateCaseFromRun }) => {
  const [inputUrl, setInputUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UrlAnalysisResponse | null>(null);
  const [showExplainer, setShowExplainer] = useState(false);
  const [copiedDefanged, setCopiedDefanged] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);

  const sampleUrls = [
    {
      name: "Punycode Homoglyph (Apple)",
      url: "https://xn--pple-43d.com/login-verification?token=sec_994",
    },
    {
      name: "Brand Spoof + Open Redirect (PayPal)",
      url: "http://security-paypal-auth.xyz/verify?redirect_uri=https://evil-harvest.top/steal",
    },
    {
      name: "IPv4 Literal Target",
      url: "http://198.51.100.45:8080/secure/bank/credential_update.php",
    },
    {
      name: "Userinfo Impersonation",
      url: "https://support.google.com@phishing-gateway.cc/auth/login",
    },
    {
      name: "Legitimate Corporate Domain",
      url: "https://www.github.com/security/advisories",
    },
  ];

  const handleAnalyze = async (urlToAnalyze?: string) => {
    const target = urlToAnalyze || inputUrl;
    if (!target.trim()) {
      setError("Please provide a valid URL string to analyze.");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await analyzeUrl(target.trim());
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to analyze URL.");
    } finally {
      setLoading(false);
    }
  };

  const defangUrl = (u: string): string => {
    return u
      .replace(/http:\/\//gi, "hxxp://")
      .replace(/https:\/\//gi, "hxxps://")
      .replace(/\./g, "[.]");
  };

  const handleCopyDefanged = (u: string) => {
    const defanged = defangUrl(u);
    navigator.clipboard.writeText(defanged);
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const handleDownloadReport = async (format: "pdf" | "csv" | "json" | "stix") => {
    if (!result) return;
    setDownloadingFormat(format);
    try {
      const rep = await generateReport({
        format,
        analysis_run_id: result.run_id,
      });
      window.open(rep.download_url, "_blank");
    } catch (err: any) {
      alert(`Report generation failed: ${err.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 p-6 shadow-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Globe className="h-5 w-5 text-indigo-400" />
              Defensive URL Threat Analyzer
            </h1>
            <p className="mt-1 text-xs text-slate-400 max-w-2xl font-sans">
              Air-gapped static URL inspection. Decodes Punycode/homoglyphs, verifies RFC 3986 normalization, inspects domain entropy and suspicious TLDs, and detects open redirect vectors without initiating network requests.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-950/60 px-3 py-1 text-xs font-mono text-emerald-400 border border-emerald-800/80">
              <ShieldCheck className="h-3.5 w-3.5" />
              Air-Gapped: Zero Outbound HTTP
            </span>
          </div>
        </div>
      </div>

      {/* Input Workbench */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-sm space-y-4">
        <label className="block text-xs font-mono font-medium text-slate-300">
          Target URL String (Raw or Defanged)
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !loading) handleAnalyze();
              }}
              placeholder="e.g. https://xn--pple-43d.com/login-verification?token=sec_994"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>
          <button
            type="button"
            onClick={() => handleAnalyze()}
            disabled={loading || !inputUrl.trim()}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-indigo-500 transition disabled:opacity-50"
          >
            {loading ? (
              <span className="flex items-center gap-1.5">
                <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white border-t-transparent" />
                Analyzing...
              </span>
            ) : (
              <>
                <Send className="h-3.5 w-3.5" />
                Analyze URL
              </>
            )}
          </button>
        </div>

        {/* Quick Sample Presets */}
        <div className="pt-2 border-t border-slate-800/60">
          <div className="flex items-center gap-2 mb-2">
            <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
            <span className="text-[11px] font-mono text-slate-400">
              Load Curated Test Cases:
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setInputUrl(s.url);
                  handleAnalyze(s.url);
                }}
                disabled={loading}
                className="rounded-md border border-slate-800 bg-slate-950/80 px-2.5 py-1 text-[11px] font-mono text-slate-300 hover:border-indigo-500/50 hover:bg-slate-800 transition"
              >
                {s.name}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-rose-900/60 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis Result Output */}
      {result && (
        <div className="space-y-6">
          {/* Top Score & Action Card */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-sm">
            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
              {/* Score Gauge */}
              <div className="md:col-span-4 p-2 border-b md:border-b-0 md:border-r border-slate-800">
                <ScoreGauge
                  score={result.risk_score}
                  severity={result.severity}
                  onExplainClick={() => setShowExplainer(true)}
                />
              </div>

              {/* Target & Summary */}
              <div className="md:col-span-5 space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Defanged Target URL
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopyDefanged(result.url)}
                    className="text-[10px] font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1 ml-auto"
                    title="Copy Defanged URL"
                  >
                    {copiedDefanged ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" />
                        <span className="text-emerald-400">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy Defanged</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="rounded-lg bg-slate-950 p-3 font-mono text-xs text-amber-300/90 border border-slate-800 break-all select-all">
                  {defangUrl(result.url)}
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="rounded-md bg-slate-950/60 p-2 border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px]">
                      REGISTRABLE DOMAIN
                    </span>
                    <span className="text-slate-200 font-semibold truncate block">
                      {result.url_analysis.registrable_domain || "N/A"}
                    </span>
                  </div>
                  <div className="rounded-md bg-slate-950/60 p-2 border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px]">
                      PUBLIC SUFFIX / TLD
                    </span>
                    <span className="text-slate-200 font-semibold truncate block">
                      .{result.url_analysis.public_suffix || "N/A"}
                    </span>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 leading-relaxed">
                  Formula Assessment:{" "}
                  <span className="text-slate-300 font-mono">
                    {result.formula_explanation}
                  </span>
                </div>
              </div>

              {/* Incident & Export Actions */}
              <div className="md:col-span-3 flex flex-col gap-2.5 border-t md:border-t-0 md:border-l border-slate-800 pt-4 md:pt-0 md:pl-6">
                <button
                  type="button"
                  onClick={() =>
                    onCreateCaseFromRun(
                      result.run_id,
                      `Investigate URL: ${result.url_analysis.hostname || result.url.substring(0, 40)}`
                    )
                  }
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600/20 border border-indigo-500/40 px-3 py-2 text-xs font-semibold text-indigo-300 hover:bg-indigo-600/30 transition"
                >
                  <Briefcase className="h-4 w-4" />
                  Create Investigation Case
                </button>

                <div className="pt-2 border-t border-slate-800">
                  <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1.5">
                    Defensive Export
                  </span>
                  <div className="grid grid-cols-4 gap-1.5">
                    <button
                      type="button"
                      disabled={!!downloadingFormat}
                      onClick={() => handleDownloadReport("pdf")}
                      className="rounded bg-slate-800 hover:bg-slate-700 p-1.5 text-[11px] font-mono text-slate-200 text-center transition"
                    >
                      {downloadingFormat === "pdf" ? "..." : "PDF"}
                    </button>
                    <button
                      type="button"
                      disabled={!!downloadingFormat}
                      onClick={() => handleDownloadReport("csv")}
                      className="rounded bg-slate-800 hover:bg-slate-700 p-1.5 text-[11px] font-mono text-slate-200 text-center transition"
                    >
                      {downloadingFormat === "csv" ? "..." : "CSV"}
                    </button>
                    <button
                      type="button"
                      disabled={!!downloadingFormat}
                      onClick={() => handleDownloadReport("json")}
                      className="rounded bg-slate-800 hover:bg-slate-700 p-1.5 text-[11px] font-mono text-slate-200 text-center transition"
                    >
                      {downloadingFormat === "json" ? "..." : "JSON"}
                    </button>
                    <button
                      type="button"
                      disabled={!!downloadingFormat}
                      onClick={() => handleDownloadReport("stix")}
                      className="rounded bg-purple-950 hover:bg-purple-900 border border-purple-800 p-1.5 text-[11px] font-mono text-purple-200 text-center transition"
                    >
                      {downloadingFormat === "stix" ? "..." : "STIX"}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Deep Forensic URL Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Structural Metrics */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-3">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Layers className="h-4 w-4 text-indigo-400" />
                Structural & Normalization Analysis
              </h3>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Scheme:</span>
                  <span className="text-indigo-300 font-semibold uppercase">
                    {result.url_analysis.scheme || "N/A"}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Hostname:</span>
                  <span className="text-slate-200 truncate max-w-[240px]">
                    {result.url_analysis.hostname}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Shannon Entropy:</span>
                  <span
                    className={`font-semibold ${
                      result.url_analysis.entropy > 4.5
                        ? "text-rose-400"
                        : "text-slate-200"
                    }`}
                  >
                    {result.url_analysis.entropy.toFixed(3)} bits
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Total Character Length:</span>
                  <span className="text-slate-200">
                    {result.url_analysis.total_length} chars
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">RFC 3986 Normalized:</span>
                  <span className="text-slate-300 truncate max-w-[240px] text-[11px]">
                    {result.url_analysis.normalized_url}
                  </span>
                </div>
              </div>
            </div>

            {/* Heuristic Threat Flags */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-3">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-rose-400" />
                Evasion & Impersonation Indicators
              </h3>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div
                  className={`p-2.5 rounded-lg border ${
                    result.url_analysis.has_brand_impersonation
                      ? "border-rose-900/80 bg-rose-950/40 text-rose-300"
                      : "border-slate-800 bg-slate-950/40 text-slate-400"
                  }`}
                >
                  <span className="text-[10px] block opacity-70">BRAND SPOOF</span>
                  <span className="font-semibold text-xs">
                    {result.url_analysis.has_brand_impersonation
                      ? `Target: ${result.url_analysis.impersonated_brand_name}`
                      : "Not Detected"}
                  </span>
                </div>

                <div
                  className={`p-2.5 rounded-lg border ${
                    result.url_analysis.is_punycode ||
                    result.url_analysis.has_mixed_script_homoglyphs
                      ? "border-rose-900/80 bg-rose-950/40 text-rose-300"
                      : "border-slate-800 bg-slate-950/40 text-slate-400"
                  }`}
                >
                  <span className="text-[10px] block opacity-70">PUNYCODE / HOMOGLYPH</span>
                  <span className="font-semibold text-xs">
                    {result.url_analysis.is_punycode
                      ? `Decoded: ${result.url_analysis.decoded_punycode_host}`
                      : result.url_analysis.has_mixed_script_homoglyphs
                      ? "Mixed Scripts"
                      : "Standard ASCII"}
                  </span>
                </div>

                <div
                  className={`p-2.5 rounded-lg border ${
                    result.url_analysis.has_open_redirect_param
                      ? "border-amber-900/80 bg-amber-950/40 text-amber-300"
                      : "border-slate-800 bg-slate-950/40 text-slate-400"
                  }`}
                >
                  <span className="text-[10px] block opacity-70">OPEN REDIRECT PARAM</span>
                  <span className="font-semibold text-xs">
                    {result.url_analysis.has_open_redirect_param
                      ? `Dest: ${result.url_analysis.open_redirect_target || "Detected"}`
                      : "None"}
                  </span>
                </div>

                <div
                  className={`p-2.5 rounded-lg border ${
                    result.url_analysis.has_ip_hostname
                      ? "border-rose-900/80 bg-rose-950/40 text-rose-300"
                      : "border-slate-800 bg-slate-950/40 text-slate-400"
                  }`}
                >
                  <span className="text-[10px] block opacity-70">IP HOSTNAME TARGET</span>
                  <span className="font-semibold text-xs">
                    {result.url_analysis.has_ip_hostname
                      ? `Literal IP (${result.url_analysis.ip_type || "IPv4"})`
                      : "Domain Name"}
                  </span>
                </div>

                <div
                  className={`p-2.5 rounded-lg border ${
                    result.url_analysis.has_suspicious_tld
                      ? "border-amber-900/80 bg-amber-950/40 text-amber-300"
                      : "border-slate-800 bg-slate-950/40 text-slate-400"
                  }`}
                >
                  <span className="text-[10px] block opacity-70">HIGH-ABUSE TLD</span>
                  <span className="font-semibold text-xs">
                    {result.url_analysis.has_suspicious_tld
                      ? `.${result.url_analysis.suspicious_tld_name}`
                      : "Standard TLD"}
                  </span>
                </div>

                <div
                  className={`p-2.5 rounded-lg border ${
                    result.url_analysis.has_userinfo_spoof
                      ? "border-rose-900/80 bg-rose-950/40 text-rose-300"
                      : "border-slate-800 bg-slate-950/40 text-slate-400"
                  }`}
                >
                  <span className="text-[10px] block opacity-70">USERINFO SPOOFING</span>
                  <span className="font-semibold text-xs">
                    {result.url_analysis.has_userinfo_spoof
                      ? `Prefix: ${result.url_analysis.userinfo}`
                      : "Clean Authority"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Triggered Findings Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                Triggered Threat Detections ({result.findings.length})
              </h3>
              <span className="text-xs font-mono text-slate-400">
                Deterministic MITRE ATT&CK Mapping
              </span>
            </div>

            {result.findings.length === 0 ? (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 text-center text-xs text-slate-400 font-mono">
                No phishing or evasion indicators triggered for this URL.
              </div>
            ) : (
              <div className="space-y-3">
                {result.findings.map((finding, idx) => (
                  <div
                    key={idx}
                    className="rounded-lg border border-slate-800 bg-slate-950 p-4 space-y-2 hover:border-slate-700 transition"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <SeverityBadge severity={finding.severity} size="sm" />
                        <span className="font-mono text-xs font-bold text-slate-200">
                          {finding.rule_id}
                        </span>
                        <span className="text-xs font-semibold text-white">
                          {finding.rule_name}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {finding.mitre_id && (
                          <span className="rounded bg-indigo-950/80 px-2 py-0.5 text-[10px] font-mono text-indigo-300 border border-indigo-800">
                            {finding.mitre_id}
                          </span>
                        )}
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-slate-300">
                          +{finding.effective_score} pts
                        </span>
                      </div>
                    </div>

                    <div className="text-xs text-slate-300 bg-slate-900/70 p-2.5 rounded border border-slate-800/80 font-mono text-[11px] overflow-x-auto">
                      {JSON.stringify(finding.evidence, null, 2)}
                    </div>

                    <div className="text-[11px] text-slate-400">
                      <strong className="text-indigo-400">Remediation:</strong>{" "}
                      {finding.remediation}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Math Score Explainer Modal */}
      {result && (
        <ScoreExplainerModal
          isOpen={showExplainer}
          onClose={() => setShowExplainer(false)}
          finalScore={result.risk_score}
          severity={result.severity}
          formulaExplanation={result.formula_explanation}
          categoryDetails={result.category_details}
          findings={result.findings}
        />
      )}
    </div>
  );
};
