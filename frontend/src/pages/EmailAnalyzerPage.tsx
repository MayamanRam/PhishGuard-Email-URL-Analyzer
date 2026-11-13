import React, { useState } from "react";
import {
  Upload,
  FileText,
  AlertTriangle,
  FileCode,
  Send,
  Briefcase,
  Sparkles,
  Database,
} from "lucide-react";
import { EmailAnalysisResponse } from "../types";
import { ScoreGauge } from "../components/ScoreGauge";
import { SeverityBadge } from "../components/SeverityBadge";
import { RoutingHopsVisualizer } from "../components/RoutingHopsVisualizer";
import { AuthClaimsBadge } from "../components/AuthClaimsBadge";
import { ScoreExplainerModal } from "../components/ScoreExplainerModal";
import { DkimCacheModal } from "../components/DkimCacheModal";
import { analyzeEmailText, analyzeEmailUpload, generateReport } from "../services/api";

interface EmailAnalyzerPageProps {
  onCreateCaseFromRun: (runId: string, title: string) => void;
}

export const EmailAnalyzerPage: React.FC<EmailAnalyzerPageProps> = ({ onCreateCaseFromRun }) => {
  const [activeInputTab, setActiveInputTab] = useState<"upload" | "paste">("upload");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [rawText, setRawText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EmailAnalysisResponse | null>(null);

  // Results subtab
  const [resultTab, setResultTab] = useState<"findings" | "hops" | "auth" | "urls" | "attachments">("findings");
  const [showExplainer, setShowExplainer] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);
  const [showDkimModal, setShowDkimModal] = useState(false);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleLoadSample = () => {
    const sample = [
      'From: "PayPal Account Security" <service@unauthorized-notification.ru>',
      "To: security-analyst@company.org",
      "Reply-To: phish-collector@external-scam.com",
      "Subject: URGENT: Immediate Account Verification Required",
      "Date: Thu, 12 Nov 2026 12:00:00 +0000",
      "MIME-Version: 1.0",
      'Content-Type: multipart/mixed; boundary="BOUNDARY_PHISH"',
      "Authentication-Results: mx.target.com; dkim=fail; spf=fail (domain does not designate 198.51.100.20); dmarc=fail (action=reject)",
      "Received: from mx.target.com by client.local; Thu, 12 Nov 2026 12:00:05 +0000",
      "Received: from mail.origin.ru ([198.51.100.20]) by mx.target.com; Thu, 12 Nov 2026 12:00:00 +0000",
      "",
      "--BOUNDARY_PHISH",
      "Content-Type: text/html; charset=utf-8",
      "",
      "<html><body>",
      "<p>Your account access has been restricted due to unauthorized login attempts.</p>",
      '<p>Please verify your identity immediately: <a href="http://192.168.1.100/paypal-login.php?redirect_uri=https://evil.ru">https://www.paypal.com/signin</a></p>',
      '<form action="http://192.168.1.100/harvest-credentials.php"><button type="submit">Unlock Account</button></form>',
      "</body></html>",
      "",
      "--BOUNDARY_PHISH",
      'Content-Type: application/octet-stream; name="Urgent_Invoice.pdf.exe"',
      'Content-Disposition: attachment; filename="Urgent_Invoice.pdf.exe"',
      "Content-Transfer-Encoding: base64",
      "",
      "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "--BOUNDARY_PHISH--",
    ].join("\r\n");

    setRawText(sample);
    setActiveInputTab("paste");
  };

  const handleRunAnalysis = async () => {
    setError(null);
    setLoading(true);

    try {
      if (activeInputTab === "upload") {
        if (!selectedFile) {
          throw new Error("Please select an .eml email file to upload.");
        }
        const data = await analyzeEmailUpload(selectedFile);
        setResult(data);
      } else {
        if (!rawText.trim()) {
          throw new Error("Please paste raw email headers and content.");
        }
        const data = await analyzeEmailText(rawText);
        setResult(data);
      }
    } catch (err: any) {
      setError(err.message || "Failed to analyze email.");
    } finally {
      setLoading(false);
    }
  };

  const handleExportReport = async (format: "pdf" | "csv" | "json" | "stix") => {
    if (!result) return;
    setDownloadingFormat(format);
    try {
      const rep = await generateReport({
        format,
        analysis_run_id: result.run_id,
      });
      window.open(rep.download_url, "_blank");
    } catch (err: any) {
      setError(`Failed to export ${format.toUpperCase()} report: ${err.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/90 p-5">
        <div>
          <h1 className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <FileCode className="h-5 w-5 text-cyan-400" />
            Defensive Email Threat Analyzer
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Static RFC 5322 / MIME analysis. Evaluates headers, transit routing hops, unverified authentication claims, anchor-destination mismatches, and attachment evasions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowDkimModal(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-mono font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition"
          >
            <Database className="h-3.5 w-3.5 text-emerald-400" />
            DKIM DNS Cache
          </button>
          <button
            type="button"
            onClick={handleLoadSample}
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-800/80 bg-cyan-950/60 px-3 py-1.5 text-xs font-mono font-medium text-cyan-300 hover:bg-cyan-900/60 transition"
          >
            <Sparkles className="h-3.5 w-3.5" />
            Load Phishing Test Sample
          </button>
        </div>
      </div>

      {/* Input Workbench */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
        {/* Toggle */}
        <div className="flex border-b border-slate-800 pb-3 gap-2">
          <button
            type="button"
            onClick={() => setActiveInputTab("upload")}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
              activeInputTab === "upload"
                ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Upload className="h-3.5 w-3.5" /> Upload .EML File
          </button>
          <button
            type="button"
            onClick={() => setActiveInputTab("paste")}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
              activeInputTab === "paste"
                ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <FileText className="h-3.5 w-3.5" /> Paste Raw RFC 5322 Text
          </button>
        </div>

        {activeInputTab === "upload" ? (
          <div className="rounded-xl border-2 border-dashed border-slate-700 bg-slate-950/60 p-8 text-center">
            <input
              type="file"
              id="eml-upload"
              accept=".eml,message/rfc822"
              onChange={handleFileUpload}
              className="hidden"
            />
            <label
              htmlFor="eml-upload"
              className="cursor-pointer flex flex-col items-center justify-center space-y-2"
            >
              <div className="h-10 w-10 rounded-full bg-slate-800 flex items-center justify-center text-cyan-400">
                <Upload className="h-5 w-5" />
              </div>
              <span className="text-xs font-semibold text-slate-200">
                {selectedFile ? selectedFile.name : "Click to browse or drag & drop suspicious .EML file"}
              </span>
              <span className="text-[11px] text-slate-500">
                10 MB maximum upload limit • Processed completely in-memory
              </span>
            </label>
          </div>
        ) : (
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            rows={8}
            placeholder="From: ...&#10;To: ...&#10;Subject: ...&#10;&#10;Paste raw headers and message body here..."
            className="w-full rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        )}

        {error && (
          <div className="rounded-lg border border-rose-900/60 bg-rose-950/30 p-3 text-xs text-rose-300 flex items-start gap-2">
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex justify-end">
          <button
            type="button"
            onClick={handleRunAnalysis}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-xs font-semibold text-white shadow-md hover:bg-cyan-500 transition disabled:opacity-50"
          >
            {loading ? (
              <>Analyzing Ingested Email...</>
            ) : (
              <>
                <Send className="h-3.5 w-3.5" /> Execute Defensive Analysis
              </>
            )}
          </button>
        </div>
      </div>

      {/* Analysis Results View */}
      {result && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Header Metadata & Gauge */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Subject and Header info */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Target Email Metadata
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  SHA-256: {result.email_metadata.sha256.substring(0, 16)}...
                </span>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div>
                  <span className="text-slate-500">Subject: </span>
                  <span className="font-bold text-white">{result.subject || "(No Subject)"}</span>
                </div>
                <div>
                  <span className="text-slate-500">From: </span>
                  <span className="text-slate-300">{result.email_metadata.from}</span>
                </div>
                <div>
                  <span className="text-slate-500">Reply-To: </span>
                  <span className="text-slate-300">
                    {result.email_metadata.sender_analysis.reply_to_address || "None specified"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Date: </span>
                  <span className="text-slate-400">{result.email_metadata.date || "Unknown"}</span>
                </div>
              </div>

              {/* Action Toolbar */}
              <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400 font-mono">Export Report:</span>
                  {(["pdf", "csv", "json", "stix"] as const).map((fmt) => (
                    <button
                      key={fmt}
                      type="button"
                      onClick={() => handleExportReport(fmt)}
                      disabled={downloadingFormat === fmt}
                      className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs font-mono uppercase text-slate-300 hover:bg-slate-700 hover:text-white transition disabled:opacity-50"
                    >
                      {downloadingFormat === fmt ? "..." : fmt === "stix" ? "STIX 2.1" : fmt}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={() => onCreateCaseFromRun(result.run_id, result.subject || "Suspicious Phishing Investigation")}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-purple-800/80 bg-purple-950/60 px-3 py-1.5 text-xs font-mono font-medium text-purple-300 hover:bg-purple-900/60 transition"
                >
                  <Briefcase className="h-3.5 w-3.5" />
                  Create Investigation Case
                </button>
              </div>
            </div>

            {/* Risk Gauge */}
            <ScoreGauge
              score={result.risk_score}
              severity={result.severity}
              onExplainClick={() => setShowExplainer(true)}
            />
          </div>

          {/* Deep Inspection Tabs */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5 space-y-4">
            <div className="flex border-b border-slate-800 pb-3 gap-1 overflow-x-auto">
              {[
                { key: "findings", label: `Triggered Findings (${result.findings.length})` },
                { key: "hops", label: `Routing Hops (${result.email_metadata.routing_hops.length})` },
                { key: "auth", label: "Auth Claims Audit" },
                { key: "urls", label: `Extracted URLs (${result.extracted_urls.length})` },
                { key: "attachments", label: `Attachments (${result.attachments.length})` },
              ].map((t) => (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => setResultTab(t.key as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition shrink-0 ${
                    resultTab === t.key
                      ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Findings Tab */}
            {resultTab === "findings" && (
              <div className="space-y-3">
                {result.findings.length === 0 ? (
                  <div className="p-6 text-center text-slate-500 text-xs">
                    No threat indicators triggered. All offline heuristic checks were negative.
                  </div>
                ) : (
                  result.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-2 hover:border-slate-700 transition"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-cyan-400">
                            [{f.rule_id}]
                          </span>
                          <span className="font-bold text-slate-200 text-xs font-mono">
                            {f.rule_name}
                          </span>
                          {f.mitre_id && (
                            <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-slate-400">
                              MITRE {f.mitre_id}
                            </span>
                          )}
                        </div>
                        <SeverityBadge severity={f.severity} size="sm" />
                      </div>

                      {f.remediation && (
                        <p className="text-xs text-slate-300 font-sans">
                          <span className="text-slate-500 font-semibold font-mono">Recommendation: </span>
                          {f.remediation}
                        </p>
                      )}

                      {f.evidence && Object.keys(f.evidence).length > 0 && (
                        <div className="rounded bg-slate-900 p-2 font-mono text-[11px] text-slate-400 overflow-x-auto border border-slate-800/60">
                          {JSON.stringify(f.evidence)}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Routing Hops Tab */}
            {resultTab === "hops" && (
              <RoutingHopsVisualizer hops={result.email_metadata.routing_hops} />
            )}

            {/* Auth Claims Tab */}
            {resultTab === "auth" && (
              <AuthClaimsBadge
                spf={result.email_metadata.auth_report.spf}
                dkim={result.email_metadata.auth_report.dkim}
                dmarc={result.email_metadata.auth_report.dmarc}
                verdict={result.email_metadata.auth_report.verdict}
                warnings={result.email_metadata.auth_report.warnings}
                disclaimer={result.email_metadata.auth_report.disclaimer}
                dkimOffline={result.email_metadata.auth_report.dkim_offline_verification}
              />
            )}

            {/* Extracted URLs Tab */}
            {resultTab === "urls" && (
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-3">Target URL</th>
                      <th className="p-3">Domain</th>
                      <th className="p-3">Flags</th>
                      <th className="p-3">Entropy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-900/60">
                    {result.extracted_urls.map((u, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="p-3 text-slate-300 max-w-sm truncate" title={u.original_url}>
                          {u.original_url}
                        </td>
                        <td className="p-3 text-slate-400">{u.registrable_domain}</td>
                        <td className="p-3 space-x-1">
                          {u.has_ip_hostname && (
                            <span className="rounded bg-rose-950 px-1 py-0.5 text-[10px] text-rose-300 border border-rose-800">
                              IP Host
                            </span>
                          )}
                          {u.has_brand_impersonation && (
                            <span className="rounded bg-orange-950 px-1 py-0.5 text-[10px] text-orange-300 border border-orange-800">
                              Brand Spoof
                            </span>
                          )}
                          {u.is_punycode && (
                            <span className="rounded bg-amber-950 px-1 py-0.5 text-[10px] text-amber-300 border border-amber-800">
                              Punycode
                            </span>
                          )}
                        </td>
                        <td className="p-3 text-slate-400">{u.entropy}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Attachments Tab */}
            {resultTab === "attachments" && (
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-3">Filename</th>
                      <th className="p-3">Declared MIME</th>
                      <th className="p-3">Extension</th>
                      <th className="p-3">YARA Signatures</th>
                      <th className="p-3">Size (Bytes)</th>
                      <th className="p-3">SHA-256 Hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-900/60">
                    {result.attachments.map((att, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="p-3 font-bold text-white">{att.filename}</td>
                        <td className="p-3 text-slate-400">{att.declared_content_type}</td>
                        <td className="p-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] ${
                              att.is_executable_or_script
                                ? "bg-rose-950 text-rose-300 border border-rose-800"
                                : "bg-slate-800 text-slate-300"
                            }`}
                          >
                            {att.primary_extension}
                          </span>
                        </td>
                        <td className="p-3">
                          {att.yara_matches && att.yara_matches.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {att.yara_matches.map((ym, yidx) => (
                                <span
                                  key={yidx}
                                  title={`${ym.description} (MITRE: ${ym.mitre_attack_id || "N/A"})`}
                                  className="rounded bg-rose-950/80 px-1.5 py-0.5 text-[10px] font-mono text-rose-300 border border-rose-700/80"
                                >
                                  {ym.rule_name}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="text-[11px] text-slate-500 font-mono">No matches</span>
                          )}
                        </td>
                        <td className="p-3 text-slate-400">{att.size_bytes.toLocaleString()}</td>
                        <td className="p-3 text-slate-500 truncate max-w-xs">{att.sha256_hash}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Explainer Modal */}
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

      {/* Air-Gapped DKIM Cache Management Modal */}
      <DkimCacheModal
        isOpen={showDkimModal}
        onClose={() => setShowDkimModal(false)}
      />
    </div>
  );
};
