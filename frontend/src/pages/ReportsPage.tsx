import React, { useEffect, useState } from "react";
import {
  FileText,
  Download,
  RefreshCw,
  Plus,
  Search,
  Copy,
  Check,
  FileCode,
  FileSpreadsheet,
  AlertTriangle,
} from "lucide-react";
import { ReportItem } from "../types";
import { fetchReports, generateReport } from "../services/api";

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Quick Generator State
  const [isGenerateModalOpen, setIsGenerateModalOpen] = useState(false);
  const [targetType, setTargetType] = useState<"analysis" | "case">("analysis");
  const [targetId, setTargetId] = useState("");
  const [format, setFormat] = useState<"pdf" | "csv" | "json" | "stix">("pdf");
  const [generating, setGenerating] = useState(false);

  const loadReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchReports();
      setReports(data.items);
    } catch (err: any) {
      setError(err.message || "Failed to load generated reports.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetId.trim()) return;
    setGenerating(true);
    try {
      const res = await generateReport({
        format,
        analysis_run_id: targetType === "analysis" ? targetId.trim() : undefined,
        case_id: targetType === "case" ? targetId.trim() : undefined,
      });
      setIsGenerateModalOpen(false);
      setTargetId("");
      await loadReports();
      window.open(res.download_url, "_blank");
    } catch (err: any) {
      alert(`Report generation failed: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  const filteredReports = reports.filter((r) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      r.report_number.toLowerCase().includes(q) ||
      r.target_id.toLowerCase().includes(q) ||
      r.sha256_hash.toLowerCase().includes(q)
    );
  });

  const getFormatBadge = (fmt: string) => {
    switch (fmt.toLowerCase()) {
      case "pdf":
        return (
          <span className="inline-flex items-center gap-1 rounded bg-rose-950/80 px-2 py-0.5 text-[11px] font-mono text-rose-300 border border-rose-800">
            <FileText className="h-3 w-3" />
            PDF (Defanged)
          </span>
        );
      case "csv":
        return (
          <span className="inline-flex items-center gap-1 rounded bg-emerald-950/80 px-2 py-0.5 text-[11px] font-mono text-emerald-300 border border-emerald-800">
            <FileSpreadsheet className="h-3 w-3" />
            CSV (Formula Escaped)
          </span>
        );
      case "json":
        return (
          <span className="inline-flex items-center gap-1 rounded bg-cyan-950/80 px-2 py-0.5 text-[11px] font-mono text-cyan-300 border border-cyan-800">
            <FileCode className="h-3 w-3" />
            JSON
          </span>
        );
      case "stix":
        return (
          <span className="inline-flex items-center gap-1 rounded bg-purple-950/80 px-2 py-0.5 text-[11px] font-mono text-purple-300 border border-purple-800">
            <FileCode className="h-3 w-3" />
            STIX 2.1 (OASIS CTI)
          </span>
        );
      default:
        return <span>{fmt}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-emerald-950/40 p-6 shadow-md">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <FileText className="h-5 w-5 text-emerald-400" />
            Investigation Report Registry & Artifact Export
          </h1>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl font-sans">
            Forensic reports generated with strict defensive guardrails: PDF links defanged into text, CSV exports protected against spreadsheet formula injection, and SHA-256 evidence integrity hashing.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setIsGenerateModalOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-emerald-500 transition"
          >
            <Plus className="h-4 w-4" />
            Generate New Report
          </button>
          <button
            type="button"
            onClick={loadReports}
            disabled={loading}
            className="rounded-lg border border-slate-700 bg-slate-800 p-2 text-slate-200 hover:bg-slate-700 transition disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Search Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4">
        <div className="relative">
          <Search className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search report number, analysis run ID, or SHA-256 hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
          />
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Reports Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-slate-400">
            Loading report artifacts...
          </div>
        ) : filteredReports.length === 0 ? (
          <div className="p-12 text-center text-xs font-mono text-slate-400">
            No reports found. Generate a report from an Email or URL analysis.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-950/80 font-mono text-[11px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="py-3 px-4">Report Number</th>
                  <th className="py-3 px-4">Format</th>
                  <th className="py-3 px-4">Target / Run Reference</th>
                  <th className="py-3 px-4">SHA-256 Digest</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">Generated At</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {filteredReports.map((r) => {
                  const isCopied = copiedHash === r.sha256_hash;
                  return (
                    <tr key={r.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-bold text-white">
                        {r.report_number}
                      </td>
                      <td className="py-3 px-4">{getFormatBadge(r.format)}</td>
                      <td className="py-3 px-4 font-mono text-slate-400 truncate max-w-[180px]">
                        {r.target_id}
                      </td>
                      <td className="py-3 px-4">
                        <button
                          type="button"
                          onClick={() => handleCopyHash(r.sha256_hash)}
                          className="flex items-center gap-1.5 text-[10px] text-slate-400 hover:text-emerald-300 font-mono"
                          title="Click to copy full SHA-256 hash"
                        >
                          {isCopied ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                          <span>{r.sha256_hash.substring(0, 16)}...</span>
                        </button>
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {(r.file_size_bytes / 1024).toFixed(1)} KB
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {new Date(r.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <a
                          href={r.download_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 rounded bg-slate-800 hover:bg-slate-700 px-2.5 py-1 text-slate-200 transition"
                        >
                          <Download className="h-3 w-3 text-emerald-400" />
                          Download
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quick Report Generator Modal */}
      {isGenerateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl space-y-4">
            <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
              <FileText className="h-4 w-4 text-emerald-400" />
              Generate Investigation Report
            </h2>

            <form onSubmit={handleGenerate} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Target Entity Type
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setTargetType("analysis")}
                    className={`rounded-lg border px-3 py-2 text-xs font-mono transition ${
                      targetType === "analysis"
                        ? "border-emerald-500 bg-emerald-950/40 text-emerald-300 font-bold"
                        : "border-slate-800 bg-slate-950 text-slate-400"
                    }`}
                  >
                    Analysis Run
                  </button>
                  <button
                    type="button"
                    onClick={() => setTargetType("case")}
                    className={`rounded-lg border px-3 py-2 text-xs font-mono transition ${
                      targetType === "case"
                        ? "border-emerald-500 bg-emerald-950/40 text-emerald-300 font-bold"
                        : "border-slate-800 bg-slate-950 text-slate-400"
                    }`}
                  >
                    Investigation Case
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  {targetType === "analysis" ? "Analysis Run ID *" : "Case ID *"}
                </label>
                <input
                  type="text"
                  required
                  placeholder={
                    targetType === "analysis"
                      ? "e.g. paste run ID from email or URL scan"
                      : "e.g. paste case UUID"
                  }
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Output Format
                </label>
                <div className="grid grid-cols-4 gap-2">
                  <button
                    type="button"
                    onClick={() => setFormat("pdf")}
                    className={`rounded-lg border px-2 py-2 text-xs font-mono transition ${
                      format === "pdf"
                        ? "border-emerald-500 bg-emerald-950/40 text-emerald-300 font-bold"
                        : "border-slate-800 bg-slate-950 text-slate-400"
                    }`}
                  >
                    PDF
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormat("csv")}
                    className={`rounded-lg border px-2 py-2 text-xs font-mono transition ${
                      format === "csv"
                        ? "border-emerald-500 bg-emerald-950/40 text-emerald-300 font-bold"
                        : "border-slate-800 bg-slate-950 text-slate-400"
                    }`}
                  >
                    CSV
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormat("json")}
                    className={`rounded-lg border px-2 py-2 text-xs font-mono transition ${
                      format === "json"
                        ? "border-emerald-500 bg-emerald-950/40 text-emerald-300 font-bold"
                        : "border-slate-800 bg-slate-950 text-slate-400"
                    }`}
                  >
                    JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormat("stix")}
                    className={`rounded-lg border px-2 py-2 text-xs font-mono transition ${
                      format === "stix"
                        ? "border-purple-500 bg-purple-950/40 text-purple-300 font-bold"
                        : "border-slate-800 bg-slate-950 text-slate-400"
                    }`}
                  >
                    STIX 2.1
                  </button>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsGenerateModalOpen(false)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating || !targetId.trim()}
                  className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 transition disabled:opacity-50"
                >
                  {generating ? "Exporting..." : "Generate & Download"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
