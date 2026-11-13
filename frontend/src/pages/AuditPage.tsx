import React, { useEffect, useState } from "react";
import {
  RefreshCw,
  Search,
  FileCode,
  X,
  Lock,
  AlertTriangle,
} from "lucide-react";
import { AuditLogItem } from "../types";
import { fetchAuditLogs } from "../services/api";

export const AuditPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedLog, setSelectedLog] = useState<AuditLogItem | null>(null);

  const loadAudit = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAuditLogs(actionFilter || undefined);
      setLogs(data.items);
    } catch (err: any) {
      setError(err.message || "Failed to load audit trail.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAudit();
  }, [actionFilter]);

  const filteredLogs = logs.filter((l) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      l.event_type.toLowerCase().includes(q) ||
      l.object_type.toLowerCase().includes(q) ||
      l.object_id.toLowerCase().includes(q) ||
      l.client_ip.toLowerCase().includes(q)
    );
  });

  const getActionBadge = (evt: string) => {
    if (evt.includes("analysis")) {
      return "bg-cyan-950/80 text-cyan-300 border-cyan-800";
    }
    if (evt.includes("case")) {
      return "bg-indigo-950/80 text-indigo-300 border-indigo-800";
    }
    if (evt.includes("report")) {
      return "bg-emerald-950/80 text-emerald-300 border-emerald-800";
    }
    return "bg-slate-800 text-slate-300 border-slate-700";
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-purple-950/40 p-6 shadow-md">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <Lock className="h-5 w-5 text-purple-400" />
            Append-Only Forensics Audit Trail
          </h1>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl font-sans">
            Chronological, immutable event telemetry recording analysis execution, case state mutations, evidence retention, and report generations in compliance with NIST SP 800-92 standards.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={loadAudit}
            disabled={loading}
            className="rounded-lg border border-slate-700 bg-slate-800 p-2 text-slate-200 hover:bg-slate-700 transition disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search event type, object ID, or client IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-purple-500 focus:outline-none"
            />
          </div>

          <div className="w-full sm:w-64">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-300 focus:outline-none"
            >
              <option value="">All Action Events</option>
              <option value="analysis_executed">Analysis Executed</option>
              <option value="case_created">Case Created</option>
              <option value="case_updated">Case Updated</option>
              <option value="note_added">Note Added</option>
              <option value="artifact_associated">Artifact Associated</option>
              <option value="report_generated">Report Generated</option>
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-slate-400">
            Loading forensic audit events...
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="p-12 text-center text-xs font-mono text-slate-400">
            No audit records found matching query.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-slate-950/80 font-mono text-[11px] uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4">Target Object</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Client IP</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`rounded border px-2 py-0.5 text-[10px] font-mono uppercase ${getActionBadge(
                          log.event_type
                        )}`}
                      >
                        {log.event_type}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-white font-semibold">{log.object_type}</div>
                      <div className="text-[10px] text-slate-500 truncate max-w-[180px]">
                        {log.object_id}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-mono uppercase ${
                          log.status.toLowerCase() === "success"
                            ? "bg-emerald-950/60 text-emerald-400 border border-emerald-800"
                            : "bg-rose-950/60 text-rose-400 border border-rose-800"
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">{log.client_ip}</td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={() => setSelectedLog(log)}
                        className="rounded bg-slate-800 hover:bg-slate-700 px-2.5 py-1 text-[11px] font-mono text-slate-200 transition"
                      >
                        View JSON
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* JSON Inspection Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="w-full max-w-xl rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                <FileCode className="h-4 w-4 text-purple-400" />
                Audit Record Event Payload
              </h2>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-500">EVENT ID:</span>
                <span className="text-slate-200">{selectedLog.id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-500">EVENT TYPE:</span>
                <span className="text-purple-400">{selectedLog.event_type}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-500">TIMESTAMP:</span>
                <span className="text-slate-200">{selectedLog.timestamp}</span>
              </div>
            </div>

            <div className="rounded-lg bg-slate-950 p-4 border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-[300px]">
              <pre>{JSON.stringify(selectedLog.details, null, 2)}</pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
