import React from "react";
import {
  Activity,
  Mail,
  Globe,
  Briefcase,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import { DashboardStats } from "../types";
import { SeverityBadge } from "../components/SeverityBadge";
import { TabKey } from "../components/Navbar";

interface DashboardPageProps {
  stats: DashboardStats | null;
  loading: boolean;
  onRefresh: () => void;
  onNavigate: (tab: TabKey) => void;
  onInspectRun: (targetType: "email" | "url", runId: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  stats,
  loading,
  onRefresh,
  onNavigate,
  onInspectRun,
}) => {
  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 p-6 shadow-md">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white font-mono">
            Security Operations Center (SOC) Console
          </h1>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl font-sans">
            Defensive phishing threat telemetry, static email header forensics, unverified authentication auditing, and URL analysis without external network interaction.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-mono uppercase tracking-wider">Total Scans</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {stats?.total_analyses ?? 0}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-mono uppercase tracking-wider">Email Scans</span>
            <Mail className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {stats?.email_analyses ?? 0}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-mono uppercase tracking-wider">URL Scans</span>
            <Globe className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {stats?.url_analyses ?? 0}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-mono uppercase tracking-wider">Open Cases</span>
            <Briefcase className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {stats?.open_cases ?? 0}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-xs font-mono uppercase tracking-wider">Total Findings</span>
            <AlertTriangle className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {stats?.total_findings ?? 0}
          </div>
        </div>
      </div>

      {/* Threat Distribution & Quick Workbenches */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 font-mono">
            Threat Severity Distribution
          </h2>
          <div className="space-y-3">
            {[
              { label: "Critical", count: stats?.severity_distribution?.critical ?? 0, color: "bg-rose-500", text: "text-rose-400" },
              { label: "High", count: stats?.severity_distribution?.high ?? 0, color: "bg-orange-500", text: "text-orange-400" },
              { label: "Moderate", count: stats?.severity_distribution?.moderate ?? 0, color: "bg-amber-500", text: "text-amber-400" },
              { label: "Low", count: stats?.severity_distribution?.low ?? 0, color: "bg-emerald-500", text: "text-emerald-400" },
            ].map((sev) => {
              const total = stats?.total_analyses || 1;
              const pct = Math.round((sev.count / total) * 100);
              return (
                <div key={sev.label} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-400">{sev.label}</span>
                    <span className={`font-bold ${sev.text}`}>{sev.count} ({pct}%)</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div className={`h-full ${sev.color} transition-all`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Quick Launch Cards */}
        <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 flex flex-col justify-between hover:border-slate-700 transition">
            <div className="space-y-2">
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-blue-950 text-blue-400 border border-blue-800/80">
                <Mail className="h-5 w-5" />
              </div>
              <h3 className="text-sm font-bold text-white font-mono">
                Email Threat Analyzer
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Upload `.eml` or paste RFC 5322 text. Performs recursive MIME parsing, hop delay routing inspection, and unverified header claim auditing.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate("email")}
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
            >
              Launch Email Analyzer <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 flex flex-col justify-between hover:border-slate-700 transition">
            <div className="space-y-2">
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-purple-950 text-purple-400 border border-purple-800/80">
                <Globe className="h-5 w-5" />
              </div>
              <h3 className="text-sm font-bold text-white font-mono">
                Static URL Analyzer
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Analyze target URLs offline. Detects Cyrillic homoglyphs, Punycode deception, brand impersonation, open redirect query tokens, and literal IP hosts.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate("url")}
              className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
            >
              Launch URL Analyzer <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent Telemetry Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 font-mono">
            Recent Analysis Telemetry
          </h2>
        </div>

        {!stats?.recent_analyses || stats.recent_analyses.length === 0 ? (
          <div className="rounded-lg border border-slate-800/60 bg-slate-950/50 p-8 text-center text-slate-500 text-xs">
            No threat analyses recorded yet. Start by submitting an email or URL above.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3">Type</th>
                  <th className="p-3">Target Subject / URL</th>
                  <th className="p-3">Risk Score</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Timestamp (UTC)</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-900/60">
                {stats.recent_analyses.map((run) => (
                  <tr key={run.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3 uppercase text-cyan-400 font-bold">{run.target_type}</td>
                    <td className="p-3 text-slate-200 max-w-xs truncate" title={run.target_identifier}>
                      {run.target_identifier}
                    </td>
                    <td className="p-3 font-bold text-white">{run.risk_score} / 100</td>
                    <td className="p-3">
                      <SeverityBadge severity={run.severity} size="sm" />
                    </td>
                    <td className="p-3 text-slate-400">
                      {new Date(run.created_at).toLocaleString()}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        type="button"
                        onClick={() => onInspectRun(run.target_type, run.id)}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
