import React, { useEffect, useState } from "react";
import {
  ListFilter,
  Search,
  BookOpen,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Tag,
  ShieldAlert,
} from "lucide-react";
import { RuleCatalogItem, TriggeredFinding } from "../types";
import { SeverityBadge } from "../components/SeverityBadge";
import { fetchFindings, fetchRuleCatalog } from "../services/api";

export const FindingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"catalog" | "triggered">("catalog");
  const [rules, setRules] = useState<RuleCatalogItem[]>([]);
  const [triggeredFindings, setTriggeredFindings] = useState<TriggeredFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      if (activeTab === "catalog") {
        const catalog = await fetchRuleCatalog();
        setRules(catalog);
      } else {
        const findings = await fetchFindings(
          severityFilter || undefined,
          categoryFilter || undefined
        );
        setTriggeredFindings(findings.items);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load detection catalog.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeTab, categoryFilter, severityFilter]);

  const toggleExpandRule = (id: string) => {
    setExpandedRuleId(expandedRuleId === id ? null : id);
  };

  const filteredRules = rules.filter((r) => {
    const matchesSearch =
      !searchQuery ||
      r.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.rule_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.mitre_attack_id &&
        r.mitre_attack_id.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesCategory = !categoryFilter || r.category === categoryFilter;
    const matchesSeverity = !severityFilter || r.severity.toLowerCase() === severityFilter.toLowerCase();

    return matchesSearch && matchesCategory && matchesSeverity;
  });

  const categories = [
    { key: "header_routing", label: "Header Routing" },
    { key: "sender_spoofing", label: "Sender Spoofing" },
    { key: "auth_claims", label: "Auth Claims" },
    { key: "url_threats", label: "URL Threats" },
    { key: "attachment_risk", label: "Attachment Risk" },
    { key: "content_evasion", label: "Content Evasion" },
  ];

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 p-6 shadow-md">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <ListFilter className="h-5 w-5 text-indigo-400" />
            Detection Catalog & MITRE ATT&CK Matrix
          </h1>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl font-sans">
            Explore PhishGuard's deterministic heuristic rules, mathematical category caps, diminishing returns weights, and adversary techniques mapped directly to the MITRE ATT&CK Enterprise Matrix.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-slate-800 bg-slate-950 p-1">
            <button
              type="button"
              onClick={() => setActiveTab("catalog")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-mono transition ${
                activeTab === "catalog"
                  ? "bg-indigo-600 text-white font-semibold"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <BookOpen className="h-3.5 w-3.5" />
              Rule Catalog ({rules.length || 27})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("triggered")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-mono transition ${
                activeTab === "triggered"
                  ? "bg-indigo-600 text-white font-semibold"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Live Telemetry Log
            </button>
          </div>
          <button
            type="button"
            onClick={loadData}
            disabled={loading}
            className="rounded-lg border border-slate-700 bg-slate-800 p-2 text-slate-200 hover:bg-slate-700 transition disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search rule ID (e.g. URL-002), MITRE ID (e.g. T1566), or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>

          <div className="flex gap-2">
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none"
            >
              <option value="">All Categories</option>
              {categories.map((c) => (
                <option key={c.key} value={c.key}>
                  {c.label}
                </option>
              ))}
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="moderate">Moderate</option>
              <option value="low">Low</option>
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

      {/* Tab 1: Rule Catalog Grid */}
      {activeTab === "catalog" && (
        <div className="space-y-3">
          {filteredRules.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 text-center text-xs font-mono text-slate-400">
              No detection rules matched your search filters.
            </div>
          ) : (
            filteredRules.map((rule) => {
              const isExpanded = expandedRuleId === rule.rule_id;
              return (
                <div
                  key={rule.rule_id}
                  className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 transition hover:border-slate-700"
                >
                  <div
                    onClick={() => toggleExpandRule(rule.rule_id)}
                    className="flex flex-wrap items-center justify-between gap-3 cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-xs font-bold text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-800">
                        {rule.rule_id}
                      </span>
                      <h3 className="text-xs font-semibold text-white">
                        {rule.rule_name}
                      </h3>
                      <SeverityBadge
                        severity={rule.severity.toLowerCase() as any}
                        size="sm"
                      />
                    </div>

                    <div className="flex items-center gap-3">
                      {rule.mitre_attack_id && (
                        <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] font-mono text-amber-300 border border-slate-700 flex items-center gap-1">
                          <Tag className="h-3 w-3" />
                          {rule.mitre_attack_id}
                        </span>
                      )}
                      <span className="rounded bg-slate-950 px-2 py-0.5 text-[11px] font-mono text-slate-400 border border-slate-800">
                        Weight: {rule.base_weight}
                      </span>
                      {isExpanded ? (
                        <ChevronUp className="h-4 w-4 text-slate-400" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {/* Expanded Rule Details */}
                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t border-slate-800 space-y-3 text-xs">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80">
                          <span className="text-[10px] font-mono text-slate-500 uppercase block">
                            CATEGORY DOMAIN
                          </span>
                          <span className="font-mono text-slate-200 uppercase font-semibold">
                            {rule.category.replace("_", " ")}
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80">
                          <span className="text-[10px] font-mono text-slate-500 uppercase block">
                            CONFIDENCE MULTIPLIER
                          </span>
                          <span className="font-mono text-emerald-400 font-semibold">
                            {rule.confidence_multiplier}x
                          </span>
                        </div>
                        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80">
                          <span className="text-[10px] font-mono text-slate-500 uppercase block">
                            MITRE ATT&CK REFERENCE
                          </span>
                          <span className="font-mono text-amber-400 font-semibold">
                            {rule.mitre_attack_id || "Unclassified Heuristic"}
                          </span>
                        </div>
                      </div>

                      <div className="space-y-1">
                        <strong className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                          Rule Description & Threat Rationale:
                        </strong>
                        <p className="text-slate-300 leading-relaxed font-sans">
                          {rule.description}
                        </p>
                      </div>

                      <div className="space-y-1 rounded-lg bg-indigo-950/20 border border-indigo-900/40 p-3">
                        <strong className="text-[11px] font-mono text-indigo-300 uppercase tracking-wider block">
                          Recommended Analyst Action:
                        </strong>
                        <p className="text-slate-300 leading-relaxed font-sans">
                          {rule.remediation_advice}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Tab 2: Live Telemetry Findings Log */}
      {activeTab === "triggered" && (
        <div className="space-y-3">
          {triggeredFindings.length === 0 ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 text-center text-xs font-mono text-slate-400">
              No triggered findings recorded yet. Run an email or URL analysis to generate detections.
            </div>
          ) : (
            triggeredFindings.map((finding, idx) => (
              <div
                key={idx}
                className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 space-y-2 hover:border-slate-700 transition"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={finding.severity} size="sm" />
                    <span className="font-mono text-xs font-bold text-slate-200">
                      {finding.rule_id}
                    </span>
                    <span className="text-xs font-semibold text-white">
                      {finding.rule_name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[11px]">
                    {finding.mitre_id && (
                      <span className="rounded bg-amber-950/80 px-2 py-0.5 text-amber-300 border border-amber-800">
                        {finding.mitre_id}
                      </span>
                    )}
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">
                      Score: +{finding.effective_score}
                    </span>
                  </div>
                </div>

                <div className="rounded-lg bg-slate-950 p-2.5 border border-slate-800/80 text-[11px] font-mono text-slate-300 overflow-x-auto">
                  {JSON.stringify(finding.evidence, null, 2)}
                </div>

                <div className="text-[11px] text-slate-400">
                  <span className="text-indigo-400 font-semibold">Remediation:</span>{" "}
                  {finding.remediation}
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};
