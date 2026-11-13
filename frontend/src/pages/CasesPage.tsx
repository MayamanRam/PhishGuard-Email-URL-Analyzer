import React, { useEffect, useState } from "react";
import {
  Briefcase,
  Plus,
  RefreshCw,
  Search,
  User,
  MessageSquare,
  FileText,
  AlertTriangle,
  ChevronRight,
  Send,
  X,
  ExternalLink,
} from "lucide-react";
import { InvestigationCaseDetail, InvestigationCaseSummary } from "../types";
import { SeverityBadge } from "../components/SeverityBadge";
import {
  addCaseNote,
  createCase,
  fetchCaseDetail,
  fetchCases,
  generateReport,
  updateCase,
} from "../services/api";

interface CasesPageProps {
  initialCaseId?: string | null;
  onNavigateToRun?: (targetType: "email" | "url", runId: string) => void;
}

export const CasesPage: React.FC<CasesPageProps> = ({
  initialCaseId,
  onNavigateToRun,
}) => {
  const [cases, setCases] = useState<InvestigationCaseSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(
    initialCaseId || null
  );
  const [caseDetail, setCaseDetail] = useState<InvestigationCaseDetail | null>(
    null
  );
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");

  // New Case Modal
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [newSeverity, setNewSeverity] = useState("high");
  const [newAssignee, setNewAssignee] = useState("analyst");
  const [createLoading, setCreateLoading] = useState(false);

  // New Note
  const [noteContent, setNoteContent] = useState("");
  const [noteAuthor, setNoteAuthor] = useState("analyst");
  const [noteLoading, setNoteLoading] = useState(false);

  // Report download
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(
    null
  );

  const loadCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchCases(
        statusFilter || undefined,
        severityFilter || undefined
      );
      setCases(data.items);
      if (!selectedCaseId && data.items.length > 0) {
        setSelectedCaseId(data.items[0].id);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load investigation cases.");
    } finally {
      setLoading(false);
    }
  };

  const loadCaseDetail = async (id: string) => {
    setDetailLoading(true);
    try {
      const detail = await fetchCaseDetail(id);
      setCaseDetail(detail);
    } catch (err: any) {
      setError(`Failed to load case details: ${err.message}`);
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, [statusFilter, severityFilter]);

  useEffect(() => {
    if (selectedCaseId) {
      loadCaseDetail(selectedCaseId);
    } else {
      setCaseDetail(null);
    }
  }, [selectedCaseId]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    setCreateLoading(true);
    try {
      const created = await createCase({
        title: newTitle.trim(),
        description: newDescription.trim() || undefined,
        severity: newSeverity,
        assigned_to: newAssignee.trim() || undefined,
      });
      setIsCreateModalOpen(false);
      setNewTitle("");
      setNewDescription("");
      await loadCases();
      setSelectedCaseId(created.id);
    } catch (err: any) {
      alert(`Error creating case: ${err.message}`);
    } finally {
      setCreateLoading(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedCaseId) return;
    try {
      await updateCase(selectedCaseId, { status: newStatus });
      await loadCaseDetail(selectedCaseId);
      await loadCases();
    } catch (err: any) {
      alert(`Error updating case status: ${err.message}`);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId || !noteContent.trim()) return;
    setNoteLoading(true);
    try {
      await addCaseNote(selectedCaseId, noteContent.trim(), noteAuthor.trim());
      setNoteContent("");
      await loadCaseDetail(selectedCaseId);
    } catch (err: any) {
      alert(`Error adding note: ${err.message}`);
    } finally {
      setNoteLoading(false);
    }
  };

  const handleExportCaseReport = async (format: "pdf" | "csv" | "json") => {
    if (!selectedCaseId) return;
    setDownloadingFormat(format);
    try {
      const rep = await generateReport({
        format,
        case_id: selectedCaseId,
      });
      window.open(rep.download_url, "_blank");
    } catch (err: any) {
      alert(`Failed to generate case report: ${err.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  const filteredCases = cases.filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.title.toLowerCase().includes(q) ||
      c.case_number.toLowerCase().includes(q)
    );
  });

  const getStatusBadgeClass = (st: string) => {
    switch (st.toLowerCase()) {
      case "open":
        return "bg-rose-950/80 text-rose-300 border-rose-800";
      case "in_review":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      case "escalated":
        return "bg-purple-950/80 text-purple-300 border-purple-800";
      case "resolved":
        return "bg-emerald-950/80 text-emerald-300 border-emerald-800";
      case "closed":
        return "bg-slate-800 text-slate-400 border-slate-700";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 p-6 shadow-md">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <Briefcase className="h-5 w-5 text-cyan-400" />
            SOC Case Management & Incident Response
          </h1>
          <p className="mt-1 text-xs text-slate-400 max-w-2xl font-sans">
            Track, prioritize, and triage phishing investigations. Correlate email artifacts, forensic hops, and URL findings with an immutable audit trail and chronological analyst notes.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setIsCreateModalOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3.5 py-2 text-xs font-semibold text-white shadow-sm hover:bg-cyan-500 transition"
          >
            <Plus className="h-4 w-4" />
            New Investigation Case
          </button>
          <button
            type="button"
            onClick={loadCases}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-700 transition disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
            />
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-900/60 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Workspace Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Cases List */}
        <div className="lg:col-span-5 space-y-4">
          {/* Search & Filter Header */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search case # or title..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="flex gap-2">
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-[11px] font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
              >
                <option value="">All Statuses</option>
                <option value="open">Open</option>
                <option value="in_review">In Review</option>
                <option value="escalated">Escalated</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-[11px] font-mono text-slate-300 focus:border-cyan-500 focus:outline-none"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          {/* Cases Feed */}
          <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
            {filteredCases.length === 0 ? (
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-8 text-center text-xs text-slate-400 font-mono">
                No investigation cases match criteria.
              </div>
            ) : (
              filteredCases.map((c) => {
                const isSelected = c.id === selectedCaseId;
                return (
                  <div
                    key={c.id}
                    onClick={() => setSelectedCaseId(c.id)}
                    className={`cursor-pointer rounded-xl border p-4 transition ${
                      isSelected
                        ? "border-cyan-500 bg-cyan-950/20 shadow-md"
                        : "border-slate-800 bg-slate-900/70 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <span className="font-mono text-xs font-bold text-cyan-400">
                        {c.case_number}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] font-mono uppercase ${getStatusBadgeClass(
                            c.status
                          )}`}
                        >
                          {c.status.replace("_", " ")}
                        </span>
                        <SeverityBadge
                          severity={
                            c.severity === "medium"
                              ? "moderate"
                              : (c.severity as any)
                          }
                          size="sm"
                        />
                      </div>
                    </div>
                    <div className="text-xs font-semibold text-white line-clamp-1">
                      {c.title}
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[11px] font-mono text-slate-500">
                      <span>{new Date(c.created_at).toLocaleString()}</span>
                      <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Case Details & Timeline */}
        <div className="lg:col-span-7">
          {detailLoading ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-12 text-center text-xs font-mono text-slate-400">
              Loading case telemetry...
            </div>
          ) : !caseDetail ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-12 text-center text-xs font-mono text-slate-400">
              Select an investigation case to inspect details, notes, and artifacts.
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-6 space-y-6">
              {/* Case Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-cyan-400">
                      {caseDetail.case_number}
                    </span>
                    <span
                      className={`rounded border px-2 py-0.5 text-[10px] font-mono uppercase ${getStatusBadgeClass(
                        caseDetail.status
                      )}`}
                    >
                      {caseDetail.status.replace("_", " ")}
                    </span>
                  </div>
                  <h2 className="mt-1 text-base font-bold text-white">
                    {caseDetail.title}
                  </h2>
                </div>

                <div className="flex items-center gap-2">
                  <select
                    value={caseDetail.status}
                    onChange={(e) => handleStatusChange(e.target.value)}
                    className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1 text-xs font-mono text-cyan-300 focus:outline-none"
                  >
                    <option value="open">Open</option>
                    <option value="in_review">In Review</option>
                    <option value="escalated">Escalated</option>
                    <option value="resolved">Resolved</option>
                    <option value="closed">Closed</option>
                  </select>

                  <div className="flex gap-1">
                    <button
                      type="button"
                      disabled={!!downloadingFormat}
                      onClick={() => handleExportCaseReport("pdf")}
                      className="rounded bg-slate-800 hover:bg-slate-700 px-2.5 py-1 text-[11px] font-mono text-slate-200 transition"
                      title="Export Case PDF Report"
                    >
                      {downloadingFormat === "pdf" ? "..." : "PDF"}
                    </button>
                    <button
                      type="button"
                      disabled={!!downloadingFormat}
                      onClick={() => handleExportCaseReport("json")}
                      className="rounded bg-slate-800 hover:bg-slate-700 px-2.5 py-1 text-[11px] font-mono text-slate-200 transition"
                      title="Export Case JSON"
                    >
                      {downloadingFormat === "json" ? "..." : "JSON"}
                    </button>
                  </div>
                </div>
              </div>

              {/* Case Description */}
              {caseDetail.description && (
                <div className="rounded-lg bg-slate-950 p-3.5 border border-slate-800/80 text-xs text-slate-300 leading-relaxed font-sans">
                  {caseDetail.description}
                </div>
              )}

              {/* Associated Artifacts */}
              <div className="space-y-2">
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  Correlated Evidence Artifacts ({caseDetail.artifacts.length})
                </h3>
                {caseDetail.artifacts.length === 0 ? (
                  <div className="rounded-lg border border-slate-800/60 bg-slate-950/60 p-3 text-center text-[11px] font-mono text-slate-500">
                    No artifacts currently attached to this case.
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {caseDetail.artifacts.map((art) => (
                      <div
                        key={art.id}
                        className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs font-mono"
                      >
                        <div className="flex items-center gap-2">
                          <span className="text-cyan-400 font-semibold truncate max-w-[280px]">
                            {art.artifact_id}
                          </span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] text-slate-500">
                            Linked:{" "}
                            {new Date(art.associated_at).toLocaleDateString()}
                          </span>
                          {onNavigateToRun && (
                            <button
                              type="button"
                              onClick={() => onNavigateToRun("email", art.artifact_id)}
                              className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 text-[11px]"
                              title="Inspect artifact"
                            >
                              <ExternalLink className="h-3 w-3" />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Timeline of Analyst Notes */}
              <div className="space-y-3 pt-2 border-t border-slate-800">
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <MessageSquare className="h-4 w-4 text-indigo-400" />
                  Investigation Timeline & Analyst Notes ({caseDetail.notes.length})
                </h3>

                <div className="space-y-2 max-h-[350px] overflow-y-auto pr-1">
                  {caseDetail.notes.length === 0 ? (
                    <div className="rounded-lg border border-slate-800/60 bg-slate-950/60 p-4 text-center text-[11px] font-mono text-slate-500">
                      No analyst notes logged yet. Record forensic findings below.
                    </div>
                  ) : (
                    caseDetail.notes.map((note) => (
                      <div
                        key={note.id}
                        className="rounded-lg border border-slate-800 bg-slate-950 p-3.5 space-y-1 text-xs"
                      >
                        <div className="flex items-center justify-between font-mono text-[11px] text-slate-400">
                          <span className="flex items-center gap-1.5 text-cyan-400 font-semibold">
                            <User className="h-3 w-3" />
                            {note.author}
                          </span>
                          <span className="text-slate-500">
                            {new Date(note.created_at).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-slate-200 whitespace-pre-wrap leading-relaxed">
                          {note.content}
                        </p>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Note Form */}
                <form
                  onSubmit={handleAddNote}
                  className="pt-3 border-t border-slate-800 space-y-2"
                >
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Analyst Name / Callout"
                      value={noteAuthor}
                      onChange={(e) => setNoteAuthor(e.target.value)}
                      className="w-36 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none"
                    />
                    <input
                      type="text"
                      placeholder="Add investigation observation or hypothesis..."
                      value={noteContent}
                      onChange={(e) => setNoteContent(e.target.value)}
                      className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none"
                    />
                    <button
                      type="submit"
                      disabled={noteLoading || !noteContent.trim()}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 transition disabled:opacity-50"
                    >
                      <Send className="h-3 w-3" />
                      Add Note
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create New Case Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                <Briefcase className="h-4 w-4 text-cyan-400" />
                Initialize New Investigation Case
              </h2>
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-3.5">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Case Title *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. PayPal Credential Harvester Campaign"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Description / Incident Context
                </label>
                <textarea
                  rows={3}
                  placeholder="Summary of incident trigger, reported impact, or threat vector..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    Initial Severity
                  </label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">
                    Assigned Analyst
                  </label>
                  <input
                    type="text"
                    value={newAssignee}
                    onChange={(e) => setNewAssignee(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createLoading || !newTitle.trim()}
                  className="rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 transition disabled:opacity-50"
                >
                  {createLoading ? "Creating..." : "Create Case"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
