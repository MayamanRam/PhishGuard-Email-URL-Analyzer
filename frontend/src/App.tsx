import React, { useEffect, useState } from "react";
import { Navbar, TabKey } from "./components/Navbar";
import { DashboardPage } from "./pages/DashboardPage";
import { EmailAnalyzerPage } from "./pages/EmailAnalyzerPage";
import { UrlAnalyzerPage } from "./pages/UrlAnalyzerPage";
import { CasesPage } from "./pages/CasesPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ReportsPage } from "./pages/ReportsPage";
import { AuditPage } from "./pages/AuditPage";
import { DashboardStats, HealthStatus } from "./types";
import {
  associateArtifactToCase,
  createCase,
  fetchDashboardStats,
  fetchHealth,
} from "./services/api";
import { ShieldCheck, Terminal } from "lucide-react";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>("dashboard");
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);

  const refreshHealthAndStats = async () => {
    try {
      const h = await fetchHealth();
      setHealth(h);
    } catch {
      setHealth({
        status: "degraded",
        app_name: "PhishGuard",
        version: "1.0.0",
        timestamp: new Date().toISOString(),
        database: { status: "offline", error: "Connection refused" },
        environment: "offline",
      });
    }

    setLoadingStats(true);
    try {
      const s = await fetchDashboardStats();
      setStats(s);
    } catch {
      // In standalone offline mode or initial startup
    } finally {
      setLoadingStats(false);
    }
  };

  useEffect(() => {
    refreshHealthAndStats();
  }, []);

  const handleInspectRun = (targetType: "email" | "url", _runId: string) => {
    if (targetType === "email") {
      setActiveTab("email");
    } else {
      setActiveTab("url");
    }
  };

  const handleCreateCaseFromRun = async (runId: string, title: string) => {
    try {
      const newCase = await createCase({
        title,
        description: `Auto-generated case for forensic analysis run ${runId}`,
        severity: "high",
        assigned_to: "security-analyst",
      });

      // Link artifact
      await associateArtifactToCase(newCase.id, "analysis_run", runId);

      setActiveCaseId(newCase.id);
      setActiveTab("cases");
      refreshHealthAndStats();
    } catch (err: any) {
      alert(`Could not automatically create case: ${err.message}`);
      setActiveTab("cases");
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Navigation Bar */}
      <Navbar
        activeTab={activeTab}
        onSelectTab={(tab) => {
          setActiveTab(tab);
          if (tab === "dashboard") refreshHealthAndStats();
        }}
        health={health}
      />

      {/* Main Dynamic Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {activeTab === "dashboard" && (
          <DashboardPage
            stats={stats}
            loading={loadingStats}
            onRefresh={refreshHealthAndStats}
            onNavigate={(tab) => {
              setActiveTab(tab);
              if (tab === "dashboard") refreshHealthAndStats();
            }}
            onInspectRun={handleInspectRun}
          />
        )}

        {activeTab === "email" && (
          <EmailAnalyzerPage onCreateCaseFromRun={handleCreateCaseFromRun} />
        )}

        {activeTab === "url" && (
          <UrlAnalyzerPage onCreateCaseFromRun={handleCreateCaseFromRun} />
        )}

        {activeTab === "cases" && (
          <CasesPage
            initialCaseId={activeCaseId}
            onNavigateToRun={handleInspectRun}
          />
        )}

        {activeTab === "findings" && <FindingsPage />}

        {activeTab === "reports" && <ReportsPage />}

        {activeTab === "audit" && <AuditPage />}
      </main>

      {/* Defensive Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 px-6 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-slate-400">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            <span>PhishGuard v1.0.0 Defensive Analysis Platform</span>
            <span className="hidden sm:inline text-slate-600">|</span>
            <span className="text-[11px] text-slate-500">
              Zero Outbound Network Interaction Guarantee
            </span>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <span className="flex items-center gap-1.5 text-cyan-400">
              <Terminal className="h-3 w-3" />
              SQLite WAL Active
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-500">
              NIST SP 800-92 Audit Preserved
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
};
export default App;
