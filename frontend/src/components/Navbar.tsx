import React from "react";
import {
  ShieldAlert,
  Mail,
  Globe,
  Briefcase,
  FileText,
  Activity,
  ListFilter,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";
import { HealthStatus } from "../types";

export type TabKey = "dashboard" | "email" | "url" | "cases" | "findings" | "reports" | "audit";

interface NavbarProps {
  activeTab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  health: HealthStatus | null;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onSelectTab, health }) => {
  const navItems: Array<{ key: TabKey; label: string; icon: React.ReactNode }> = [
    { key: "dashboard", label: "Dashboard", icon: <Activity className="h-4 w-4" /> },
    { key: "email", label: "Email Analyzer", icon: <Mail className="h-4 w-4" /> },
    { key: "url", label: "URL Analyzer", icon: <Globe className="h-4 w-4" /> },
    { key: "cases", label: "Cases", icon: <Briefcase className="h-4 w-4" /> },
    { key: "findings", label: "Findings", icon: <ListFilter className="h-4 w-4" /> },
    { key: "reports", label: "Reports", icon: <FileText className="h-4 w-4" /> },
    { key: "audit", label: "Audit Trail", icon: <Activity className="h-4 w-4" /> },
  ];

  return (
    <header className="sticky top-0 z-40 border-b border-slate-800 bg-slate-950/95 backdrop-blur">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6 lg:px-8">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 shadow-md">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold tracking-tight text-white font-mono">
                PhishGuard
              </span>
              <span className="rounded bg-cyan-950 px-1.5 py-0.5 text-[10px] font-mono text-cyan-400 border border-cyan-800">
                v1.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans hidden sm:block">
              Defensive Phishing Email & URL Threat Analysis Platform
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden lg:flex items-center gap-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => onSelectTab(item.key)}
                className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                  isActive
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                    : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                }`}
              >
                {item.icon}
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* System Health Status */}
        <div className="flex items-center gap-2 text-xs font-mono">
          {health?.status === "healthy" ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-950/60 px-2.5 py-1 text-emerald-400 border border-emerald-800/60">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Engine Online</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-950/60 px-2.5 py-1 text-rose-400 border border-rose-800/60">
              <AlertCircle className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Degraded</span>
            </span>
          )}
        </div>
      </div>

      {/* Mobile / Tablet Tab Bar */}
      <div className="flex lg:hidden overflow-x-auto border-t border-slate-800/80 px-2 py-1.5 gap-1 bg-slate-900/60">
        {navItems.map((item) => {
          const isActive = activeTab === item.key;
          return (
            <button
              key={item.key}
              type="button"
              onClick={() => onSelectTab(item.key)}
              className={`flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                  : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          );
        })}
      </div>
    </header>
  );
};

