import React from "react";
import { HelpCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import { RiskLevel } from "../types";
import { SeverityBadge } from "./SeverityBadge";

interface ScoreGaugeProps {
  score: number;
  severity: RiskLevel;
  onExplainClick?: () => void;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, severity, onExplainClick }) => {
  const roundedScore = Math.round(score);

  let barColor = "bg-emerald-500";
  let textColor = "text-emerald-400";
  if (severity === "moderate") {
    barColor = "bg-amber-500";
    textColor = "text-amber-400";
  } else if (severity === "high") {
    barColor = "bg-orange-500";
    textColor = "text-orange-400";
  } else if (severity === "critical") {
    barColor = "bg-rose-500";
    textColor = "text-rose-400";
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-lg backdrop-blur">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {score >= 60 ? (
            <ShieldAlert className="h-5 w-5 text-rose-400" />
          ) : (
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
          )}
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
            Phishing Risk Assessment
          </span>
        </div>
        <SeverityBadge severity={severity} size="sm" />
      </div>

      <div className="my-4 flex items-baseline gap-2">
        <span className={`text-5xl font-black tracking-tight font-mono ${textColor}`}>
          {roundedScore}
        </span>
        <span className="text-sm font-semibold text-slate-500 font-mono">/ 100</span>
      </div>

      {/* Progress Bar */}
      <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full transition-all duration-700 ease-out ${barColor}`}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>

      <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
        <span>Diminishing returns scaled</span>
        {onExplainClick && (
          <button
            type="button"
            onClick={onExplainClick}
            className="inline-flex items-center gap-1 font-medium text-cyan-400 hover:text-cyan-300 hover:underline"
          >
            <HelpCircle className="h-3.5 w-3.5" />
            How is this calculated?
          </button>
        )}
      </div>
    </div>
  );
};

