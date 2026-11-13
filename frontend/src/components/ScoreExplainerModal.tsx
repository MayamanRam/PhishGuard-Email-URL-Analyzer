import React from "react";
import { X, Calculator, ShieldCheck } from "lucide-react";
import { CategoryScoreDetail, TriggeredFinding } from "../types";

interface ScoreExplainerModalProps {
  isOpen: boolean;
  onClose: () => void;
  finalScore: number;
  severity: string;
  formulaExplanation: string;
  categoryDetails: CategoryScoreDetail[];
  findings?: TriggeredFinding[];
}

export const ScoreExplainerModal: React.FC<ScoreExplainerModalProps> = ({
  isOpen,
  onClose,
  finalScore,
  severity,
  formulaExplanation,
  categoryDetails,
  findings = [],
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl text-slate-200">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <Calculator className="h-6 w-6 text-cyan-400" />
            <h2 className="text-lg font-bold text-white tracking-wide">
              Explainable Risk Scoring Methodology
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="my-5 space-y-4">
          {/* Executive Verdict Box */}
          <div className="rounded-xl border border-cyan-900/50 bg-cyan-950/20 p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs uppercase font-mono tracking-wider text-cyan-400">
                Final Calculated Score
              </span>
              <span className="font-mono text-xl font-black text-cyan-300">
                {finalScore.toFixed(1)} / 100 ({severity.toUpperCase()})
              </span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              {formulaExplanation}
            </p>
          </div>

          {/* Mathematical Formula Explanation */}
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 font-mono mb-2">
              1. Category Diminishing Returns Formula
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed mb-3">
              To prevent a single heuristic (e.g. an unusual domain or urgent word) from artificially inflating the score into a critical phishing tier, scores are calculated per threat category using asymptotic diminishing returns:
            </p>
            <div className="rounded-lg bg-slate-950 p-3 font-mono text-xs text-emerald-400 border border-slate-800">
              S_c = Cap_c × [ 1 - Π (1 - (Weight_r × Confidence_r) / (Cap_c + 15)) ]
            </div>
          </div>

          {/* Category Breakdown Table */}
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 font-mono mb-2">
              2. Category Contributions & Caps
            </h3>
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="p-2.5">Category</th>
                    <th className="p-2.5">Rules Triggered</th>
                    <th className="p-2.5">Raw Sum</th>
                    <th className="p-2.5">Category Cap</th>
                    <th className="p-2.5 text-right">Scaled Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-900">
                  {categoryDetails.map((cat) => (
                    <tr key={cat.category} className="hover:bg-slate-800/40">
                      <td className="p-2.5 font-bold text-white">{cat.category}</td>
                      <td className="p-2.5 text-slate-300">{cat.rules_triggered_count}</td>
                      <td className="p-2.5 text-slate-400">{cat.raw_rule_sum.toFixed(1)}</td>
                      <td className="p-2.5 text-slate-400">{cat.category_cap.toFixed(1)}</td>
                      <td className="p-2.5 text-right font-bold text-cyan-400">
                        +{cat.diminishing_score.toFixed(1)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Corroboration Guardrail */}
          <div className="rounded-xl border border-slate-800 bg-slate-950 p-3.5 text-xs text-slate-300 flex items-start gap-2.5">
            <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white">Corroboration Safeguard: </span>
              A score above 85 (Critical) cannot be achieved by a single isolated vector. A critical classification requires corroborated signals across at least two distinct threat categories or multiple high-severity findings.
            </div>
          </div>

          {findings.length > 0 && (
            <div className="text-[11px] font-mono text-slate-400">
              Evaluated {findings.length} triggered detection rules across categories.
            </div>
          )}
        </div>

        <div className="mt-6 flex justify-end border-t border-slate-800 pt-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-medium text-white hover:bg-slate-700 transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
