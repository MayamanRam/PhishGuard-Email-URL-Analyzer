import React from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle, Info, KeyRound, Lock } from "lucide-react";
import { AuthClaimDetail } from "../types";

interface AuthClaimsBadgeProps {
  spf: AuthClaimDetail;
  dkim: AuthClaimDetail;
  dmarc: AuthClaimDetail;
  verdict: string;
  warnings?: string[];
  disclaimer?: string;
  dkimOffline?: {
    status: string;
    verified: boolean;
    message: string;
    selector?: string | null;
    signing_domain?: string | null;
  } | null;
}

export const AuthClaimsBadge: React.FC<AuthClaimsBadgeProps> = ({
  spf,
  dkim,
  dmarc,
  verdict,
  warnings = [],
  disclaimer,
  dkimOffline,
}) => {
  const renderStatus = (res: string) => {
    const val = (res || "missing").toLowerCase();
    if (val === "pass") {
      return (
        <span className="inline-flex items-center gap-1 rounded bg-emerald-950/70 px-2 py-0.5 text-xs font-mono font-medium text-emerald-400 border border-emerald-800/60">
          <ShieldCheck className="h-3 w-3" /> PASS
        </span>
      );
    }
    if (val === "fail") {
      return (
        <span className="inline-flex items-center gap-1 rounded bg-rose-950/70 px-2 py-0.5 text-xs font-mono font-medium text-rose-400 border border-rose-800/60">
          <ShieldAlert className="h-3 w-3" /> FAIL
        </span>
      );
    }
    if (val === "softfail") {
      return (
        <span className="inline-flex items-center gap-1 rounded bg-amber-950/70 px-2 py-0.5 text-xs font-mono font-medium text-amber-300 border border-amber-800/60">
          <AlertTriangle className="h-3 w-3" /> SOFTFAIL
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-400 border border-slate-700">
        MISSING / NONE
      </span>
    );
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-sm space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
          Authentication Header Claims
        </h3>
        <span className="inline-flex items-center gap-1 rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-mono text-slate-400">
          <Info className="h-3 w-3 text-cyan-400" />
          Verdict: {verdict ? verdict.toUpperCase() : "UNVERIFIED"}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* SPF */}
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-300">SPF</span>
            {renderStatus(spf.result)}
          </div>
          <div className="text-[11px] text-slate-400 font-mono truncate" title={spf.sender_domain || spf.raw_claim || ""}>
            {spf.sender_domain ? `Domain: ${spf.sender_domain}` : "No sender domain"}
          </div>
        </div>

        {/* DKIM */}
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-300">DKIM</span>
            {renderStatus(dkim.result)}
          </div>
          <div className="text-[11px] text-slate-400 font-mono truncate" title={dkim.signing_domain || dkim.raw_claim || ""}>
            {dkim.signing_domain ? `Signer: ${dkim.signing_domain}` : "No signature domain"}
          </div>
        </div>

        {/* DMARC */}
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-300">DMARC</span>
            {renderStatus(dmarc.result)}
          </div>
          <div className="text-[11px] text-slate-400 font-mono truncate" title={dmarc.action_taken || dmarc.raw_claim || ""}>
            {dmarc.action_taken ? `Policy: ${dmarc.action_taken}` : "No policy action"}
          </div>
        </div>
      </div>

      {dkimOffline && (
        <div
          className={`rounded-lg border p-3 text-xs space-y-1.5 ${
            dkimOffline.status === "PASS"
              ? "border-emerald-800/80 bg-emerald-950/30 text-emerald-300"
              : dkimOffline.status === "FAIL"
              ? "border-rose-800/80 bg-rose-950/30 text-rose-300"
              : "border-slate-800 bg-slate-950/40 text-slate-400"
          }`}
        >
          <div className="flex items-center gap-2 font-mono font-semibold">
            {dkimOffline.status === "PASS" ? (
              <KeyRound className="h-4 w-4 text-emerald-400 shrink-0" />
            ) : dkimOffline.status === "FAIL" ? (
              <ShieldAlert className="h-4 w-4 text-rose-400 shrink-0" />
            ) : (
              <Lock className="h-4 w-4 text-slate-400 shrink-0" />
            )}
            <span>
              Offline DKIM Cryptographic Verification:{" "}
              <span className="uppercase">{dkimOffline.status}</span>
            </span>
          </div>
          <p className="text-[11px] leading-relaxed opacity-90 pl-6">
            {dkimOffline.message}
          </p>
        </div>
      )}

      {warnings && warnings.length > 0 && (
        <div className="rounded-lg border border-amber-900/50 bg-amber-950/20 p-3 text-xs text-amber-300 space-y-1">
          {warnings.map((w, idx) => (
            <div key={idx} className="flex items-start gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      {disclaimer && (
        <p className="text-[11px] text-slate-500 italic leading-relaxed">
          {disclaimer}
        </p>
      )}
    </div>
  );
};
