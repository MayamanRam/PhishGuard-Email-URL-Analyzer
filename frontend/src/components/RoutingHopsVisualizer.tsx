import React from "react";
import { ArrowDown, AlertCircle, Clock } from "lucide-react";
import { RoutingHop } from "../types";

interface RoutingHopsVisualizerProps {
  hops: RoutingHop[];
}

export const RoutingHopsVisualizer: React.FC<RoutingHopsVisualizerProps> = ({ hops }) => {
  if (!hops || hops.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center text-slate-500 text-sm">
        No Received: headers recorded in email metadata.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {hops.map((hop, idx) => (
        <div key={hop.hop_number} className="relative">
          <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 shadow-sm hover:border-slate-700 transition">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2 mb-2">
              <div className="flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-950 text-cyan-400 font-mono text-xs font-bold border border-cyan-800">
                  {hop.hop_number}
                </span>
                <span className="text-xs font-semibold text-slate-300 font-mono">
                  {idx === 0 ? "Originating Relay (Client)" : idx === hops.length - 1 ? "Final Receiver MTA" : `Intermediate Hop #${hop.hop_number}`}
                </span>
              </div>

              <div className="flex items-center gap-2 text-xs font-mono">
                {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                  <span className="inline-flex items-center gap-1 text-slate-400">
                    <Clock className="h-3 w-3 text-slate-500" />
                    +{hop.delay_seconds.toFixed(1)}s delay
                  </span>
                )}
                {hop.ip_address && (
                  <span
                    className={`px-2 py-0.5 rounded text-xs border ${
                      hop.is_private_ip
                        ? "bg-slate-800 text-slate-300 border-slate-700"
                        : "bg-blue-950/60 text-blue-300 border-blue-800/60"
                    }`}
                  >
                    {hop.ip_address} ({hop.is_private_ip ? "RFC 1918 Private" : "Public IP"})
                  </span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-400">
              <div>
                <span className="text-slate-500 font-mono">From: </span>
                <span className="text-slate-300 font-mono">{hop.from_host || "unknown"}</span>
              </div>
              <div>
                <span className="text-slate-500 font-mono">By: </span>
                <span className="text-slate-300 font-mono">{hop.by_host || "unknown"}</span>
              </div>
              {hop.timestamp_raw && (
                <div className="col-span-full">
                  <span className="text-slate-500 font-mono">Header Date: </span>
                  <span className="text-slate-400 font-mono">{hop.timestamp_raw}</span>
                </div>
              )}
            </div>

            {/* Hop Anomalies */}
            {hop.anomalies && hop.anomalies.length > 0 && (
              <div className="mt-2.5 rounded-lg border border-amber-900/60 bg-amber-950/20 p-2 text-xs text-amber-300 flex items-start gap-1.5">
                <AlertCircle className="h-3.5 w-3.5 text-amber-400 shrink-0 mt-0.5" />
                <span>{hop.anomalies.join("; ")}</span>
              </div>
            )}
          </div>

          {/* Connector arrow between hops */}
          {idx < hops.length - 1 && (
            <div className="flex justify-center my-1 text-slate-600">
              <ArrowDown className="h-4 w-4" />
            </div>
          )}
        </div>
      ))}
    </div>
  );
};
