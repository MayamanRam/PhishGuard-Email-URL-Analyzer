import React from "react";
import { RiskLevel } from "../types";

interface SeverityBadgeProps {
  severity: RiskLevel | string;
  size?: "sm" | "md" | "lg";
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = "md" }) => {
  const sevLower = (severity || "low").toLowerCase();

  let colorClasses = "bg-emerald-950/60 text-emerald-400 border-emerald-800/60";
  let dotColor = "bg-emerald-400";

  if (sevLower === "moderate" || sevLower === "medium") {
    colorClasses = "bg-amber-950/60 text-amber-300 border-amber-800/60";
    dotColor = "bg-amber-400";
  } else if (sevLower === "high") {
    colorClasses = "bg-orange-950/60 text-orange-400 border-orange-800/60";
    dotColor = "bg-orange-400";
  } else if (sevLower === "critical") {
    colorClasses = "bg-rose-950/70 text-rose-300 border-rose-800/80 animate-pulse";
    dotColor = "bg-rose-400";
  }

  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs font-mono",
    md: "px-2.5 py-1 text-xs font-mono font-medium",
    lg: "px-3 py-1.5 text-sm font-mono font-semibold",
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border uppercase tracking-wider ${colorClasses} ${sizeClasses}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${dotColor}`} />
      {severity}
    </span>
  );
};

