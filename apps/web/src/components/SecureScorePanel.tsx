// Reusable presentational widget for the Pre-Session Security Gate (docs/05 K1) — the
// score ring + KPI cards + detailed checks list, with no page-level navigation logic (that lives
// in whichever page embeds this: pages/SecurityGate.tsx for the full-screen gate, or e.g.
// Settings.tsx for an in-app status widget). Card/grid markup copied from Xfeatures HQ's
// business/Economy.tsx — see docs/07-ui-design-system.md.
import type { ReactElement } from "react";
import { AlertTriangle, CheckCircle2, Circle, Loader2, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { Button } from "@vorticity/ui";
import type { CheckStatus } from "../lib/securityChecks";
import type { SecurityScan } from "../hooks/useSecurityScan";

const TIER_COLOR: Record<"ok" | "warn" | "critical", string> = {
  ok: "var(--color-signal-success)",
  warn: "var(--color-signal-warning)",
  critical: "var(--color-signal-danger)",
};

function ScoreRing({ score, size = 144 }: { score: number | null; size?: number }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const pct = score ?? 0;
  const offset = circumference * (1 - pct / 100);
  const tier = score === null ? null : score >= 80 ? "ok" : score >= 50 ? "warn" : "critical";
  const strokeColor = tier ? TIER_COLOR[tier] : "var(--color-fluid-peach)";

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 140 140" className="-rotate-90" style={{ width: size, height: size }}>
        <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" />
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.6s var(--ease-house), stroke 0.4s" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold text-white font-sans">{score === null ? "--" : score}</span>
        <span className="text-[10px] text-white/50 uppercase tracking-widest">/ 100</span>
      </div>
    </div>
  );
}

const STATUS_ICON: Record<CheckStatus, ReactElement> = {
  pending: <Circle className="w-5 h-5 text-white/20" />,
  checking: <Loader2 className="w-5 h-5 text-fluid-peach animate-spin" />,
  ok: <CheckCircle2 className="w-5 h-5 text-signal-success" />,
  warn: <AlertTriangle className="w-5 h-5 text-signal-warning" />,
  critical: <XCircle className="w-5 h-5 text-signal-danger" />,
};

interface SecureScorePanelProps {
  scan: SecurityScan;
  /** Tighter spacing/ring for embedding inside another page's layout (e.g. Settings). */
  compact?: boolean;
}

export function SecureScorePanel({ scan, compact = false }: SecureScorePanelProps) {
  const { checks, score, scanning, tier, okCount, warnCount, criticalCount, rerun } = scan;

  return (
    <div className={compact ? "space-y-4" : "space-y-6"}>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-2 vx-glass-dimmable p-6 rounded-2xl border border-white/10 shadow-glass flex items-center gap-6">
          <ScoreRing score={score} size={compact ? 112 : 144} />
          <div>
            <h3 className="text-white/50 text-sm font-medium">Vorticity Secure Score</h3>
            <p className="text-white/70 text-sm mt-1 max-w-xs">
              {scanning
                ? "Running environment attestation…"
                : tier === "ok"
                  ? "Environment looks safe to proceed."
                  : tier === "warn"
                    ? "Some risks found — review before proceeding."
                    : tier === "critical"
                      ? "Critical risk detected — fix before proceeding."
                      : ""}
            </p>
          </div>
        </div>

        <div className="vx-glass-dimmable p-5 rounded-2xl border border-white/10 shadow-glass">
          <div className="flex justify-between items-start mb-4">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-signal-success/10">
              <ShieldCheck className="w-5 h-5 text-signal-success" />
            </div>
          </div>
          <h3 className="text-white/50 text-sm font-medium">Checks Passed</h3>
          <p className="text-3xl font-bold text-white mt-1 font-sans">{okCount}</p>
        </div>

        <div className="vx-glass-dimmable p-5 rounded-2xl border border-white/10 shadow-glass">
          <div className="flex justify-between items-start mb-4">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-signal-warning/10">
              <ShieldAlert className="w-5 h-5 text-signal-warning" />
            </div>
          </div>
          <h3 className="text-white/50 text-sm font-medium">Warnings / Critical</h3>
          <p className="text-3xl font-bold text-white mt-1 font-sans">
            {warnCount}
            <span className="text-white/30"> / </span>
            {criticalCount}
          </p>
        </div>
      </div>

      <div className="vx-glass-dimmable rounded-2xl border border-white/10 p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-white/70 font-semibold">Environment Checks</h3>
          <Button variant="ghost" onClick={rerun} disabled={scanning}>
            Re-run Scan
          </Button>
        </div>
        <div className="divide-y divide-white/5">
          {checks.map((check) => (
            <div key={check.id} className="flex items-center gap-4 py-3">
              <div className="w-9 h-9 rounded-lg bg-white/5 flex items-center justify-center shrink-0">
                <check.icon className="w-4 h-4 text-white/60" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-white">{check.label}</div>
                <div className="text-xs text-white/50 truncate">
                  {check.status === "pending" ? "Waiting…" : check.status === "checking" ? "Checking…" : check.detail}
                </div>
              </div>
              <div className="shrink-0">{STATUS_ICON[check.status]}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
