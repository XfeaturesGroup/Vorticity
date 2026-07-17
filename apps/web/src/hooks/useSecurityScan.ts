// Encapsulates the Pre-Session Security Gate's scan state machine (docs/05 K1) so it can be
// reused anywhere — the standalone full-screen gate at "/" and, e.g., an embedded status widget
// inside Settings — without duplicating the run/score logic in each call site.
import { useEffect, useMemo, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { CHECK_DEFS, scoreFromStatus, tierFromScore, type CheckStatus } from "../lib/securityChecks";

export interface CheckState {
  id: string;
  label: string;
  icon: LucideIcon;
  status: CheckStatus;
  detail: string;
}

export interface SecurityScan {
  checks: CheckState[];
  score: number | null;
  scanning: boolean;
  tier: "ok" | "warn" | "critical" | null;
  okCount: number;
  warnCount: number;
  criticalCount: number;
  rerun: () => void;
}

function initialChecks(): CheckState[] {
  return CHECK_DEFS.map((d) => ({ id: d.id, label: d.label, icon: d.icon, status: "pending", detail: "" }));
}

export function useSecurityScan(): SecurityScan {
  const [checks, setChecks] = useState<CheckState[]>(initialChecks);
  const runToken = useRef(0);

  const runScan = () => {
    const token = ++runToken.current;
    setChecks(initialChecks());

    (async () => {
      for (const def of CHECK_DEFS) {
        if (runToken.current !== token) return; // a newer scan superseded this one
        setChecks((prev) => prev.map((c) => (c.id === def.id ? { ...c, status: "checking" } : c)));
        const result = await def.run();
        if (runToken.current !== token) return;
        setChecks((prev) => prev.map((c) => (c.id === def.id ? { ...c, status: result.status, detail: result.detail } : c)));
      }
    })();
  };

  useEffect(() => {
    // Each mount gets its own scan (e.g. the gate page and a Settings widget instance both run
    // independently); `runToken` makes React 19 StrictMode's dev-only double-invoke a no-op
    // rather than a race between two overlapping runs.
    runScan();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const resolvedChecks = useMemo(
    () =>
      checks.filter(
        (c): c is CheckState & { status: "ok" | "warn" | "critical" } =>
          c.status === "ok" || c.status === "warn" || c.status === "critical",
      ),
    [checks],
  );
  const score =
    resolvedChecks.length === 0 ? null : Math.round(resolvedChecks.reduce((sum, c) => sum + scoreFromStatus(c.status), 0) / resolvedChecks.length);

  return {
    checks,
    score,
    scanning: checks.some((c) => c.status === "pending" || c.status === "checking"),
    tier: score === null ? null : tierFromScore(score),
    okCount: resolvedChecks.filter((c) => c.status === "ok").length,
    warnCount: resolvedChecks.filter((c) => c.status === "warn").length,
    criticalCount: resolvedChecks.filter((c) => c.status === "critical").length,
    rerun: runScan,
  };
}
