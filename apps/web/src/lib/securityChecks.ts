// Pre-Session Security Gate check definitions (docs/05-features-and-killer-features.md K1).
// Each check returns a real result where the browser genuinely allows one synchronously/locally
// (secure context, RNG health, a best-effort WebRTC ICE probe); the rest are honestly simulated
// placeholders, clearly marked, for checks that need a server round-trip (VPN/egress, per docs/05
// check #1 — needs the Messaging Plane's capability endpoint, not built yet) or native APIs
// unavailable on web (Capacitor plugins land in Phase 4 per docs/06). This file draws no
// conclusions the current stack can't actually support yet.
import type { LucideIcon } from "lucide-react";
import { Clock, Globe, Lock, Radio, Server, Sparkles } from "lucide-react";

export type CheckStatus = "pending" | "checking" | "ok" | "warn" | "critical";

export interface CheckResult {
  status: Exclude<CheckStatus, "pending" | "checking">;
  detail: string;
}

export interface CheckDef {
  id: string;
  label: string;
  icon: LucideIcon;
  run: () => Promise<CheckResult>;
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── real checks ─────────────────────────────────────────────────────────────────────────────

async function checkSecureContext(): Promise<CheckResult> {
  await wait(350);
  const secure = typeof window !== "undefined" && window.isSecureContext;
  return secure
    ? { status: "ok", detail: "HTTPS / secure context confirmed" }
    : { status: "critical", detail: "Insecure context — do not proceed" };
}

async function checkRng(): Promise<CheckResult> {
  await wait(300);
  try {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    const allZero = buf.every((b) => b === 0);
    return allZero
      ? { status: "critical", detail: "CSPRNG returned all-zero output" }
      : { status: "ok", detail: "crypto.getRandomValues() healthy" };
  } catch {
    return { status: "critical", detail: "crypto.getRandomValues() unavailable" };
  }
}

/**
 * Best-effort real WebRTC probe: gathers actual ICE candidates via RTCPeerConnection and flags a
 * "host" (local-network) candidate as a leak signal. This is a simplified heuristic, not a full
 * public-IP comparison (that needs a server round trip) — good enough to demonstrate the real
 * mechanism docs/05 describes, not yet the production-grade version.
 */
function checkWebRtc(): Promise<CheckResult> {
  return new Promise((resolve) => {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      const candidates: string[] = [];
      let settled = false;
      const finish = (result: CheckResult) => {
        if (settled) return;
        settled = true;
        pc.close();
        resolve(result);
      };
      pc.onicecandidate = (e) => {
        if (e.candidate) candidates.push(e.candidate.candidate);
      };
      pc.createDataChannel("probe");
      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(() => finish({ status: "warn", detail: "Unable to probe WebRTC in this environment" }));
      setTimeout(() => {
        const hostLeak = candidates.some((c) => c.includes("typ host") && /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(c));
        finish(
          hostLeak
            ? { status: "warn", detail: "A host ICE candidate exposes a local network address" }
            : { status: "ok", detail: "No host-candidate leak detected" },
        );
      }, 900);
    } catch {
      resolve({ status: "warn", detail: "WebRTC unavailable in this environment" });
    }
  });
}

// ── simulated checks (honestly labeled — need infra this stack doesn't have wired up yet) ─────

async function checkVpn(): Promise<CheckResult> {
  // TODO(Phase 2+): real egress-ASN check needs a round trip through the Messaging Plane's
  // capability endpoint (docs/05 K1 #1), which doesn't exist yet. Simulated for this layout pass.
  await wait(700);
  return Math.random() > 0.4
    ? { status: "ok", detail: "Egress does not match a known datacenter/residential leak pattern (simulated)" }
    : { status: "warn", detail: "Your IP may be visible to network observers — consider a VPN (simulated)" };
}

async function checkDns(): Promise<CheckResult> {
  // TODO(Phase 2+): real check is a DoH probe against a trusted resolver (docs/05 K1 #3).
  await wait(600);
  return Math.random() > 0.35
    ? { status: "ok", detail: "Resolver appears to use encrypted DNS (simulated)" }
    : { status: "warn", detail: "Resolver may be your ISP's plaintext DNS (simulated)" };
}

async function checkClock(): Promise<CheckResult> {
  // TODO(Phase 2+): real check compares against signed edge time from the Messaging Worker
  // (docs/05 K1 #4) — the epoch-bucketed ZK nullifier/PoW windows depend on this being accurate.
  await wait(500);
  const skewMs = Math.round((Math.random() - 0.5) * 4000);
  return Math.abs(skewMs) < 1500
    ? { status: "ok", detail: `Clock within ${Math.abs(skewMs)}ms of expected (simulated)` }
    : { status: "warn", detail: `Clock skew of ${skewMs}ms detected (simulated)` };
}

export const CHECK_DEFS: CheckDef[] = [
  { id: "vpn", label: "VPN / Egress Exposure", icon: Globe, run: checkVpn },
  { id: "webrtc", label: "WebRTC Leak Protection", icon: Radio, run: checkWebRtc },
  { id: "dns", label: "DNS Resolver Quality", icon: Server, run: checkDns },
  { id: "clock", label: "Clock Synchronization", icon: Clock, run: checkClock },
  { id: "secure-context", label: "Secure Context", icon: Lock, run: checkSecureContext },
  { id: "rng", label: "RNG Health", icon: Sparkles, run: checkRng },
];

const STATUS_POINTS: Record<CheckStatus, number> = { ok: 100, warn: 55, critical: 15, pending: 0, checking: 0 };

export function scoreFromStatus(status: CheckStatus): number {
  return STATUS_POINTS[status];
}

export function tierFromScore(score: number): "ok" | "warn" | "critical" {
  if (score >= 80) return "ok";
  if (score >= 50) return "warn";
  return "critical";
}
