// Pre-Session Security Gate check definitions (docs/05-features-and-killer-features.md K1).
//
// De-simulation pass (2026-07): every check here is now either REAL or, where a genuine measurement
// is structurally impossible from a sandboxed web page (DNS resolver encryption status, network-level
// VPN/egress detection — both are OS/network-stack properties invisible to page JS, not something a
// browser API can honestly report), replaced a `Math.random()` coin-flip with a DETERMINISTIC, plainly
// -worded statement of that limitation. Rolling dice and calling it a security check was worse than
// admitting the limitation: a user reading "simulated" text next to a random pass/fail has no way to
// tell whether today's "pass" means anything. Nothing here draws a conclusion the current stack can't
// actually support.
import type { LucideIcon } from "lucide-react";
import { Bot, Clock, Cookie, Globe, Lock, Radio, Server, Sparkles } from "lucide-react";

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

// Same dev/prod split AuthCallback.tsx already established for the Enrollment Worker's public
// (unauthenticated) `/health` route — reused here rather than inventing a second convention.
const ENROLLMENT_API_URL = import.meta.env.DEV ? "http://localhost:8788" : "https://id.vort.xfeatures.net";

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

/**
 * REAL (2026-07, was random-simulated): a genuine HTTP round trip to the Enrollment Worker's public
 * `/health` route, comparing the local clock against the response's `Date` header. Honest limits,
 * stated rather than papered over: HTTP `Date` has only 1-second resolution, and this measures skew
 * against ONE edge/origin, not a dedicated time-sync service — good enough to catch a grossly wrong
 * local clock (the actual failure mode this check exists to catch, since PoW/nullifier epoch bucketing
 * depends on rough clock agreement — docs/05 K1 #4), not a precision NTP-grade measurement. If the
 * server doesn't send a `Date` header at all (observed in local `wrangler dev`/Miniflare, which
 * doesn't add one — real Cloudflare edge responses always do), this is reported as exactly that
 * limitation, not silently treated as "in sync."
 */
async function checkClock(): Promise<CheckResult> {
  const t0 = Date.now();
  let res: Response;
  try {
    res = await fetch(`${ENROLLMENT_API_URL}/health`);
  } catch {
    return { status: "warn", detail: `Could not reach ${ENROLLMENT_API_URL} to check clock skew` };
  }
  const t1 = Date.now();
  const dateHeader = res.headers.get("Date");
  if (!dateHeader) {
    return { status: "ok", detail: `Reachable (${t1 - t0}ms round-trip) — server sent no Date header to check skew against (expected in local dev)` };
  }
  const serverMs = Date.parse(dateHeader);
  if (Number.isNaN(serverMs)) {
    return { status: "warn", detail: "Server's Date header was unparseable" };
  }
  // Estimate the server's clock at the moment it responded as roughly the midpoint of the round
  // trip — a standard NTP-style correction for one-way latency, not a fabricated number.
  const midpoint = t0 + (t1 - t0) / 2;
  const skewMs = Math.round(midpoint - serverMs);
  return Math.abs(skewMs) < 2000
    ? { status: "ok", detail: `Clock within ~${Math.abs(skewMs)}ms of server time` }
    : { status: "warn", detail: `Clock skew of ~${skewMs}ms detected vs. server time` };
}

/**
 * REAL (2026-07, was random-simulated), reframed rather than faked: a browser genuinely cannot
 * observe which DNS resolver the OS used or whether that resolver speaks DoH/DoT — that's a
 * network-stack property with no web-exposed API (confirmed before writing this: neither `fetch`,
 * `Resource Timing`, nor any other page-JS-reachable API surfaces the resolver's identity or
 * transport). What a page CAN genuinely measure is this navigation's own DNS lookup latency via the
 * real Navigation Timing API (`domainLookupEnd - domainLookupStart`) — a real number, not a claim
 * about encryption. Renamed/reworded accordingly rather than keeping a misleading label on a
 * necessarily-fake result.
 */
async function checkDnsLatency(): Promise<CheckResult> {
  await wait(150); // let the navigation timing entry settle
  const [nav] = performance.getEntriesByType("navigation") as PerformanceNavigationTiming[];
  if (!nav || nav.domainLookupEnd <= 0) {
    return { status: "ok", detail: "DNS lookup timing unavailable in this environment (likely cached/prefetched by the browser)" };
  }
  const lookupMs = Math.round(nav.domainLookupEnd - nav.domainLookupStart);
  return lookupMs > 300
    ? { status: "warn", detail: `DNS lookup took ${lookupMs}ms for this page load — slower than typical` }
    : { status: "ok", detail: `DNS lookup took ${lookupMs}ms for this page load` };
}

/**
 * REAL (2026-07, was random-simulated): `navigator.webdriver` is a real, standard browser API that
 * is `true` when the page is being driven by automation (Selenium/Playwright/Puppeteer/CDP-based
 * tooling) — a genuine, deterministic signal, not a heuristic. Flagged as a warning, not critical:
 * plenty of legitimate reasons exist to run a browser under automation (this very check was verified
 * using one), so this is informational context for a security-conscious user, not a hard block.
 */
async function checkAutomation(): Promise<CheckResult> {
  await wait(150);
  const automated = typeof navigator !== "undefined" && navigator.webdriver === true;
  return automated
    ? { status: "warn", detail: "This browser is being controlled by automation (navigator.webdriver)" }
    : { status: "ok", detail: "No automation/remote-control flag detected" };
}

/**
 * REAL (2026-07, new check — "add more environment tests"): reports the browser's own
 * Global Privacy Control / Do Not Track signal, both real standardized APIs. Purely informational
 * (this app makes no tracking decisions either way) — always "ok", never penalizes the score, since
 * the ABSENCE of these signals says nothing about the environment's actual security.
 */
async function checkPrivacySignal(): Promise<CheckResult> {
  await wait(150);
  const nav = navigator as Navigator & { globalPrivacyControl?: boolean };
  if (nav.globalPrivacyControl) return { status: "ok", detail: "Global Privacy Control signal is active" };
  if (navigator.doNotTrack === "1") return { status: "ok", detail: "Do Not Track signal is active" };
  return { status: "ok", detail: "No GPC/DNT signal set (informational only — not a risk)" };
}

// ── honestly-unmeasurable-from-a-web-page, deterministic (no more Math.random) ─────────────────

/**
 * VPN / egress-ASN detection genuinely needs a server-side capability endpoint that inspects the
 * connecting IP (docs/05 K1 #1) — this Worker route doesn't exist yet (Phase 2+). A browser page has
 * no way to determine this about itself at all (there is no "am I behind a VPN" web API, and calling
 * a third-party IP-intelligence service from here would leak "this user is checking VPN status" to
 * that third party — against this project's own no-third-party-leak posture). Reports the real,
 * current state of that gap plainly instead of a random pass/fail.
 */
async function checkVpn(): Promise<CheckResult> {
  await wait(400);
  return { status: "warn", detail: "Not yet verifiable from this page — needs a server-side capability endpoint (Phase 2+), not built yet" };
}

export const CHECK_DEFS: CheckDef[] = [
  { id: "vpn", label: "VPN / Egress Exposure", icon: Globe, run: checkVpn },
  { id: "webrtc", label: "WebRTC Leak Protection", icon: Radio, run: checkWebRtc },
  { id: "dns", label: "DNS Lookup Latency", icon: Server, run: checkDnsLatency },
  { id: "clock", label: "Clock Synchronization", icon: Clock, run: checkClock },
  { id: "secure-context", label: "Secure Context", icon: Lock, run: checkSecureContext },
  { id: "rng", label: "RNG Health", icon: Sparkles, run: checkRng },
  { id: "automation", label: "Automation Detection", icon: Bot, run: checkAutomation },
  { id: "privacy-signal", label: "Privacy Signal (GPC/DNT)", icon: Cookie, run: checkPrivacySignal },
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
