// Promoted out of Settings.tsx into its own top-level nav tab (2026-07 redesign pass) — the
// environment-attestation score is substantial enough on its own (7 checks, live re-scan) to
// deserve a dedicated page rather than living as one collapsed section among several in Settings.
import { useSecurityScan } from "../hooks/useSecurityScan";
import { SecureScorePanel } from "../components/SecureScorePanel";

export function Security() {
  const scan = useSecurityScan();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white font-sans">Security</h1>
        <p className="text-white/50 mt-1">Live environment attestation for this device and session.</p>
      </div>
      <SecureScorePanel scan={scan} />
    </div>
  );
}
