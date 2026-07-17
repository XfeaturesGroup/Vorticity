// Placeholder — Phase 4. The Security Status section below demonstrates that SecureScorePanel is
// a genuinely reusable widget, not just markup baked into the standalone gate page: same
// component + hook, embedded here instead of full-screen, running its own independent scan.
import { useSecurityScan } from "../hooks/useSecurityScan";
import { SecureScorePanel } from "../components/SecureScorePanel";

export function Settings() {
  const scan = useSecurityScan();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white font-sans">Settings</h1>
        <p className="text-white/50 mt-1">Not implemented yet — Phase 4.</p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Security Status</h2>
        <SecureScorePanel scan={scan} compact />
      </div>
    </div>
  );
}
