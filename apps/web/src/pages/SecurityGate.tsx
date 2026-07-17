// Pre-Session Security Gate (Killer Feature K1, docs/05-features-and-killer-features.md).
// Deliberately standalone — no Sidebar/AppLayout. The user hasn't authenticated yet, so there is
// nothing app-shell-shaped to show them: this is the "airlock" screen before OAuth, centered on
// its own, with no navigation out except forward through Proceed.
import { Shield } from "lucide-react";
import { Button, NoiseOverlay } from "@vorticity/ui";
import { useSecurityScan } from "../hooks/useSecurityScan";
import { SecureScorePanel } from "../components/SecureScorePanel";
import { generateCodeChallenge, generateCodeVerifier, PKCE_VERIFIER_KEY } from "../lib/pkce";

// Mock client_id for this Phase 4 layout pass — see docs/legacy-reference/README.md for the real
// client_id (`xf_9116480c21a94a849a1182717e35f335`) already wired into workers/enrollment's
// wrangler.toml; swap this in once apps/web's enrollment flow is actually built. PKCE params
// (code_challenge/code_challenge_method) are NOT mocked, though — the real IDM rejects requests
// without them (confirmed live: "Authorization Error: PKCE ... is required"), so this must be a
// real challenge derived from a real verifier every time, not a placeholder.
const OAUTH_AUTHORIZE_URL = "https://account.xfeatures.net/oauth/authorize";

export function SecurityGate() {
  const scan = useSecurityScan();

  const handleProceed = async () => {
    const codeVerifier = generateCodeVerifier();
    sessionStorage.setItem(PKCE_VERIFIER_KEY, codeVerifier);
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    const params = new URLSearchParams({
      client_id: "xf_9116480c21a94a849a1182717e35f335",
      response_type: "code",
      redirect_uri: `${window.location.origin}/auth/callback`,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    window.location.href = `${OAUTH_AUTHORIZE_URL}?${params.toString()}`;
  };

  return (
    <div className="relative min-h-screen bg-black flex items-center justify-center p-6">
      <NoiseOverlay />
      <div className="relative w-full max-w-3xl space-y-8 py-12">
        <div className="flex flex-col items-center gap-3 text-center">
          <Shield className="w-16 h-16 text-fluid-peach" />
          <span className="font-serif text-4xl tracking-tight text-white">Vorticity</span>
          <p className="text-white/50 text-sm max-w-md">Environment attestation before every new session.</p>
        </div>

        <SecureScorePanel scan={scan} />

        <div className="flex justify-center pt-2">
          <Button
            variant="primary"
            disabled={scan.scanning}
            onClick={handleProceed}
            className={
              scan.scanning
                ? "px-10 py-4 text-base font-bold"
                : "px-10 py-4 text-base font-bold bg-fluid-peach/90 hover:bg-fluid-peach border-fluid-peach/40 text-black"
            }
          >
            {scan.scanning ? "Scanning…" : "Proceed to Auth"}
          </Button>
        </div>
      </div>
    </div>
  );
}
