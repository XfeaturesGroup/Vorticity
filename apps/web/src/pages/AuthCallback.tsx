// OAuth callback landing page — now a fully real enrollment pipeline, no setTimeout mocks:
//   Step 1 "Exchanging OAuth Token"      — REAL PKCE exchange at workers/enrollment POST /oauth/callback
//                                          (real Xfeatures IDM, PPID, sybil-guard upsert in DB_ENROLL).
//   Step 2 "Blinding Identity (RSABSSA)" — REAL RSA blind signature blind() (RFC 9474) of a random
//                                          identity message via the vortic-core WASM (`blindSigBlind`).
//                                          Replaces the earlier VOPRF-based blinding — see
//                                          packages/vortic-core/src/blind_sig.rs's module doc for why
//                                          (a VOPRF evaluation can't be verified by a third party
//                                          without a shared secret; an RSA signature can, with only
//                                          the issuer's PUBLIC key).
//   Step 3 "Issuing Redemption Token"    — REAL POST /token/issue: the Enrollment Worker blind-signs
//                                          the blinded message under its RSA-3072 secret key; the
//                                          client finalizes (`blindSigFinalize`) into a real,
//                                          verifiable `(msg, sig, msgRandomizer)` redemption token
//                                          (finalize also self-verifies, so a dishonest issuer's bad
//                                          signature is caught here, not later).
//   Step 4 "Joining Membership Set"      — REAL POST /membership/insert (Messaging Worker, port 8787):
//                                          Messaging verifies the redemption token against the
//                                          issuer's PUBLIC key (no shared secret — see
//                                          workers/messaging/src/issuer-keys.ts), then inserts a
//                                          random Semaphore `commitment` into MerkleTreeDO and
//                                          returns the Merkle root.
//   Step 5 "Proving Membership (ZK)"     — REAL POST /auth/session: a genuine Groth16 proof (R23,
//                                          2026-07) generated IN-BROWSER via snarkjs against the
//                                          official PSE ceremony `semaphore-20.wasm`/`.zkey`
//                                          (`public/zk/`, see `../lib/zkProof.ts`) for the identity
//                                          just inserted in step 4. The Worker runs the real WASM
//                                          verifier (zk.rs) and, on true, mints a signed session
//                                          `capability` — which becomes the login token.
// Real client-side proving (`zkProof.ts`) now works for a tree of any size: after step 4 inserts this
// identity's commitment, this page fetches the identity's own real Merkle proof from the Worker's
// `GET /membership/proof/:commitment` (backed by `MerkleTreeDO`'s `/proof/` route — commitments are
// public by Semaphore's own design, so this needs no capability gate any more than `/root` does) before
// generating the ZK proof.
// Honest remaining gaps: the identity message (RSABSSA redemption token) is random-per-session (a real
// deployment derives it from a stable identity so re-enrollment/replay across sessions is detectable);
// and there's no ratchet/PQ hybrid in the chat cipher yet.
import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { CheckCircle2, Circle, Loader2, Shield, XCircle } from "lucide-react";
import { Button, NoiseOverlay, cn } from "@vorticity/ui";
import { initCrypto, blindSigBlind, blindSigFinalize, blindSigRandomizer } from "@vorticity/vortic-core";
import { useAuth } from "../contexts/AuthContext";
import { PKCE_VERIFIER_KEY } from "../lib/pkce";
import { ISSUER_PK_PEM } from "../lib/issuerKey";
import { Identity, proveMembershipSession, type MerkleProofResponse } from "../lib/zkProof";
import { ohttpFetch } from "../lib/ohttp";

const STEPS = [
  "Exchanging OAuth Token",
  "Blinding Identity (RSABSSA)",
  "Issuing Redemption Token",
  "Joining Membership Set",
  "Proving Membership (ZK)",
];

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function fieldToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

interface TokenIssueResponse {
  blindSig: string;
}

interface MembershipInsertResponse {
  merkleRoot: string;
  size: number;
}
interface SessionResponse {
  capability: string;
}

// Dev: local `wrangler dev` instance of workers/enrollment. Prod: not actually deployed anywhere
// yet (same honest caveat as workers/messaging's placeholder host) — `id.vort.xfeatures.net`
// mirrors the redirect host already hardcoded into that Worker's wrangler.toml for symmetry with
// the messaging Worker's `api.vort.xfeatures.net` naming, not a live endpoint.
const ENROLLMENT_API_URL = import.meta.env.DEV ? "http://localhost:8788" : "https://id.vort.xfeatures.net";
// Messaging Plane (Flow 1 membership insert + Flow 2 ZK session) calls no longer hit this Worker's
// origin directly — R25 (2026-07) routes them through real OHTTP (../lib/ohttp.ts's `ohttpFetch`,
// itself pointed at workers/ohttp-relay). No `MESSAGING_API_URL` constant is needed here any more.

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function AuthCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useAuth();
  const [stepIndex, setStepIndex] = useState(0);
  const [networkError, setNetworkError] = useState<string | null>(null);
  // Monotonic run-id, NOT a boolean "already started" guard (see useSecurityScan.ts's `runToken`
  // for the same pattern). A boolean guard is wrong here: React 19 StrictMode's dev-only
  // mount->cleanup->remount happens synchronously, so the FIRST effect run gets cancelled before
  // its first `await` resolves, and a boolean guard would then block the SECOND (real, lasting)
  // run from ever starting — the steps would freeze at step 1 forever. Confirmed live: this was
  // an actual bug caught by browser testing, not a hypothetical.
  const runId = useRef(0);
  // Caches the one-time PKCE verifier across React 19 StrictMode's dev-only double-invoke of this
  // effect. `sessionStorage.removeItem` below is a real side effect (consuming a single-use value)
  // that must only happen once — but it ran unconditionally on the FIRST (soon-to-be-cancelled)
  // invocation, deleting the key before the SECOND (real, lasting) invocation could read it. Found
  // live: the callback surfaced "Missing PKCE code_verifier" even though the network tab showed a
  // real POST to /oauth/callback had already fired with a valid one. `readOnceRef` makes the
  // read+remove happen exactly once per mount; every invocation after that reuses the cached value
  // instead of re-touching sessionStorage.
  const readOnceRef = useRef(false);
  const codeVerifierRef = useRef<string | null>(null);
  // The token exchange must fire EXACTLY ONCE, even though React 19 StrictMode double-invokes this
  // effect in dev. An OAuth authorization `code` is single-use: sending it twice makes the two
  // requests RACE to consume the same code at the IDM — one wins (200), the loser hits a
  // mid-consumption code and the real IDM answers that race unpredictably (observed live: usually a
  // clean `invalid_grant` 502, but intermittently a 500 / dropped connection). The runId/token
  // pattern below correctly cancels stale *UI*, but it does NOT stop the second invocation from
  // firing its own fetch (confirmed live: two `[DEBUG] ENTER` lines in the Worker log for one
  // navigation). So the fetch itself is deduped here: the first invocation to reach this point
  // creates the exchange promise and stores it in a ref; every later invocation (the StrictMode
  // twin, or a re-render) awaits that SAME promise instead of issuing a second request. Result:
  // one code, one exchange, no race — while the runId guard still decides which run drives the UI.
  const exchangeRef = useRef<Promise<{ ok: boolean; error?: string; ticket?: string }> | null>(null);

  const code = searchParams.get("code");
  const oauthError = searchParams.get("error");
  const oauthErrorDescription = searchParams.get("error_description");

  useEffect(() => {
    if (oauthError) return; // don't run the pipeline against an error response
    const token = ++runId.current;

    if (!readOnceRef.current) {
      readOnceRef.current = true;
      codeVerifierRef.current = sessionStorage.getItem(PKCE_VERIFIER_KEY);
      sessionStorage.removeItem(PKCE_VERIFIER_KEY);
    }
    const codeVerifier = codeVerifierRef.current;

    if (!code) {
      navigate("/", { replace: true });
      return;
    }
    if (!codeVerifier) {
      setNetworkError("Missing PKCE code_verifier — session expired or this page was reloaded. Restart from the Security Gate.");
      return;
    }

    // Fire the single-use token exchange at most once per mount (see exchangeRef note above).
    if (!exchangeRef.current) {
      exchangeRef.current = (async (): Promise<{ ok: boolean; error?: string; ticket?: string }> => {
        let res: Response;
        try {
          res = await fetch(`${ENROLLMENT_API_URL}/oauth/callback`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            // redirect_uri must be byte-identical to what SecurityGate.tsx sent to /authorize (RFC
            // 6749 §4.1.3) — reconstructed the same way here (`${origin}/auth/callback`) rather than
            // hardcoded, so it's automatically correct in whatever environment this is running.
            body: JSON.stringify({
              code,
              code_verifier: codeVerifier,
              redirect_uri: `${window.location.origin}/auth/callback`,
            }),
          });
        } catch {
          return { ok: false, error: `Could not reach the Enrollment Worker at ${ENROLLMENT_API_URL}. Is it running?` };
        }
        if (res.ok) {
          // { enrolled: true, ticket } — the ticket proves THIS oauth exchange happened; required by
          // /token/issue below (real bug fixed 2026-07-23: that endpoint used to accept any caller
          // with no proof of enrollment at all).
          const { ticket } = (await res.json()) as { enrolled: boolean; ticket: string };
          return { ok: true, ticket };
        }
        const body = (await res.json().catch(() => ({}))) as { error?: string };
        return { ok: false, error: body.error || `Enrollment request failed (HTTP ${res.status})` };
      })();
    }
    const exchange = exchangeRef.current;

    (async () => {
      if (runId.current !== token) return;
      setStepIndex(0);

      const result = await exchange;
      if (runId.current !== token) return;
      if (!result.ok || !result.ticket) {
        setNetworkError(result.error ?? "Enrollment failed");
        return;
      }

      // --- Step 2: blind a random identity message (real RSA blind signature blind(), RFC 9474) ---
      if (runId.current !== token) return;
      setStepIndex(1);
      await initCrypto();
      if (runId.current !== token) return;
      const identityMsg = crypto.getRandomValues(new Uint8Array(32));
      const { blindingState, blindedMessage } = blindSigBlind(ISSUER_PK_PEM, identityMsg);
      await wait(300);

      // --- Step 3: real POST /token/issue -> finalize into a verifiable redemption token ---
      if (runId.current !== token) return;
      setStepIndex(2);
      let issueRes: Response;
      try {
        issueRes = await fetch(`${ENROLLMENT_API_URL}/token/issue`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ blinded: bytesToB64(blindedMessage), ticket: result.ticket }),
        });
      } catch {
        if (runId.current === token) setNetworkError(`Could not reach the Enrollment Worker at ${ENROLLMENT_API_URL}.`);
        return;
      }
      if (runId.current !== token) return;
      if (!issueRes.ok) {
        const body = (await issueRes.json().catch(() => ({}))) as { error?: string };
        setNetworkError(body.error || `Token issuance failed (HTTP ${issueRes.status})`);
        return;
      }
      const issued = (await issueRes.json()) as TokenIssueResponse;
      if (runId.current !== token) return;

      // Finalize also self-verifies the unblinded signature (blind_sig.rs's finalize_inner calls
      // pk.verify() internally) — a dishonest issuer's bad signature throws here, not later.
      let redemptionSig: Uint8Array;
      try {
        redemptionSig = blindSigFinalize(ISSUER_PK_PEM, blindingState, b64ToBytes(issued.blindSig), identityMsg);
      } catch (err) {
        setNetworkError(`Redemption token finalize failed: ${(err as Error).message}`);
        return;
      }
      const msgRandomizer = blindSigRandomizer(blindingState);
      console.log(`[Enroll] Redemption token issued+finalized: msg 0x${bytesToHex(identityMsg).slice(0, 16)}...`);
      await wait(300);

      // --- Step 4 (Flow 1): redeem the token -> insert a REAL Semaphore identity commitment ---
      // (R23, 2026-07) `identity.commitment = Poseidon2(Ax,Ay)` — the real Semaphore v4 identity
      // scheme, generated fresh per session (see this file's header comment on the honest gap: a real
      // deployment would derive this from a stable, re-usable identity, not a fresh random one).
      if (runId.current !== token) return;
      setStepIndex(3);
      const identity = new Identity();
      const commitment = fieldToHex(identity.commitment);
      // R25 (2026-07): this call goes through real OHTTP (RFC 9458) — HPKE-sealed via the Messaging
      // Worker's published Key Config, relayed by workers/ohttp-relay, decapsulated by the Worker's
      // Gateway route. Cloudflare never sees this browser's real IP on this request; see
      // ../lib/ohttp.ts and docs/06's R25 entry. Not a plain `fetch()` any more — deliberately.
      let insertRes: Response;
      try {
        insertRes = await ohttpFetch("/membership/insert", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            msg: bytesToB64(identityMsg),
            sig: bytesToB64(redemptionSig),
            msgRandomizer: bytesToB64(msgRandomizer),
            commitment,
          }),
        });
      } catch (err) {
        if (runId.current === token) setNetworkError(`OHTTP request to the Messaging Gateway failed: ${(err as Error).message}`);
        return;
      }
      if (runId.current !== token) return;
      if (!insertRes.ok) {
        const body = (await insertRes.json().catch(() => ({}))) as { error?: string };
        setNetworkError(body.error || `Membership insert failed (HTTP ${insertRes.status})`);
        return;
      }
      const { merkleRoot: insertedRoot, size } = (await insertRes.json()) as MembershipInsertResponse;
      console.log(`[Membership] commitment inserted; merkleRoot 0x${insertedRoot.slice(0, 16)}..., size ${size}`);
      await wait(300);

      // --- Step 5 (Flow 2): generate a REAL Groth16 proof in-browser -> receive a session capability ---
      if (runId.current !== token) return;
      setStepIndex(4);
      // Fetch this identity's OWN real Merkle proof (siblings + index) — MerkleTreeDO's new
      // /proof/:commitment route, needed for any tree size beyond the earlier sole-member special case.
      // R25: also via OHTTP — same reasoning as the insert call above.
      let merkleProofRes: Response;
      try {
        merkleProofRes = await ohttpFetch(`/membership/proof/${commitment}`, { method: "GET" });
      } catch (err) {
        if (runId.current === token) setNetworkError(`OHTTP request to the Messaging Gateway failed: ${(err as Error).message}`);
        return;
      }
      if (runId.current !== token) return;
      if (!merkleProofRes.ok) {
        const body = (await merkleProofRes.json().catch(() => ({}))) as { error?: string };
        setNetworkError(body.error || `Merkle proof lookup failed (HTTP ${merkleProofRes.status})`);
        return;
      }
      const merkleProof = (await merkleProofRes.json()) as MerkleProofResponse;
      console.log(`[Session] fetched Merkle proof: index ${merkleProof.index}, ${merkleProof.siblings.length} sibling(s)`);

      let proof: Awaited<ReturnType<typeof proveMembershipSession>>;
      try {
        proof = await proveMembershipSession(identity, merkleProof);
      } catch (err) {
        setNetworkError(`ZK proof generation failed: ${(err as Error).message}`);
        return;
      }
      if (runId.current !== token) return;
      if (proof.merkleRoot !== merkleProof.merkleRoot) {
        setNetworkError(
          `Internal error: the circuit's own merkleRoot output (0x${proof.merkleRoot.slice(0, 16)}...) does not ` +
            `match the root the Merkle proof was built against (0x${merkleProof.merkleRoot.slice(0, 16)}...).`,
        );
        return;
      }
      console.log(
        `[Session] real proof generated in-browser: merkleRoot 0x${proof.merkleRoot.slice(0, 16)}..., ` +
          `nullifier 0x${proof.nullifier.slice(0, 16)}...`,
      );
      // R25: also via OHTTP — same reasoning as the insert call above.
      let sessionRes: Response;
      try {
        sessionRes = await ohttpFetch("/auth/session", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            proof: bytesToB64(proof.proofBytes),
            merkleRoot: proof.merkleRoot,
            nullifier: proof.nullifier,
            message: proof.message,
            scope: proof.scope,
          }),
        });
      } catch (err) {
        if (runId.current === token) setNetworkError(`OHTTP request to the Messaging Gateway failed: ${(err as Error).message}`);
        return;
      }
      if (runId.current !== token) return;
      if (!sessionRes.ok) {
        const body = (await sessionRes.json().catch(() => ({}))) as { error?: string };
        setNetworkError(body.error || `ZK session issuance failed (HTTP ${sessionRes.status})`);
        return;
      }
      const { capability } = (await sessionRes.json()) as SessionResponse;
      console.log(`[Session] ZK-verified session capability received: ${capability.slice(0, 24)}...`);

      if (runId.current !== token) return;
      setStepIndex(STEPS.length);
      await wait(300); // let the last checkmark land on screen before navigating away
      if (runId.current !== token) return;
      login(capability); // final session capability from the ZK airlock, not the VOPRF token or a mock
      navigate("/chats", { replace: true });
    })();
  }, [code, oauthError, login, navigate]);

  const displayError = oauthError ? oauthErrorDescription || oauthError : networkError;

  return (
    <div className="relative min-h-screen bg-black flex items-center justify-center p-6">
      <NoiseOverlay />
      <div className="relative w-full max-w-md text-center space-y-8">
        <div className="flex flex-col items-center gap-3">
          <Shield className={cn("w-14 h-14 text-fluid-peach", !displayError && "animate-pulse")} />
          <span className="font-serif text-2xl tracking-tight text-white">Vorticity</span>
        </div>

        {displayError ? (
          <div className="vx-glass-dimmable rounded-2xl border border-signal-danger/30 shadow-glass p-8 text-left space-y-4">
            <div className="flex items-center gap-3">
              <XCircle className="w-6 h-6 text-signal-danger shrink-0" />
              <h1 className="text-white font-semibold">Authorization Error</h1>
            </div>
            <p className="text-sm text-white/60">{displayError}</p>
            <Button variant="outline" onClick={() => navigate("/", { replace: true })} className="w-full">
              Return to Security Gate
            </Button>
          </div>
        ) : (
          <div className="vx-glass-dimmable rounded-2xl border border-white/10 shadow-glass p-8 text-left space-y-4">
            {STEPS.map((label, i) => {
              const state = i < stepIndex ? "done" : i === stepIndex ? "active" : "pending";
              return (
                <div key={label} className="flex items-center gap-3">
                  <div className="shrink-0">
                    {state === "done" ? (
                      <CheckCircle2 className="w-5 h-5 text-signal-success" />
                    ) : state === "active" ? (
                      <Loader2 className="w-5 h-5 text-fluid-peach animate-spin" />
                    ) : (
                      <Circle className="w-5 h-5 text-white/20" />
                    )}
                  </div>
                  <span className={cn("text-sm", state === "pending" ? "text-white/30" : "text-white")}>
                    {i + 1}. {label}…
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
