// Session capability persistence (2026-07 revision — see lib/secureStore.ts's header comment for
// the full "why" of the mechanism used here).
//
// ORIGINAL BUGFIX (2026-07, Plane Bridge pass): this used to persist the capability in
// `localStorage`, which is plain JS-readable — a single XSS payload or a malicious/compromised
// browser extension with DOM access can read it trivially, and it survives long after the tab
// closes. Moved to React state only, with NO persistence, accepting "reload loses the session" as
// the tradeoff — a page reload started every session from a fresh `token: null`, and the file's own
// comment at the time named the fix for this properly: "a future 'remember this device' UX should
// use a non-extractable key... never a plain string in Web Storage."
//
// THIS PASS implements exactly that: `login()` seals the capability into `lib/secureStore.ts`'s
// non-extractable AES-GCM vault (IndexedDB) in addition to setting React state; on mount, a reload
// attempts to unseal and restore it. The capability's own `exp` (embedded in its payload segment,
// see workers/messaging/src/session.ts's `mintCapability` — `base64url(payloadJson).base64url(hmac)`,
// readable client-side without needing the server) is checked before trusting a restored value — an
// expired one is discarded and the vault entry cleared, falling back to the original "re-run the
// airlock flow" behavior exactly as before this pass. `logout()` clears the vault entry too.
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { clearFromStore, sealToStore, unsealFromStore } from "../lib/secureStore";

const CAPABILITY_STORE_KEY = "session-capability";

interface AuthContextValue {
  isAuthenticated: boolean;
  /** The ZK-verified session capability from /auth/session — presented to the Messaging Plane to
   * authorise /queue etc. Null when logged out, or before the vault-restore attempt on mount resolves. */
  token: string | null;
  /** True until the vault-restore attempt on mount has resolved (found-and-valid, found-and-expired,
   * or nothing persisted). AuthGuard must wait for this before deciding to redirect — otherwise a
   * reload on an already-authenticated route would bounce to "/" on the FIRST render, before this
   * effect even runs, defeating the whole point of restoring the session. */
  isRestoring: boolean;
  login: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Reads the `exp` field out of a capability's own payload segment, without needing the server —
 * same base64url(JSON).base64url(HMAC) shape `session.ts`'s `verifyCapability` parses server-side.
 * Returns `null` on anything malformed, treated the same as "expired" by the caller. */
function capabilityExpiry(token: string): number | null {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  try {
    const binary = atob(token.slice(0, dot).replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const payload = JSON.parse(new TextDecoder().decode(bytes)) as { exp?: unknown };
    return typeof payload.exp === "number" ? payload.exp : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [isRestoring, setIsRestoring] = useState(true);

  // Restore-on-mount — see `isRestoring`'s doc comment above for why AuthGuard must wait for this
  // rather than reading `isAuthenticated` on the very first render.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const bytes = await unsealFromStore(CAPABILITY_STORE_KEY);
      if (cancelled) return;
      if (!bytes) {
        setIsRestoring(false);
        return;
      }
      const restored = new TextDecoder().decode(bytes);
      const exp = capabilityExpiry(restored);
      if (exp === null || exp <= Date.now()) {
        // Expired or unparseable — discard and fall back to the original "re-run the airlock flow"
        // behavior, exactly as if nothing had ever been persisted.
        await clearFromStore(CAPABILITY_STORE_KEY);
        if (!cancelled) setIsRestoring(false);
        return;
      }
      setToken(restored);
      setIsRestoring(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback((newToken: string) => {
    setToken(newToken);
    sealToStore(CAPABILITY_STORE_KEY, new TextEncoder().encode(newToken)).catch((err) =>
      console.warn("[Auth] Failed to persist capability to the vault (session will not survive a reload):", (err as Error).message),
    );
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    clearFromStore(CAPABILITY_STORE_KEY).catch(() => {});
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated: token !== null, token, isRestoring, login, logout }}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth() must be called within an AuthProvider");
  return ctx;
}
