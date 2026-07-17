// Session capability held in React state only — NEVER in localStorage/sessionStorage/IndexedDB.
//
// BUGFIX (2026-07, Plane Bridge pass): this used to persist the capability in `localStorage`, which
// is plain JS-readable storage — a single XSS payload or a malicious/compromised browser extension
// with DOM access can read it trivially, and it survives long after the tab closes. The capability
// IS the bearer credential that authorises every /queue, /conv, /group call (see
// workers/messaging/src/index.ts's `requireCapability`); it deserves the same treatment as any other
// bearer token, not localStorage's "just a string sitting in the page's storage forever" model.
//
// TRADEOFF (accepted, not hidden): a page reload loses the session — `token` starts `null` on every
// fresh mount, there is no read-back. The user re-runs the enrollment/airlock flow (AuthCallback.tsx)
// to re-mint a fresh capability. This is the correct shape for a short-lived (1h TTL, see
// workers/messaging/src/session.ts's CAPABILITY_TTL_MS) bearer credential — re-minting on session
// break is cheap (the VOPRF/RSABSSA token + Merkle commitment persist across the reload; only the
// final ZK-session capability itself needs to be redone) and is a deliberately better tradeoff than
// leaving a live bearer credential sitting in storage an attacker's JS can simply read. A future
// "remember this device" UX (if ever added) should use a non-extractable key (e.g. a WebCrypto
// non-exportable CryptoKey / platform keystore), never a plain string in Web Storage.
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

interface AuthContextValue {
  isAuthenticated: boolean;
  /** The ZK-verified session capability from /auth/session — presented to the Messaging Plane to
   * authorise /queue etc. Null when logged out or after a reload (see file header: not persisted). */
  token: string | null;
  login: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);

  const login = useCallback((newToken: string) => {
    setToken(newToken);
  }, []);

  const logout = useCallback(() => {
    setToken(null);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated: token !== null, token, login, logout }}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth() must be called within an AuthProvider");
  return ctx;
}
