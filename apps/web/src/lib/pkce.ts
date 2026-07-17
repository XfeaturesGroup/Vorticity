// Ported from docs/legacy-reference/oauth-pkce.js — standard PKCE, no identity logic, still
// valid as-is. The real IDM (account.xfeatures.net) enforces PKCE (code_challenge +
// code_challenge_method=S256 required, confirmed live against a real "Authorization Error"
// response), so this must run before every redirect to /oauth/authorize, not just be nice-to-have.
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function generateCodeVerifier(): string {
  const array = new Uint32Array(28);
  window.crypto.getRandomValues(array);
  return Array.from(array, (dec) => ("0" + dec.toString(16)).substr(-2)).join("");
}

/** sessionStorage (not localStorage): a code_verifier is single-use, tied to one in-flight
 * authorize->callback round trip, and should not outlive the tab. */
export const PKCE_VERIFIER_KEY = "vortic_pkce_code_verifier";
