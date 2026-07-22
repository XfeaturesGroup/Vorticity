// CORS-aware JSON responses for the browser-facing airlock endpoints (/membership/insert,
// /auth/session). Mirrors workers/enrollment/src/response.ts: an origin ALLOW-LIST (never `*` for an
// auth-plane Worker, never a single hardcoded prod value that would break local dev), applied on
// EVERY response path — success, expected error, and unexpected exception — so a bare fallback can't
// surface to the browser as a misleading "blocked by CORS policy" error (the bug hit in enrollment).
const DEFAULT_ORIGIN = "https://vort.xfeatures.net";
const ALLOWED_ORIGINS = [DEFAULT_ORIGIN, "http://localhost:5173"];

export function corsHeaders(origin: string | null): Record<string, string> {
  const allowed = origin && ALLOWED_ORIGINS.includes(origin) ? origin : DEFAULT_ORIGIN;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

export function jsonResp(data: unknown, origin: string | null, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

export function errorResp(message: string, origin: string | null, status = 400): Response {
  return jsonResp({ error: message }, origin, status);
}
