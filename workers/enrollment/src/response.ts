// Adapted from docs/legacy-reference/response.js — same shape, origin tightened (the legacy
// `Access-Control-Allow-Origin: '*'` is fine for a public marketing site, not for an auth plane).
//
// Origin is an allow-list, not a single static value: this Worker is called from `apps/web` both
// in local dev (`http://localhost:5173`, via `wrangler dev`) and in production
// (`https://vort.xfeatures.net`). A single hardcoded prod origin silently breaks every local dev
// fetch — the browser blocks the response client-side with no server-visible signal — so the
// allowed origin is picked per-request from this fixed list, never reflected from an arbitrary
// caller-supplied value.
const ALLOWED_ORIGINS = ["https://vort.xfeatures.net", "http://localhost:5173"];

export function corsHeaders(origin: string | null): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0]!,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    Pragma: "no-cache",
    Expires: "0",
  };
}

export function jsonResp(data: unknown, origin: string | null, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders(origin) });
}

export function errorResp(msg: string, origin: string | null, status = 400): Response {
  return new Response(JSON.stringify({ error: msg }), { status, headers: corsHeaders(origin) });
}
