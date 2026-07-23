// The OHTTP Relay role (RFC 9458 §4) — see wrangler.toml's header comment for the full picture. This
// Worker is deliberately dumb: it never parses, decrypts, or inspects the HPKE-sealed bytes it
// forwards, and it never sees the Gateway's private key. Its ONLY job is "carry opaque bytes between
// the Client and the Gateway" — which is exactly what makes the Relay/Gateway split work: whoever
// operates this Worker sees the client's real IP (this is a normal Cloudflare Worker invocation) but
// never the plaintext request; the Gateway sees the plaintext request but only ever this Relay's own
// server-to-server fetch, never the original client's IP.
//
// R26 (2026-07): also proxies the WS subscribe/receive connections (`/queue/:id`, `/conv/:id`) that
// R25's OHTTP cannot wrap (RFC 9458 is single-shot request/response, structurally incompatible with a
// persistent connection) — see `proxyWebSocket` below and docs/06's R26 entry for the full picture,
// INCLUDING THE LOAD-BEARING CAVEAT: this is implemented against Cloudflare's own documented
// same-zone/cross-zone `CF-Connecting-IP` behavior (developers.cloudflare.com/fundamentals/reference/
// http-request-headers/) but is NOT independently live-verified — that specific edge-network routing
// behavior does not exist in local `wrangler dev`/Miniflare (confirmed before writing this: Miniflare
// only simulates the static `request.cf` metadata object, not dynamic zone-routing header rewriting),
// and nothing in this project is deployed to a real Cloudflare zone yet. Do not treat this as a
// confirmed fix — see docs/06 R26 for what live verification against a real deployment would need to
// check before this can be marked resolved.
export interface Env {
  GATEWAY_ORIGIN: string;
}

// Real bug found + fixed 2026-07-19 (first real browser click-through — every prior test of this
// Worker was curl/vitest, and CORS is enforced by the BROWSER, not the server or a Node fetch client,
// so this was invisible until now): this Worker never sent any CORS headers at all, and `POST
// /ohttp/gateway`'s `Content-Type: message/ohttp-req` is not a CORS-safelisted content type, so the
// browser sends a real OPTIONS preflight first — which this Worker used to answer with a bare 404
// (`ALLOWED_PATHS` doesn't include `OPTIONS`'s implicit path check), failing the whole request before
// it ever reached the Gateway. Same allow-list convention already used by
// `workers/enrollment/src/response.ts` / `workers/messaging` — never a wildcard/reflected-arbitrary-
// origin, this Worker is called from `apps/web` in local dev AND production.
const ALLOWED_ORIGINS = ["https://vort.xfeatures.net", "http://localhost:5173"];

function corsHeaders(origin: string | null): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0]!,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

// Only these two paths are meaningful to relay — anything else is refused outright rather than
// silently forwarded, so this Worker can never be turned into an open proxy for arbitrary origins.
const ALLOWED_PATHS = new Set(["/ohttp/keys", "/ohttp/gateway"]);

// Matches exactly `/queue/{id}`, `/conv/{id}`, `/presence/{id}`, or `/group/{id}` — the WS subscribe
// endpoints QueueDO/ConvLogDO/PresenceDO/GroupDO expose (see workers/messaging/src/index.ts's
// `/queue/:queueId/*`, `/conv/:convId/*`, `/presence/:chatId/*`, and `/group/:groupId/*` routes; the
// WS upgrade case is the SAME path as the plain HTTP routes under those prefixes, distinguished only
// by the `Upgrade` header, not a different sub-path). No trailing segment allowed (`/queue/{id}/push`
// — the OHTTP-wrapped send path — must NOT match here; it's handled entirely by the `/ohttp/gateway`
// branch above and never needs raw WS proxying). `presence` added alongside `queue`/`conv` (2026-07,
// PresenceDO pass); `group` added (2026-07, first group-chat client pass) — GroupDO's `/push`/`/sync`
// have no OHTTP-wrapped path yet (see GroupDO.ts's own header comment on that gap), but its WS
// subscribe still needs the same real-IP-hiding proxy every other live socket gets — same structural
// reasoning as R26's own note above: WS is single-shot-incompatible with OHTTP, so this is the same
// plain network-level proxy, not a new mechanism.
const WS_PROXY_PATTERN = /^\/(queue|conv|presence|group)\/[^/]+$/;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    if (request.headers.get("Upgrade") === "websocket" && WS_PROXY_PATTERN.test(url.pathname)) {
      return proxyWebSocket(request, url, env);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (!ALLOWED_PATHS.has(url.pathname)) {
      return new Response("Not found", { status: 404, headers: corsHeaders(origin) });
    }

    const target = new URL(url.pathname, env.GATEWAY_ORIGIN);
    const contentType = request.headers.get("Content-Type");
    const forwarded = new Request(target, {
      method: request.method,
      headers: contentType ? { "Content-Type": contentType } : {},
      body: request.method === "GET" || request.method === "HEAD" ? null : request.body,
    });

    const gatewayResponse = await fetch(forwarded);
    return new Response(gatewayResponse.body, {
      status: gatewayResponse.status,
      headers: {
        "Content-Type": gatewayResponse.headers.get("Content-Type") ?? "application/octet-stream",
        ...corsHeaders(origin),
      },
    });
  },
};

// Transparent pass-through: forward the WS upgrade to the Gateway and return its Response verbatim
// (`resp.webSocket` set, per Cloudflare's documented proxy pattern) — the runtime wires the two
// WebSocketPair ends together without this Worker's JS reading individual frames, so it does not stay
// "in use"/billed for the connection's lifetime (Cloudflare's own documented cost behavior for this
// exact pattern). This is what keeps delivery genuinely real-time, no polling fallback.
async function proxyWebSocket(request: Request, url: URL, env: Env): Promise<Response> {
  const target = new URL(url.pathname + url.search, env.GATEWAY_ORIGIN);
  const headers = new Headers(request.headers);
  // Best-effort SAME-ZONE mitigation: Cloudflare's docs state same-zone subrequests' `CF-Connecting-IP`
  // "reflects the value of x-real-ip, [which] can be altered by the user in their Worker script" — so
  // overriding it here is the documented lever, not a guess. UNVERIFIED (see module doc above) whether
  // this override is honored exactly this way in practice. The STRONGER, platform-guaranteed path is
  // deploying this Relay under a genuinely separate Cloudflare zone from the Messaging Worker, where
  // `CF-Connecting-IP` is automatically replaced by Cloudflare itself for cross-zone subrequests — no
  // header manipulation needed or relied upon in that case.
  headers.set("x-real-ip", "0.0.0.0");
  const forwarded = new Request(target, { method: request.method, headers, body: null });
  return fetch(forwarded);
}
