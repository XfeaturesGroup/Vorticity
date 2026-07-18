// The OHTTP Relay role (RFC 9458 §4) — see wrangler.toml's header comment for the full picture. This
// Worker is deliberately dumb: it never parses, decrypts, or inspects the HPKE-sealed bytes it
// forwards, and it never sees the Gateway's private key. Its ONLY job is "carry opaque bytes between
// the Client and the Gateway" — which is exactly what makes the Relay/Gateway split work: whoever
// operates this Worker sees the client's real IP (this is a normal Cloudflare Worker invocation) but
// never the plaintext request; the Gateway sees the plaintext request but only ever this Relay's own
// server-to-server fetch, never the original client's IP.
export interface Env {
  GATEWAY_ORIGIN: string;
}

// Only these two paths are meaningful to relay — anything else is refused outright rather than
// silently forwarded, so this Worker can never be turned into an open proxy for arbitrary origins.
const ALLOWED_PATHS = new Set(["/ohttp/keys", "/ohttp/gateway"]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (!ALLOWED_PATHS.has(url.pathname)) {
      return new Response("Not found", { status: 404 });
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
      headers: { "Content-Type": gatewayResponse.headers.get("Content-Type") ?? "application/octet-stream" },
    });
  },
};
