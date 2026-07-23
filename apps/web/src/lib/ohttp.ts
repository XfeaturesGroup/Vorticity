// R25 (2026-07): real client-side OHTTP (RFC 9458). Used by AuthCallback.tsx for the three
// "anonymity zone" calls docs/04's Flow 1/2 diagrams draw through the OHTTP Relay
// (`/membership/insert`, `/membership/proof/:commitment`, `/auth/session`), AND — R25 follow-up,
// same pass day — by useQueueTransport.ts's `pushEnvelope` for `POST /queue/:id/push`. That second
// one matters MORE in practice than the three one-time enrollment calls: it fires on every single
// message send, not once per session, and it's a plain POST/response like the others (unlike WS
// subscribe, nothing structurally blocks wrapping it — the first pass just hadn't gotten to it yet,
// flagged honestly in docs/06 rather than silently, and closed in this follow-up). `ohttpFetch`
// mirrors the browser `fetch()` signature closely enough to be close to a drop-in swap at call
// sites: it returns a real `Response`, so `.ok`/`.status`/`.json()` all work unchanged.
//
// Wire path: encapsulate (HPKE-seal + Binary HTTP framing, packages/ohttp) -> POST to the Relay
// (workers/ohttp-relay, the only hop that ever sees this browser's real IP) -> the Relay forwards
// opaque bytes to the Messaging Worker's Gateway route -> decapsulate the Gateway's encapsulated
// response back into a real status/headers/body.
import { encapsulateRequest, MEDIA_TYPE_KEY_CONFIG, MEDIA_TYPE_REQUEST } from "@vorticity/ohttp";

const RELAY_URL = import.meta.env.DEV ? "http://localhost:8789" : "https://relay.vort.xfeatures.net";

// The Key Config rarely changes (only on Gateway key rotation) — fetch once per page load and reuse.
// A failed fetch is not cached, so a later call can retry rather than being stuck on a rejected promise.
let cachedKeyConfig: Promise<Uint8Array> | null = null;

async function fetchKeyConfig(): Promise<Uint8Array> {
  if (cachedKeyConfig) return cachedKeyConfig;
  const promise = (async () => {
    const res = await fetch(`${RELAY_URL}/ohttp/keys`);
    if (!res.ok) throw new Error(`failed to fetch OHTTP gateway key config: HTTP ${res.status}`);
    const contentType = res.headers.get("Content-Type");
    if (contentType !== MEDIA_TYPE_KEY_CONFIG) {
      throw new Error(`OHTTP key config endpoint returned unexpected Content-Type: ${contentType}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  })();
  cachedKeyConfig = promise;
  promise.catch(() => {
    cachedKeyConfig = null; // don't poison future calls with a stale rejected promise
  });
  return promise;
}

export interface OhttpFetchInit {
  method: "GET" | "POST" | "PUT";
  headers?: Record<string, string>;
  /** A JSON string (the usual case) or already-encoded bytes (e.g. a padded Sealed Sender++
   * envelope — see useQueueTransport.ts's `pushEnvelope`, which is not JSON at all). */
  body?: string | Uint8Array;
}

/**
 * `path` is a path-and-query only (e.g. `/membership/insert`) — the scheme/authority fields Binary
 * HTTP framing requires are nominal placeholders, never actually dialed over the network (the real
 * network hop is always the Relay's own URL); the Gateway dispatches purely on `method` + `path`.
 */
export async function ohttpFetch(path: string, init: OhttpFetchInit): Promise<Response> {
  const keyConfig = await fetchKeyConfig();
  const bodyBytes =
    init.body === undefined ? new Uint8Array(0) : typeof init.body === "string" ? new TextEncoder().encode(init.body) : init.body;
  const headers = Object.entries(init.headers ?? {});

  const handle = await encapsulateRequest(keyConfig, {
    method: init.method,
    scheme: "https",
    authority: "q.vort.xfeatures.net",
    path,
    headers,
    body: bodyBytes,
  });

  const relayRes = await fetch(`${RELAY_URL}/ohttp/gateway`, {
    method: "POST",
    headers: { "Content-Type": MEDIA_TYPE_REQUEST },
    body: handle.encapsulatedRequest as BodyInit,
  });
  if (!relayRes.ok) {
    throw new Error(`OHTTP relay/gateway request failed: HTTP ${relayRes.status}`);
  }
  const encapsulatedResponse = new Uint8Array(await relayRes.arrayBuffer());
  const decoded = await handle.decapsulateResponse(encapsulatedResponse);

  const responseHeaders = new Headers();
  for (const [name, value] of decoded.headers) responseHeaders.set(name, value);
  return new Response(decoded.body as BodyInit, { status: decoded.status, headers: responseHeaders });
}
