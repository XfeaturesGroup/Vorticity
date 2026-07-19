// R22 (2026-07): minimal client-side transport for ConvLogDO (docs/04 Flow 4, multi-device CRDT
// op-log sync). This is deliberately the TRANSPORT primitive only — append an opaque encrypted blob,
// receive the ordered op-log (backlog on connect + live WS push) — not a CRDT implementation. There is
// no Yjs/Automerge integration here: `blob` is whatever opaque bytes the caller wants ordered and
// fanned out; a real chat UI wiring this up would put an encrypted Yjs update in `blob` and run
// `Y.applyUpdate` on receipt. That integration is separate, not-yet-built work (see docs/06) — this
// module proves the transport is real, not that multi-device merge UX exists yet.
// `appendToConvLog`/`syncConvLog` below (plain HTTP POST/GET) are NOT OHTTP-wrapped — out of R25's
// scope (only /membership/insert, /membership/proof/:commitment, /auth/session, /queue/:id/push were
// wired) and not touched by R26 either. `subscribeConvLog`'s WS connection, per R26 (2026-07), now
// goes through workers/ohttp-relay instead of the Messaging Worker directly — see
// useQueueTransport.ts's header comment (same reasoning, same unverified-pending-real-deployment
// caveat) and docs/06's R26 entry.
const MESSAGING_API_URL = import.meta.env.DEV ? "http://localhost:8787" : "https://api.vort.xfeatures.net";
const WS_BASE_URL = import.meta.env.DEV ? "ws://localhost:8789/conv" : "wss://relay.vort.xfeatures.net/conv";

export interface ConvLogEntry {
  seq: number;
  blob: Uint8Array;
  enqueuedAt: number;
}

function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Append one or more opaque blobs to `convId`'s op-log. Returns the seq assigned to each, in order. */
export async function appendToConvLog(convId: string, cap: string, blobs: Uint8Array[]): Promise<number[]> {
  const res = await fetch(`${MESSAGING_API_URL}/conv/${encodeURIComponent(convId)}/append`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cap}`, "Content-Type": "application/json" },
    body: JSON.stringify({ blobs: blobs.map(bytesToB64) }),
  });
  if (!res.ok) throw new Error(`append to conv ${convId} failed: HTTP ${res.status}`);
  const { seqs } = (await res.json()) as { seqs: number[] };
  return seqs;
}

/** One-shot poll: entries strictly after `sinceSeq`. Used for a non-live catch-up read. */
export async function syncConvLog(convId: string, cap: string, sinceSeq: number): Promise<ConvLogEntry[]> {
  const res = await fetch(`${MESSAGING_API_URL}/conv/${encodeURIComponent(convId)}/sync?since_seq=${sinceSeq}`, {
    headers: { Authorization: `Bearer ${cap}` },
  });
  if (!res.ok) throw new Error(`sync conv ${convId} failed: HTTP ${res.status}`);
  const { entries } = (await res.json()) as { entries: { seq: number; blob: string; enqueuedAt: number }[] };
  return entries.map((e) => ({ seq: e.seq, blob: b64ToBytes(e.blob), enqueuedAt: e.enqueuedAt }));
}

/**
 * Live subscription: opens a WS to `convId` (backlog since `sinceSeq` flushed immediately on connect,
 * matching ConvLogDO's `handleSubscribe`), calls `onEntry` for each entry in seq order. Returns a
 * closer function. No reconnect/backoff logic here (unlike the message-queue transport) — this is a
 * thin primitive for the live test and future real wiring, not the full production hook.
 */
export function subscribeConvLog(convId: string, cap: string, sinceSeq: number, onEntry: (entry: ConvLogEntry) => void): () => void {
  const ws = new WebSocket(`${WS_BASE_URL}/${encodeURIComponent(convId)}?cap=${encodeURIComponent(cap)}&since_seq=${sinceSeq}`);
  ws.onmessage = (event) => {
    if (typeof event.data !== "string") return;
    let wire: unknown;
    try {
      wire = JSON.parse(event.data);
    } catch {
      return;
    }
    const w = wire as { seq?: unknown; blob?: unknown; enqueuedAt?: unknown };
    if (typeof w.seq !== "number" || typeof w.blob !== "string" || typeof w.enqueuedAt !== "number") return;
    onEntry({ seq: w.seq, blob: b64ToBytes(w.blob), enqueuedAt: w.enqueuedAt });
  };
  return () => ws.close();
}
