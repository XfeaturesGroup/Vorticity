// R22 (2026-07): the real 1:1 message transport (docs/04 Flow 3), replacing the earlier
// "Phase 5 transport spike" (`useChatWebSocket.ts`, deleted) that did a single `ws.send()` on the
// same socket for both directions with no persistence and no real push path.
//
// REAL PROTOCOL, exactly as documented (not improvised beyond it):
//   - Send: capability-gated `POST /queue/{queueId}/push` (ciphertext body, X-Ttl-Ms, X-Size-Bucket).
//   - Receive: WS push if subscribed (QueueDO.handleSubscribe already flushes the full backlog the
//     instant a socket connects — that backlog flush on connect literally IS "pull on wake": there is
//     no separate poll needed, (re)establishing the WS on wake achieves the same thing).
//   - Ack: `{type:"ack",upToSeq}` sent back over the SAME WS (QueueDO.webSocketMessage's only frame).
// See workers/messaging/src/durable-objects/QueueDO.ts for the server side (unchanged by this pass
// except removing the now-dead relay fallback the old mock needed).
//
// TWO UNIDIRECTIONAL QUEUES PER CHAT (docs/README.md decision #7, DO catalog: "QueueDO ... One
// unidirectional pairwise queue"): `${chatId}:AtoB` and `${chatId}:BtoA`. Real production queue-id
// *provisioning* (rotating opaque ids, exchanged during contact establishment — Flow 5/6) is a
// separate, not-yet-built system; this pass is about fixing the TRANSPORT primitive, not building
// contact discovery. `role` ("initiator" | "responder") is an explicit, honest stand-in for that
// missing piece — the mock UI (`Chats.tsx`) has no real per-user identity to assign roles from yet, so
// it defaults every mock chat to "initiator"; a real 2-party live test (docs/06) drives two independent
// clients with opposite roles directly.
//
// SEALED SENDER++ RECEIPTS (docs/01 "Vorticity counter", docs/README.md decision #5): padded, delayed,
// and decoupled from the message path — not the message queue, a SEPARATE `${queueId}:receipt` queue
// running the opposite direction, pushed after a randomized delay so an observer watching queue
// traffic can't use "receipt arrived N ms after message" as a relinking oracle (the documented Signal
// weakness this is explicitly countering). Same padding/bucket scheme as messages, so a receipt isn't
// even distinguishable from a message by size on the wire.
//
// CRYPTO (R24, 2026-07): the earlier spike's unauthenticated, non-ratcheting X25519 DH is GONE —
// replaced by a real PQXDH-style authenticated handshake (Ed25519-signed hybrid ML-KEM-768+X25519
// prekey bundle) feeding a real Double Ratchet + Sparse PQ Ratchet (packages/vortic-core/src/ratchet.rs;
// see its module doc for the full design and the honest scope of the PQ remix property). No fallback
// to the old flat-DH path is kept.
//
// PQXDH IS ASYMMETRIC (unlike the old symmetric DH swap): one side ("responder", Bob) publishes a
// signed prekey bundle; the other ("initiator", Alice) verifies it and encapsulates. This maps
// directly onto the existing `role` stand-in from R22 (still an honest placeholder for real Flow 5/6
// contact establishment — NOT built here either): "responder" generates and pushes a `prekey_offer`
// envelope once per chat mount; "initiator" answers with a `session_init` envelope carrying the KEM
// ciphertext. Both identity and prekey material are generated FRESH per mount (not persisted to
// device storage, not published to any directory service) — real long-term identity persistence and
// a `PrekeyDO` (docs/03 §4) are separate, not-yet-built infrastructure; this pass replaces the KEY
// EXCHANGE cryptography, not identity/prekey distribution.
import { useCallback, useEffect, useRef, useState } from "react";
import {
  freshRatchetEntropy,
  identitySignBundle,
  identityVerifyingKey,
  initCrypto,
  kemGenerateKeypair,
  kemPublicKeyFromKeypair,
  RatchetSession,
} from "@vorticity/vortic-core";
import { useAuth } from "../contexts/AuthContext";
import { formatNow, type ChatMessage } from "../lib/mockChats";
import { ohttpFetch } from "../lib/ohttp";

function freshSeed32(): Uint8Array {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return seed;
}

export type SocketStatus = "offline" | "connecting" | "online" | "reconnecting";
export type TransportRole = "initiator" | "responder";

// R25 follow-up (2026-07): `MESSAGING_API_URL` is gone — `pushEnvelope` below goes through
// `ohttpFetch` (../lib/ohttp.ts) instead of hitting this Worker's origin directly. WS subscribe
// (`WS_BASE_URL` below) still connects directly — a persistent connection structurally cannot be
// OHTTP-wrapped (RFC 9458 is single-shot request/response); see docs/06's R25 entry for the honest,
// permanent residual gap this leaves (a subscriber's IP is visible to Cloudflare's edge for the
// lifetime of that connection).
const WS_BASE_URL = import.meta.env.DEV ? "ws://localhost:8787/queue" : "wss://api.vort.xfeatures.net/ws/queue";

const MESSAGE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — matches QueueDO's own defensive cap
const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000; // receipts are a backstop signal, not durable history
const RECEIPT_DELAY_MIN_MS = 2000;
const RECEIPT_DELAY_MAX_MS = 8000;

const BASE_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30_000;

// --- base64 <-> bytes ---
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
function shortHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes.slice(0, 4)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// --- Sealed Sender++ padding: pad the JSON envelope up to the nearest size bucket, so a receipt is
// not distinguishable from a real message by ciphertext length on the wire. ---
const SIZE_BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384];

function padHex(byteLen: number): string {
  const raw = new Uint8Array(byteLen);
  crypto.getRandomValues(raw);
  // Hex, not raw bytes: every character is exactly 1 UTF-8 byte and never needs JSON escaping, so the
  // padded length calculation below stays exact.
  return Array.from(raw).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, byteLen);
}

// --- Wire envelopes (the padded JSON blob pushed as a queue message's opaque ciphertext body) ---
// PQXDH handshake is two envelopes, not one symmetric exchange (see this file's header comment):
// "responder" pushes PrekeyOffer once; "initiator" answers with SessionInit once. From then on both
// sides exchange MessageEnvelope, whose `wire` field is the Double Ratchet's own header+ciphertext
// framing (ratchet.rs's `parse_wire`/`RatchetHeader::to_bytes`), base64-encoded for the JSON envelope.
interface PrekeyOfferEnvelope {
  type: "prekey_offer";
  verifyingKey: string; // base64 Ed25519 verifying key (32 bytes)
  bundle: string; // base64 hybrid KEM public bundle (ML-KEM-768 ek || X25519 pk)
  bundleSig: string; // base64 Ed25519 signature over `bundle` (64 bytes)
}
interface SessionInitEnvelope {
  type: "session_init";
  ciphertext: string; // base64 hybrid KEM ciphertext (the PQXDH-style encapsulation)
}
interface MessageEnvelope {
  type: "message";
  wire: string; // base64(RatchetSession.encryptMessage output: header || AEAD ciphertext)
  timestamp: string;
}
interface ReceiptEnvelope {
  type: "receipt";
  ackSeq: number; // the queue seq of the message being acknowledged
}
type Envelope = PrekeyOfferEnvelope | SessionInitEnvelope | MessageEnvelope | ReceiptEnvelope;

function isEnvelope(v: unknown): v is Envelope {
  const t = (v as { type?: unknown } | null)?.type;
  return t === "prekey_offer" || t === "session_init" || t === "message" || t === "receipt";
}

function padEnvelope(envelope: Envelope): { bytes: Uint8Array; bucket: number } {
  const withoutPad = JSON.stringify({ ...envelope, pad: "" });
  const overhead = new TextEncoder().encode(withoutPad).length;
  for (let bucket = 0; bucket < SIZE_BUCKETS.length; bucket++) {
    const bucketSize = SIZE_BUCKETS[bucket]!;
    if (overhead <= bucketSize) {
      const padded = JSON.stringify({ ...envelope, pad: padHex(bucketSize - overhead) });
      return { bytes: new TextEncoder().encode(padded), bucket };
    }
  }
  // Larger than the biggest bucket (shouldn't happen for chat text/receipts) — send unpadded rather
  // than silently truncate real content; still tagged with the largest bucket index.
  return { bytes: new TextEncoder().encode(withoutPad), bucket: SIZE_BUCKETS.length - 1 };
}

// R25 follow-up (2026-07): goes through real OHTTP now, not a plain `fetch()` — this is the highest-
// frequency OHTTP-eligible call in the app (fires per message), higher priority in practice than the
// three one-time enrollment calls the first R25 pass wired; see ../lib/ohttp.ts and docs/06's R25 entry.
async function pushEnvelope(queueId: string, cap: string, envelope: Envelope, ttlMs: number): Promise<void> {
  const { bytes, bucket } = padEnvelope(envelope);
  const res = await ohttpFetch(`/queue/${encodeURIComponent(queueId)}/push`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cap}`,
      "X-Ttl-Ms": String(ttlMs),
      "X-Size-Bucket": String(bucket),
    },
    body: bytes,
  });
  if (!res.ok) throw new Error(`push to ${queueId} failed: HTTP ${res.status}`);
}

interface QueueWireMessage {
  type: "message";
  seq: number;
  ciphertext: string; // base64 of the padded envelope bytes (QueueDO's generic opaque-blob field)
  sizeBucket: number;
  enqueuedAt: number;
}

/**
 * Subscribes to one QueueDO's WS (reconnecting with backoff), decodes each inbound frame's padded
 * envelope, hands it to `onEnvelope`, and acks. Used twice per chat (inbound message queue, inbound
 * receipt queue) — see `useQueueTransport` below.
 */
function useQueueSubscription(queueId: string | null, cap: string | null, onEnvelope: (envelope: Envelope, seq: number) => void): SocketStatus {
  const [status, setStatus] = useState<SocketStatus>("offline");
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const attemptRef = useRef(0);
  const onEnvelopeRef = useRef(onEnvelope);
  onEnvelopeRef.current = onEnvelope;

  useEffect(() => {
    if (!queueId || !cap) {
      setStatus("offline");
      return;
    }

    let cancelled = false;
    let maxSeqSeen = 0;
    attemptRef.current = 0;

    const connect = () => {
      if (cancelled) return;
      setStatus(attemptRef.current === 0 ? "connecting" : "reconnecting");

      const ws = new WebSocket(`${WS_BASE_URL}/${encodeURIComponent(queueId)}?cap=${encodeURIComponent(cap)}`);
      wsRef.current = ws;

      ws.onopen = () => {
        if (cancelled) return;
        attemptRef.current = 0;
        setStatus("online");
      };

      ws.onmessage = (event) => {
        if (cancelled || typeof event.data !== "string") return;
        let wire: unknown;
        try {
          wire = JSON.parse(event.data);
        } catch {
          return; // malformed frame — ignore, don't crash the socket
        }
        const w = wire as Partial<QueueWireMessage>;
        if (w.type !== "message" || typeof w.seq !== "number" || typeof w.ciphertext !== "string") return;
        maxSeqSeen = Math.max(maxSeqSeen, w.seq);

        let envelope: unknown;
        try {
          envelope = JSON.parse(new TextDecoder().decode(b64ToBytes(w.ciphertext)));
        } catch {
          // Undecodable padded envelope — ack it anyway (it's not coming back correct on retry either)
          // and move on, same "one bad frame can't wedge the queue" tolerance as the rest of this file.
          ws.send(JSON.stringify({ type: "ack", upToSeq: maxSeqSeen }));
          return;
        }
        if (isEnvelope(envelope)) onEnvelopeRef.current(envelope, w.seq);
        ws.send(JSON.stringify({ type: "ack", upToSeq: maxSeqSeen }));
      };

      ws.onclose = () => {
        wsRef.current = null;
        if (cancelled) return;
        setStatus("reconnecting");
        const attempt = attemptRef.current++;
        const delay = Math.min(BASE_BACKOFF_MS * 2 ** attempt, MAX_BACKOFF_MS);
        reconnectTimerRef.current = setTimeout(connect, delay);
      };
      ws.onerror = () => {};
    };

    connect();
    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [queueId, cap]);

  return status;
}

interface QueueIds {
  outMsg: string;
  inMsg: string;
  outReceipt: string;
  inReceipt: string;
}

function queueIds(chatId: string, role: TransportRole): QueueIds {
  const aToB = `${chatId}:AtoB`;
  const bToA = `${chatId}:BtoA`;
  return role === "initiator"
    ? { outMsg: aToB, inMsg: bToA, outReceipt: `${bToA}:receipt`, inReceipt: `${aToB}:receipt` }
    : { outMsg: bToA, inMsg: aToB, outReceipt: `${aToB}:receipt`, inReceipt: `${bToA}:receipt` };
}

export function useQueueTransport(
  chatId: string | null,
  role: TransportRole,
  onMessage: (chatId: string, message: ChatMessage) => void,
) {
  const { token: cap } = useAuth();
  // Own long-term-for-this-chat identity + hybrid prekey material — only meaningful for the
  // "responder" role (only Bob publishes a bundle in PQXDH's one-sided handshake). Fresh per mount;
  // see this file's header comment for why that's an honest, not a production, choice.
  const identitySeedRef = useRef<Uint8Array | null>(null);
  const kemKeypairBytesRef = useRef<Uint8Array | null>(null);
  const ratchetSessionRef = useRef<RatchetSession | null>(null);
  const idsRef = useRef<QueueIds | null>(null);
  idsRef.current = chatId ? queueIds(chatId, role) : null;

  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  const chatIdRef = useRef(chatId);
  chatIdRef.current = chatId;

  // --- Inbound on the message queue: prekey_offer / session_init / message ---
  const handleInboundMessage = useCallback(
    async (envelope: Envelope, seq: number) => {
      const ids = idsRef.current;
      const activeChatId = chatIdRef.current;
      if (!ids || !cap || !activeChatId) return;

      if (envelope.type === "prekey_offer") {
        if (ratchetSessionRef.current) return; // already have a session — a duplicate/replayed offer
        await initCrypto();
        let session: RatchetSession;
        let ciphertext: Uint8Array;
        try {
          session = RatchetSession.handshakeInitiate(
            freshSeed32(),
            freshSeed32(),
            b64ToBytes(envelope.verifyingKey),
            b64ToBytes(envelope.bundle),
            b64ToBytes(envelope.bundleSig),
          );
          ciphertext = session.takeHandshakeCiphertext();
        } catch (err) {
          console.warn("[Crypto] Rejected peer prekey bundle (bad signature — possible MITM):", (err as Error).message);
          return;
        }
        ratchetSessionRef.current = session;
        console.log(`[Crypto] PQXDH handshake initiated, verified peer bundle ${shortHex(b64ToBytes(envelope.verifyingKey))}...`);
        pushEnvelope(ids.outMsg, cap, { type: "session_init", ciphertext: bytesToB64(ciphertext) }, MESSAGE_TTL_MS).catch((err) =>
          console.warn("[Transport] session_init push failed:", (err as Error).message),
        );
        return;
      }

      if (envelope.type === "session_init") {
        if (ratchetSessionRef.current) return; // already responded — ignore a duplicate
        const kemKeypair = kemKeypairBytesRef.current;
        if (!kemKeypair) return; // we're not the responder for this chat — not expected on this side
        await initCrypto();
        const session = RatchetSession.handshakeRespond(kemKeypair, b64ToBytes(envelope.ciphertext));
        ratchetSessionRef.current = session;
        console.log("[Crypto] PQXDH handshake completed (responder side) — ratchet session ready");
        return;
      }

      if (envelope.type !== "message") return; // only "receipt" left, handled by the OTHER subscription
      const session = ratchetSessionRef.current;
      if (!session) {
        console.warn("[Crypto] Dropped a message frame — no ratchet session yet (handshake incomplete)");
        return;
      }
      let plaintext: string;
      try {
        plaintext = session.decryptMessage(b64ToBytes(envelope.wire), freshRatchetEntropy());
      } catch (err) {
        console.warn("[Crypto] Dropped an undecryptable frame:", (err as Error).message);
        return;
      }
      console.log(
        `[Crypto] Received ratchet frame seq ${seq} -> decrypted: "${plaintext}" (PQ remixes so far: ${session.pqRemixCount()})`,
      );
      onMessageRef.current(activeChatId, {
        id: crypto.randomUUID(),
        senderId: "them",
        text: plaintext,
        timestamp: envelope.timestamp ?? formatNow(),
      });

      // Sealed Sender++ receipt: padded (same bucket scheme as messages, so it's not distinguishable
      // by size), delayed by a random jitter, and on a SEPARATE queue from the message path — see this
      // file's header comment for why this specific shape is the documented security property, not UX.
      const delay = RECEIPT_DELAY_MIN_MS + Math.random() * (RECEIPT_DELAY_MAX_MS - RECEIPT_DELAY_MIN_MS);
      setTimeout(() => {
        const currentIds = idsRef.current;
        if (!currentIds || chatIdRef.current !== activeChatId) return; // chat changed under us — drop, not stale-deliver
        pushEnvelope(currentIds.outReceipt, cap, { type: "receipt", ackSeq: seq }, RECEIPT_TTL_MS).catch((err) =>
          console.warn("[Transport] receipt push failed:", (err as Error).message),
        );
      }, delay);
    },
    [cap],
  );

  // --- Inbound on the receipt queue: someone acknowledging a message WE sent ---
  const handleInboundReceipt = useCallback((envelope: Envelope) => {
    if (envelope.type !== "receipt") return;
    console.log(`[Transport] Receipt received for our message seq ${envelope.ackSeq}`);
  }, []);

  const msgStatus = useQueueSubscription(idsRef.current?.inMsg ?? null, cap, handleInboundMessage);
  useQueueSubscription(idsRef.current?.inReceipt ?? null, cap, handleInboundReceipt);

  // Only the "responder" role publishes a signed prekey bundle on (re)connect to a chat — PQXDH's
  // handshake is one-sided (only Bob publishes; Alice verifies + encapsulates on receipt of it), so
  // the "initiator" role does nothing here and instead reacts to the incoming `prekey_offer` above.
  useEffect(() => {
    if (!chatId || !cap) return;
    let cancelled = false;
    ratchetSessionRef.current = null;
    identitySeedRef.current = null;
    kemKeypairBytesRef.current = null;
    if (role !== "responder") return;
    const ids = queueIds(chatId, role);
    initCrypto().then(() => {
      if (cancelled) return;
      const identitySeed = freshSeed32();
      const kemKeypair = kemGenerateKeypair(freshSeed32());
      identitySeedRef.current = identitySeed;
      kemKeypairBytesRef.current = kemKeypair;
      const bundle = kemPublicKeyFromKeypair(kemKeypair);
      const verifyingKey = identityVerifyingKey(identitySeed);
      const bundleSig = identitySignBundle(identitySeed, bundle);
      console.log(`[Crypto] Publishing signed prekey bundle, verifying key ${shortHex(verifyingKey)}...`);
      pushEnvelope(
        ids.outMsg,
        cap,
        { type: "prekey_offer", verifyingKey: bytesToB64(verifyingKey), bundle: bytesToB64(bundle), bundleSig: bytesToB64(bundleSig) },
        MESSAGE_TTL_MS,
      ).catch((err) => console.warn("[Transport] prekey_offer push failed:", (err as Error).message));
    });
    return () => {
      cancelled = true;
      ratchetSessionRef.current = null;
      identitySeedRef.current = null;
      kemKeypairBytesRef.current = null;
    };
  }, [chatId, role, cap]);

  const sendMessage = useCallback(
    (text: string) => {
      const ids = idsRef.current;
      const session = ratchetSessionRef.current;
      if (!ids || !cap) return false;
      if (!session) {
        console.warn("[Crypto] Not sending — PQXDH handshake not complete, no ratchet session yet");
        return false;
      }
      const wire = session.encryptMessage(text, freshRatchetEntropy());
      console.log(`[Crypto] Sending ratchet frame (${wire.length} bytes, PQ remixes so far: ${session.pqRemixCount()})`);
      pushEnvelope(ids.outMsg, cap, { type: "message", wire: bytesToB64(wire), timestamp: formatNow() }, MESSAGE_TTL_MS).catch((err) =>
        console.warn("[Transport] message push failed:", (err as Error).message),
      );
      return true;
    },
    [cap],
  );

  return { status: chatId ? msgStatus : "offline", sendMessage };
}
