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
// ciphertext. A real `PrekeyDO` (docs/03 §4, a server-side directory) is still separate, not-yet-built
// infrastructure; this pass replaces the KEY EXCHANGE cryptography, not identity/prekey distribution.
//
// IDENTITY PERSISTENCE + RE-HANDSHAKE RECOVERY (2026-07, closes a real gap the user caught: identity
// material used to be generated FRESH on every mount, meaning a reload silently orphaned any
// established ratchet session on both sides with no recovery path — the peer's `if
// (ratchetSessionRef.current) return` guards treated a legitimate re-handshake attempt as a duplicate
// to ignore). The "responder" role's `identitySeed`/`kemKeypair` are now generated ONCE per `chatId`
// and sealed via `lib/secureStore.ts` (non-extractable AES-GCM, IndexedDB) — stable across reloads,
// so a re-mounted responder republishes the EXACT SAME signed bundle, not a new one. This turns
// "republish while a session already exists" into a reliable, cryptographically-groundable recovery
// signal instead of an ambiguous replay: the initiator can tell a genuine reset (same verifying
// key + bundle) apart from a substituted identity (different key — rejected, not silently accepted),
// and the responder can tell a genuine new handshake attempt apart from an exact replay (QueueDO
// evicts a message once acked, so a SECOND session_init on the wire is never a backlog replay of the
// first — see `handleInboundMessage` below for exactly what this does and does not trust).
import { useCallback, useEffect, useRef, useState } from "react";
import { clearFromStore, sealToStore, unsealFromStore } from "../lib/secureStore";
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
import { formatNow, type ChatMessage, type TransportRole } from "../lib/chat";
import { ohttpFetch } from "../lib/ohttp";
import {
  consumeFromPool,
  fetchAndPopBundle,
  fetchStatus,
  publishBundle,
  topUpPool,
  ONETIME_REPLENISH_THRESHOLD,
  SIGNED_PREKEY_ROTATE_AFTER_MS,
  type FetchedBundle,
} from "../lib/prekeys";
import { acquireLease, releaseLease } from "../lib/deviceLease";

/** Loads the responder's persisted identity/signed-prekey material for `chatId`, generating it fresh
 * on the very first mount, and ROTATING the signed prekey (fresh KEM keypair, same long-term Ed25519
 * identity — identity keys don't rotate, only the prekey they sign, matching classic X3DH) once it's
 * older than `SIGNED_PREKEY_ROTATE_AFTER_MS`. See this file's header comment for why the identity
 * itself needs to be stable across reloads; rotation age is tracked in a third sealed record
 * (`ratchet-kem-rotated-at`) alongside the identity/KEM material this already persisted. */
async function getOrRotateIdentity(chatId: string): Promise<{ identitySeed: Uint8Array; kemKeypair: Uint8Array; rotated: boolean }> {
  await initCrypto(); // idempotent — kemGenerateKeypair below needs WASM initialized
  const [sealedIdentity, sealedKem, sealedRotatedAt] = await Promise.all([
    unsealFromStore(`ratchet-identity:${chatId}`),
    unsealFromStore(`ratchet-kem:${chatId}`),
    unsealFromStore(`ratchet-kem-rotated-at:${chatId}`),
  ]);
  const identitySeed = sealedIdentity ?? freshSeed32();
  const rotatedAt = sealedRotatedAt ? Number(new TextDecoder().decode(sealedRotatedAt)) : 0;
  const isStale = !sealedKem || Date.now() - rotatedAt > SIGNED_PREKEY_ROTATE_AFTER_MS;

  if (!isStale) {
    return { identitySeed, kemKeypair: sealedKem!, rotated: false };
  }
  const kemKeypair = kemGenerateKeypair(freshSeed32());
  await Promise.all([
    sealToStore(`ratchet-identity:${chatId}`, identitySeed),
    sealToStore(`ratchet-kem:${chatId}`, kemKeypair),
    sealToStore(`ratchet-kem-rotated-at:${chatId}`, new TextEncoder().encode(String(Date.now()))),
  ]);
  return { identitySeed, kemKeypair, rotated: true };
}

function freshSeed32(): Uint8Array {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return seed;
}

export type SocketStatus = "offline" | "connecting" | "online" | "reconnecting";
export type { TransportRole };

// R25 follow-up (2026-07): `MESSAGING_API_URL` is gone — `pushEnvelope` below goes through
// `ohttpFetch` (../lib/ohttp.ts) instead of hitting this Worker's origin directly.
//
// R26 (2026-07): `WS_BASE_URL` now points at `workers/ohttp-relay` (the same Relay `ohttpFetch` uses),
// not the Messaging Worker directly — RFC 9458 can't wrap a persistent WS connection (single-shot
// request/response only), so the Relay instead does a plain network-level proxy of the WS upgrade
// (see workers/ohttp-relay/src/index.ts's `proxyWebSocket`). IMPORTANT, stated plainly: this is
// implemented against Cloudflare's documented same-zone/cross-zone `CF-Connecting-IP` behavior but is
// NOT independently live-verified — that behavior doesn't exist in local `wrangler dev`, and nothing
// in this project is deployed to a real Cloudflare zone yet. See docs/06's R26 entry before treating
// this as a confirmed fix rather than a documented-but-unverified one.
const WS_BASE_URL = import.meta.env.DEV ? "ws://localhost:8789/queue" : "wss://relay.vort.xfeatures.net/queue";

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
  // Rotation pass (2026-07): present iff the initiator's bundle came with a one-time prekey (fetched
  // from PrekeyDO, either proactively on mount or included in a queue-pushed prekey_offer) — tells
  // the responder WHICH locally-persisted one-time private keypair to consume for decapsulation (see
  // lib/prekeys.ts's `consumeFromPool`). Absent means "plain signed-prekey-only handshake", same as
  // before this pass — real X3DH tolerates an exhausted one-time pool, this is that fallback.
  oneTimePrekeyId?: string;
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
  // Device-linking pass: whether THIS device currently holds the live-session lease for this chat
  // (DeviceLeaseDO) — see lib/deviceLease.ts and DeviceLeaseDO.ts's header comment for why this
  // exists (two linked devices both running a live ratchet for the same chat would desync it, for
  // the PEER too, not just the linked user). `idsRef` below is gated on this: no lease means no
  // queue ids means every subscription/publish effect naturally no-ops, without touching each one.
  const [hasLease, setHasLease] = useState(false);
  const [leaseHeldByOther, setLeaseHeldByOther] = useState(false);
  // Own long-term-for-this-chat identity + hybrid prekey material — only meaningful for the
  // "responder" role (only Bob publishes a bundle in PQXDH's one-sided handshake). Persisted per
  // `chatId` via lib/secureStore.ts (see this file's header comment) — stable across reloads, not
  // regenerated every mount.
  const identitySeedRef = useRef<Uint8Array | null>(null);
  const kemKeypairBytesRef = useRef<Uint8Array | null>(null);
  const ratchetSessionRef = useRef<RatchetSession | null>(null);
  // The peer identity (initiator side only) our CURRENT ratchetSessionRef was established against —
  // lets handleInboundMessage tell "peer reset, same identity, please re-handshake" apart from "a
  // different identity is trying to replace an active session" (rejected, not silently accepted).
  const trustedPeerBundleRef = useRef<{ verifyingKey: string; bundle: string } | null>(null);
  const idsRef = useRef<QueueIds | null>(null);
  idsRef.current = chatId && hasLease ? queueIds(chatId, role) : null;

  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  const chatIdRef = useRef(chatId);
  chatIdRef.current = chatId;

  // Initiator side of the handshake, given a peer bundle from EITHER source: a queue-pushed
  // `prekey_offer` (fast path, both sides live at once) or a proactive PrekeyDO fetch on mount
  // (rotation pass — works even if the responder is currently offline). Factored out so both call
  // sites share the exact same signature-verification, re-handshake-recovery, and session_init-push
  // logic rather than maintaining two copies that could drift.
  const initiateHandshakeFromBundle = useCallback(
    async (bundle: { verifyingKey: string; bundle: string; bundleSig: string; onetimePrekey?: { id: string; pubKey: string } | null }) => {
      const ids = idsRef.current;
      if (!ids || !cap) return;

      const isSamePeer =
        trustedPeerBundleRef.current?.verifyingKey === bundle.verifyingKey && trustedPeerBundleRef.current?.bundle === bundle.bundle;
      if (ratchetSessionRef.current) {
        if (!isSamePeer) {
          // A DIFFERENT identity republished while we already trust one for this chat — the same
          // caution `handshakeInitiate`'s own signature check applies to a first contact applies
          // here too: never silently swap the peer we're talking to mid-session.
          console.warn("[Crypto] Ignored a prekey bundle from a DIFFERENT identity than our active session — possible identity change or attack, not auto-accepted.");
          return;
        }
        console.log("[Crypto] Peer republished its (unchanged) prekey bundle while we had an active session — treating as a stale-session recovery signal, re-handshaking.");
        // Same identity, so fall through and redo the handshake — this is what actually recovers
        // a session after the RESPONDER side reloaded (their persisted identity is stable, so this
        // republish is byte-identical to their original one, not a new/different bundle).
      }
      await initCrypto();
      let session: RatchetSession;
      let ciphertext: Uint8Array;
      let oneTimePrekeyId: string | undefined;
      try {
        if (bundle.onetimePrekey) {
          session = RatchetSession.handshakeInitiateWithOnetime(
            freshSeed32(),
            freshSeed32(),
            freshSeed32(),
            b64ToBytes(bundle.verifyingKey),
            b64ToBytes(bundle.bundle),
            b64ToBytes(bundle.bundleSig),
            b64ToBytes(bundle.onetimePrekey.pubKey),
          );
          oneTimePrekeyId = bundle.onetimePrekey.id;
        } else {
          // No one-time prekey available (PrekeyDO's pool was empty, or this bundle came from the
          // queue-pushed prekey_offer fast path, which never carries one — see this file's header
          // comment on the two-source split) — real X3DH tolerates this, same strength as before
          // this pass, just without the extra one-time-prekey hardening.
          session = RatchetSession.handshakeInitiate(
            freshSeed32(),
            freshSeed32(),
            b64ToBytes(bundle.verifyingKey),
            b64ToBytes(bundle.bundle),
            b64ToBytes(bundle.bundleSig),
          );
        }
        ciphertext = session.takeHandshakeCiphertext();
      } catch (err) {
        console.warn("[Crypto] Rejected peer prekey bundle (bad signature — possible MITM):", (err as Error).message);
        return;
      }
      ratchetSessionRef.current = session;
      trustedPeerBundleRef.current = { verifyingKey: bundle.verifyingKey, bundle: bundle.bundle };
      console.log(
        `[Crypto] PQXDH handshake initiated${oneTimePrekeyId ? " (one-time-prekey strengthened)" : ""}, verified peer bundle ${shortHex(b64ToBytes(bundle.verifyingKey))}...`,
      );
      pushEnvelope(
        ids.outMsg,
        cap,
        { type: "session_init", ciphertext: bytesToB64(ciphertext), ...(oneTimePrekeyId ? { oneTimePrekeyId } : {}) },
        MESSAGE_TTL_MS,
      ).catch((err) => console.warn("[Transport] session_init push failed:", (err as Error).message));
    },
    [cap],
  );

  // --- Inbound on the message queue: prekey_offer / session_init / message ---
  const handleInboundMessage = useCallback(
    async (envelope: Envelope, seq: number) => {
      const ids = idsRef.current;
      const activeChatId = chatIdRef.current;
      if (!ids || !cap || !activeChatId) return;

      if (envelope.type === "prekey_offer") {
        // The queue-pushed fast path never carries a one-time prekey (see this file's header comment
        // and initiateHandshakeFromBundle's own doc) — only a proactive PrekeyDO fetch can supply one.
        await initiateHandshakeFromBundle({ verifyingKey: envelope.verifyingKey, bundle: envelope.bundle, bundleSig: envelope.bundleSig });
        return;
      }

      if (envelope.type === "session_init") {
        const kemKeypair = kemKeypairBytesRef.current;
        if (!kemKeypair) return; // we're not the responder for this chat — not expected on this side
        await initCrypto();
        let session: RatchetSession;
        try {
          if (envelope.oneTimePrekeyId) {
            const onetimeKeypair = await consumeFromPool(chatIdRef.current ?? "", envelope.oneTimePrekeyId);
            if (!onetimeKeypair) {
              // This device never had (or already consumed) the referenced one-time keypair — e.g.
              // local storage was cleared after PrekeyDO already handed its public half to some
              // initiator (see lib/prekeys.ts's header comment, the one honestly-unreconciled gap in
              // this pass). Dropping is correct: falling back to the plain signed-prekey path here
              // would silently accept a session_init this device cannot actually decapsulate correctly.
              console.warn("[Crypto] session_init referenced a one-time prekey this device doesn't have — dropping (see lib/prekeys.ts's local-pool-loss gap).");
              return;
            }
            session = RatchetSession.handshakeRespondWithOnetime(kemKeypair, onetimeKeypair, b64ToBytes(envelope.ciphertext));
          } else {
            session = RatchetSession.handshakeRespond(kemKeypair, b64ToBytes(envelope.ciphertext));
          }
        } catch (err) {
          // A stale/corrupt ciphertext, or a genuine replay attempt that fails to decapsulate against
          // our current keypair — dropped, not fatal. A LEGITIMATE new session_init always decapsulates
          // successfully (only we hold the matching KEM private key), which is what makes accepting it
          // below safe even while a session already exists — see this file's header comment.
          console.warn("[Crypto] Failed to decapsulate session_init — dropping:", (err as Error).message);
          return;
        }
        if (ratchetSessionRef.current) {
          console.log("[Crypto] Received a NEW session_init while a session was already active — decapsulated successfully against our stable keypair, accepting as a legitimate re-handshake (peer likely reloaded).");
        }
        ratchetSessionRef.current = session;
        console.log(`[Crypto] PQXDH handshake completed (responder side)${envelope.oneTimePrekeyId ? " (one-time-prekey strengthened)" : ""} — ratchet session ready`);
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

  // Resets live session state ONLY when the ACTIVE CHAT itself changes — deliberately NOT in the
  // lease-acquire effect below (whose own deps include `cap`/`chatId` too, but which may also fire
  // again on a heartbeat-driven state update within the SAME chat) and NOT at the top of the
  // responder-mount effect the way earlier passes had it, because the hydration step below needs to
  // populate `ratchetSessionRef` from an imported device-link payload BEFORE the responder/initiator
  // effects run in that same commit — those effects blindly nulling it back out on every one of
  // their own dependency changes would silently discard a just-imported session.
  useEffect(() => {
    ratchetSessionRef.current = null;
    identitySeedRef.current = null;
    kemKeypairBytesRef.current = null;
    trustedPeerBundleRef.current = null;
  }, [chatId]);

  // Device-linking pass: acquire (and heartbeat-renew) the live-session lease for this chat before
  // any queue subscription/publish is allowed to run — see DeviceLeaseDO.ts's header comment. Renews
  // well inside the server's LEASE_TTL_MS (45s) margin; releases on unmount/chat change so a clean
  // tab-close or chat-switch frees the lease immediately rather than waiting out the full TTL.
  //
  // HYDRATION: on the FIRST successful acquire for this chat (i.e. no live session yet), checks for
  // an imported ratchet-state blob (lib/deviceLink.ts's `applyLinkPayload`, sealed via
  // `ratchet-imported-state:${chatId}`) and, if present, reconstructs the session directly via
  // `RatchetSession.importState` — the whole point of device-linking being "hand over the EXISTING
  // session", not "re-handshake from scratch" (which would need the peer's cooperation and lose any
  // forward-secrecy-relevant state the exporting device already had).
  useEffect(() => {
    setHasLease(false);
    setLeaseHeldByOther(false);
    if (!chatId || !cap) return;
    let cancelled = false;

    const tryAcquire = async () => {
      try {
        const result = await acquireLease(chatId, cap);
        if (cancelled) return;
        if (result.granted && !ratchetSessionRef.current) {
          const importedBytes = await unsealFromStore(`ratchet-imported-state:${chatId}`);
          if (importedBytes && !cancelled) {
            try {
              const imported = JSON.parse(new TextDecoder().decode(importedBytes)) as {
                ratchetStateB64: string;
                trustedPeerBundle: { verifyingKey: string; bundle: string } | null;
              };
              ratchetSessionRef.current = RatchetSession.importState(b64ToBytes(imported.ratchetStateB64));
              trustedPeerBundleRef.current = imported.trustedPeerBundle;
              await clearFromStore(`ratchet-imported-state:${chatId}`);
              console.log("[Crypto] Hydrated ratchet session from an imported device-link payload — continuing the existing conversation.");
            } catch (err) {
              console.warn("[Crypto] Failed to import linked device's ratchet state (will fall back to a fresh handshake):", (err as Error).message);
            }
          }
        }
        setHasLease(result.granted);
        setLeaseHeldByOther(!result.granted);
        if (!result.granted) {
          console.warn(
            `[Transport] Chat is live on another linked device (holder ${result.holder}) — staying read-only until it releases or its lease expires.`,
          );
        }
      } catch (err) {
        if (cancelled) return;
        // Fail CLOSED (no live session), not open — an acquire we can't confirm succeeded must be
        // treated as "not held", the same safety-over-availability call DeviceLeaseDO's own expiry
        // logic makes; silently proceeding without a confirmed lease risks the exact desync this
        // mechanism exists to prevent.
        console.warn("[Transport] Lease acquire failed — staying read-only:", (err as Error).message);
        setHasLease(false);
        setLeaseHeldByOther(false);
      }
    };

    tryAcquire();
    const heartbeat = setInterval(tryAcquire, 15_000);
    return () => {
      cancelled = true;
      clearInterval(heartbeat);
      releaseLease(chatId, cap).catch(() => {});
    };
  }, [chatId, cap]);

  // Only the "responder" role publishes a signed prekey bundle on (re)connect to a chat — PQXDH's
  // handshake is one-sided (only Bob publishes; Alice verifies + encapsulates on receipt of it).
  // ROTATION PASS (2026-07): in addition to the queue-pushed `prekey_offer` fast path (unchanged),
  // this now ALSO publishes the bundle — and tops up a one-time-prekey pool — to PrekeyDO, so an
  // initiator can fetch it asynchronously even while this device is offline (see lib/prekeys.ts).
  // Gated on `hasLease` (device-linking pass): never runs without the live-session lease, so a
  // second linked device that lost the race stays read-only instead of racing the ratchet state.
  useEffect(() => {
    if (!chatId || !cap || !hasLease) return;
    let cancelled = false;
    if (role !== "responder") return;
    const ids = queueIds(chatId, role);
    (async () => {
      const { identitySeed, kemKeypair, rotated } = await getOrRotateIdentity(chatId);
      if (cancelled) return;
      identitySeedRef.current = identitySeed;
      kemKeypairBytesRef.current = kemKeypair;
      const bundlePub = kemPublicKeyFromKeypair(kemKeypair);
      const verifyingKey = identityVerifyingKey(identitySeed);
      const bundleSig = identitySignBundle(identitySeed, bundlePub);
      console.log(
        `[Crypto] Publishing signed prekey bundle (${rotated ? "freshly rotated" : "persisted"}), verifying key ${shortHex(verifyingKey)}...`,
      );
      // Fast path: unchanged from before this pass — reaches an initiator only if already subscribed.
      pushEnvelope(
        ids.outMsg,
        cap,
        { type: "prekey_offer", verifyingKey: bytesToB64(verifyingKey), bundle: bytesToB64(bundlePub), bundleSig: bytesToB64(bundleSig) },
        MESSAGE_TTL_MS,
      ).catch((err) => console.warn("[Transport] prekey_offer push failed:", (err as Error).message));

      // Durable path: publish to PrekeyDO so a not-yet-subscribed (or entirely offline) initiator can
      // fetch this bundle later. Only replenishes the one-time pool if it's actually running low
      // (ONETIME_REPLENISH_THRESHOLD) — avoids needless key churn/publish traffic on every ordinary
      // mount once the pool is already healthy.
      try {
        const status = await fetchStatus(chatId, cap);
        if (cancelled) return;
        const onetimePubKeys = status.onetimeCount < ONETIME_REPLENISH_THRESHOLD ? await topUpPool(chatId, status.onetimeCount) : [];
        if (cancelled) return;
        const result = await publishBundle(chatId, cap, {
          verifyingKey: bytesToB64(verifyingKey),
          signedPrekeyPub: bytesToB64(bundlePub),
          signedPrekeySig: bytesToB64(bundleSig),
          onetimePubKeys,
        });
        console.log(`[Crypto] PrekeyDO bundle published (chat ${chatId.slice(0, 12)}...), one-time pool now ${result.onetimeCount}`);
      } catch (err) {
        // PrekeyDO reachability is a durability/async-handshake IMPROVEMENT, not the only path a
        // handshake can succeed through — the queue-pushed prekey_offer above still works standalone
        // (exactly as it did before this pass), so a publish failure here is logged, not fatal.
        console.warn("[Transport] PrekeyDO publish failed (queue-pushed prekey_offer still works):", (err as Error).message);
      }
    })();
    // Deliberately does NOT null `ratchetSessionRef`/`identitySeedRef`/`kemKeypairBytesRef` here —
    // only the chatId-scoped effect above does that. This cleanup can fire on a transient `hasLease`
    // flip (e.g. one missed heartbeat) that has nothing to do with actually leaving the chat; wiping
    // a live or just-hydrated session on every such flip would be strictly worse than the mechanism
    // this whole lease system exists to prevent.
    return () => {
      cancelled = true;
    };
  }, [chatId, role, cap, hasLease]);

  // INITIATOR side of the rotation pass: proactively fetch the responder's bundle from PrekeyDO on
  // mount instead of only passively waiting for a queue-pushed `prekey_offer` (which requires the
  // responder to be live at roughly the same time). Falls back to that passive wait exactly as
  // before this pass if PrekeyDO 404s (responder hasn't published yet) or the fetch otherwise fails.
  // Also gated on `hasLease`, same reasoning as the responder effect above. AND skips entirely if a
  // session is already live (device-linking pass: a hydrated import means there's nothing to
  // handshake — fetching anyway would needlessly burn a one-time prekey from PrekeyDO's pool for a
  // fetch whose result `initiateHandshakeFromBundle` would just reject as "different/unknown peer"
  // relative to the imported session's already-established state).
  useEffect(() => {
    if (!chatId || !cap || !hasLease || role !== "initiator" || ratchetSessionRef.current) return;
    let cancelled = false;
    (async () => {
      let bundle: FetchedBundle | null;
      try {
        bundle = await fetchAndPopBundle(chatId, cap);
      } catch (err) {
        console.warn("[Transport] Proactive PrekeyDO fetch failed (will fall back to the queue prekey_offer):", (err as Error).message);
        return;
      }
      if (cancelled || !bundle) return;
      console.log("[Crypto] Fetched responder's bundle from PrekeyDO proactively — initiating handshake without waiting for a queue push.");
      await initiateHandshakeFromBundle({
        verifyingKey: bundle.verifyingKey,
        bundle: bundle.signedPrekeyPub,
        bundleSig: bundle.signedPrekeySig,
        onetimePrekey: bundle.onetimePrekey,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [chatId, role, cap, hasLease, initiateHandshakeFromBundle]);

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

  // Device-linking pass: exposes the LIVE ratchet session's state export (see ratchet.rs's
  // `exportState`/`RatchetSession.exportState()`) for lib/deviceLink.ts to seal and hand to a second
  // device — `null` if there's no established session yet (nothing to link) or this device doesn't
  // hold the lease (linking FROM a read-only device would hand over stale state; the caller should
  // only offer the "link a device" action when `hasLease` is true).
  const exportRatchetState = useCallback((): Uint8Array | null => {
    return ratchetSessionRef.current?.exportState() ?? null;
  }, []);

  // Alongside the ratchet bytes, an initiator-role export should also carry the peer bundle it
  // trusts (device-linking pass) — without it, a linked device would have a working session but no
  // record of which identity it belongs to, silently disabling the existing re-handshake-recovery
  // detection in `initiateHandshakeFromBundle` for that device. `null` on the responder side (who has
  // no `trustedPeerBundleRef` — only initiators verify a peer bundle).
  const getTrustedPeerBundle = useCallback((): { verifyingKey: string; bundle: string } | null => {
    return trustedPeerBundleRef.current;
  }, []);

  return {
    status: chatId ? msgStatus : "offline",
    sendMessage,
    hasLease,
    leaseHeldByOther,
    exportRatchetState,
    getTrustedPeerBundle,
  };
}
