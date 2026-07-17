// Phase 5 transport spike: wires the active conversation to QueueDO over a raw WebSocket.
//
// E2EE: only ciphertext crosses the wire — `encryptMessage`/`decryptMessage` from
// @vorticity/vortic-core (REAL ChaCha20-Poly1305, RFC 8439, compiled from Rust to WASM) wrap every
// message payload. The key is NO LONGER hardcoded: on connect each peer generates an ephemeral
// X25519 keypair, exchanges public keys over the socket (`handshake`/`handshake_ack` frames), and
// derives a shared ChaCha key via X25519 Diffie-Hellman (`deriveSharedSecret`). Only public keys and
// ciphertext ever cross the wire. Remaining honest gaps (later work): no post-quantum leg (the
// ML-KEM half of kem.rs isn't in this handshake yet), no forward secrecy/ratchet, and the DH is
// UNAUTHENTICATED — a MITM on the very first exchange is undetected (needs signed prekeys). This is
// "a real shared secret over the wire", not the finished PQXDH+ratchet pipeline.
//
// `initCrypto()` must instantiate the WASM before any keygen/derive/encrypt call, so the connect
// effect awaits it before opening the socket.
//
// SCOPING DECISION: this hook takes a single `chatId` (the active conversation only), matching
// QueueDO's one-instance-per-direction model (docs/04) and the task's own framing ("ID активного
// чата", singular) — it does not fan in every chat's queue simultaneously. Selecting a different
// chat tears down the old socket and opens a new one; background chats have no live push until
// selected. Multi-queue fan-in (e.g. via a session-level Durable Object or a socket pool) is a
// later task, not something to speculatively build here.
//
// KNOWN GAP (tracked in docs/06, not solved here): the real QueueDO's WS is receive-only fan-out
// (server -> client) plus a JSON `{type:"ack", upToSeq}` frame client -> server; pushing a NEW
// message is a separate `POST /push` HTTP call with `X-Ttl-Ms`/`X-Size-Bucket` headers and a raw
// ciphertext body (see workers/messaging/src/durable-objects/QueueDO.ts). `sendMessage` below
// currently just does `ws.send(JSON.stringify(...))` on the same socket for both directions, which
// is NOT the real protocol — it is a placeholder that exercises "does the socket open, receive,
// and reconnect correctly" per this task's explicit scope ("просто перегоняем plain-text JSON...
// чтобы проверить транспортный слой"). Reconciling the asymmetric push/subscribe shape is follow-up
// work once the Enrollment<->Messaging capability bridge (blinded queue-id token) exists.
import { useCallback, useEffect, useRef, useState } from "react";
import {
  decryptMessage,
  deriveSharedSecret,
  encryptMessage,
  generateKeyPair,
  initCrypto,
  type X25519KeyPair,
} from "@vorticity/vortic-core";
import { useAuth } from "../contexts/AuthContext";
import { formatNow, type ChatMessage } from "../lib/mockChats";

export type SocketStatus = "offline" | "connecting" | "online" | "reconnecting";

// --- Base64 <-> bytes for putting a 32-byte X25519 public key on the (text) wire ---
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
  return (
    "0x" +
    Array.from(bytes.slice(0, 4))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

// Dev: talk directly to a local `wrangler dev` instance of workers/messaging (default port 8787),
// no TLS, and no `/ws` prefix — that prefix is added by production's edge routing in front of
// `api.vort.xfeatures.net`, not by the Worker itself, so hitting the Worker directly during local
// dev means dropping it (see workers/messaging/src/index.ts's `/queue/:queueId/*` route).
// Prod: capability auth still isn't wired (see docs/06 "still open": real token exchange / blinded
// queue-id capability) — this is still a placeholder host, not a fully wired path.
// NOTE: `vort.xfeatures.net` is Vorticity's own dedicated subdomain — `api.xfeatures.net` is a
// live prod domain for other Xfeatures products and must never be targeted by this messenger.
const WS_BASE_URL = import.meta.env.DEV ? "ws://localhost:8787/queue" : "wss://api.vort.xfeatures.net/ws/queue";

const BASE_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30_000;

// Wire frames. `handshake` is the initial public-key offer sent on connect; `handshake_ack` is the
// reply so a peer who connected AFTER us (and thus missed our initial offer, since the relay only
// fans out to currently-connected sockets) still receives our key. Only an `ack` never triggers a
// further reply, so there is no ping-pong loop.
interface HandshakeWire {
  type: "handshake" | "handshake_ack";
  publicKey: string; // base64 of the 32-byte X25519 public key
}
interface MessageWire {
  type: "message";
  ciphertext: string;
  senderId?: "me" | "them";
  timestamp?: string;
}

function isHandshakeWire(v: unknown): v is HandshakeWire {
  const t = (v as { type?: unknown })?.type;
  return (
    typeof v === "object" &&
    v !== null &&
    (t === "handshake" || t === "handshake_ack") &&
    typeof (v as { publicKey?: unknown }).publicKey === "string"
  );
}
function isMessageWire(v: unknown): v is MessageWire {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as { type?: unknown }).type === "message" &&
    typeof (v as { ciphertext?: unknown }).ciphertext === "string"
  );
}

export function useChatWebSocket(chatId: string | null, onMessage: (chatId: string, message: ChatMessage) => void) {
  const [status, setStatus] = useState<SocketStatus>("offline");
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const attemptRef = useRef(0);

  // Ephemeral X25519 keypair for the current connection, and the ChaCha key derived once the peer's
  // public key arrives. Null until the handshake completes — `sendMessage` refuses to encrypt before
  // then, and incoming ciphertext is dropped until it's set.
  const keyPairRef = useRef<X25519KeyPair | null>(null);
  const sessionKeyRef = useRef<Uint8Array | null>(null);

  // Latest callback in a ref so the connect effect only depends on `chatId`, not on the parent's
  // callback identity — avoids tearing the socket down on every unrelated re-render.
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  // The ZK-verified session capability, presented to the Messaging Worker to authorise the queue. A
  // browser can't set headers on `new WebSocket()`, so it rides as a `?cap=` query param (the Worker
  // accepts that or an Authorization header — see requireCapability there). Kept in a ref so the
  // connect effect doesn't re-run on unrelated auth re-renders; it's stable for a logged-in session.
  const { token } = useAuth();
  const tokenRef = useRef(token);
  tokenRef.current = token;

  useEffect(() => {
    if (!chatId) {
      setStatus("offline");
      return;
    }

    let cancelled = false;
    attemptRef.current = 0;
    sessionKeyRef.current = null;
    keyPairRef.current = null;

    const connect = () => {
      if (cancelled) return;
      setStatus(attemptRef.current === 0 ? "connecting" : "reconnecting");

      const cap = tokenRef.current;
      const capQuery = cap ? `?cap=${encodeURIComponent(cap)}` : "";
      const ws = new WebSocket(`${WS_BASE_URL}/${encodeURIComponent(chatId)}${capQuery}`);
      wsRef.current = ws;

      ws.onopen = () => {
        if (cancelled) return;
        attemptRef.current = 0;
        setStatus("online");
        // Fresh ephemeral keypair per connection; offer our public key to whoever is on the queue.
        const kp = generateKeyPair();
        keyPairRef.current = kp;
        sessionKeyRef.current = null;
        console.log(`[Crypto] Sent handshake, my X25519 pub: ${shortHex(kp.publicKey)}...`);
        ws.send(JSON.stringify({ type: "handshake", publicKey: bytesToB64(kp.publicKey) }));
      };

      ws.onmessage = (event) => {
        if (cancelled || typeof event.data !== "string") return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(event.data);
        } catch {
          return; // malformed frame — ignore rather than crash the socket
        }

        // --- Handshake: derive the shared secret from the peer's public key ---
        if (isHandshakeWire(parsed)) {
          const kp = keyPairRef.current;
          if (!kp) return; // socket not fully open yet — ignore
          let peerPub: Uint8Array;
          try {
            peerPub = b64ToBytes(parsed.publicKey);
          } catch {
            return;
          }
          try {
            sessionKeyRef.current = deriveSharedSecret(kp.privateKey, peerPub);
          } catch (err) {
            console.warn("[Crypto] Handshake failed:", (err as Error).message);
            return;
          }
          console.log(
            `[Crypto] Shared secret established with peer ${shortHex(peerPub)}... -> key ${shortHex(sessionKeyRef.current)}...`,
          );
          // Reply to an initial offer so a peer who joined after us also gets our key. Never reply to
          // an ack (that would loop).
          if (parsed.type === "handshake") {
            ws.send(JSON.stringify({ type: "handshake_ack", publicKey: bytesToB64(kp.publicKey) }));
          }
          return;
        }

        // --- Message: decrypt under the established session key ---
        if (!isMessageWire(parsed)) return;
        const key = sessionKeyRef.current;
        if (!key) {
          console.warn("[Crypto] Dropped a message frame — no session key yet (handshake incomplete)");
          return;
        }
        // Real AEAD: a bad tag / wrong key / truncated payload makes decrypt THROW (never returns
        // garbage). Swallow it per-frame so one undecryptable message can't tear down the socket.
        let plaintext: string;
        try {
          plaintext = decryptMessage(key, parsed.ciphertext);
        } catch (err) {
          console.warn("[Crypto] Dropped an undecryptable frame:", (err as Error).message);
          return;
        }
        console.log(`[Crypto] Received ciphertext: ${parsed.ciphertext} -> decrypted: "${plaintext}"`);
        onMessageRef.current(chatId, {
          id: crypto.randomUUID(),
          senderId: parsed.senderId === "me" ? "me" : "them",
          text: plaintext,
          timestamp: parsed.timestamp ?? formatNow(),
        });
      };

      ws.onclose = () => {
        wsRef.current = null;
        sessionKeyRef.current = null;
        keyPairRef.current = null;
        if (cancelled) return;
        setStatus("reconnecting");
        const attempt = attemptRef.current++;
        const delay = Math.min(BASE_BACKOFF_MS * 2 ** attempt, MAX_BACKOFF_MS);
        reconnectTimerRef.current = setTimeout(connect, delay);
      };

      // The browser fires `close` right after `error` for connection failures, so reconnect
      // scheduling lives in `onclose` only — this just avoids an unhandled-error console spew.
      ws.onerror = () => {};
    };

    // The WASM must be instantiated before any keygen/derive/encrypt runs, so gate the socket on it.
    // It's a one-time async instantiation (idempotent across mounts/chats); by the time the socket
    // opens, `generateKeyPair`/`deriveSharedSecret`/`encryptMessage` are callable. `initCrypto()`
    // never rejects in practice (local bundled asset), but if it did we'd simply never connect.
    initCrypto().then(
      () => {
        if (!cancelled) connect();
      },
      (err) => {
        console.error("[Crypto] WASM init failed — not connecting:", err);
        if (!cancelled) setStatus("offline");
      },
    );

    return () => {
      cancelled = true;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
      wsRef.current = null;
      sessionKeyRef.current = null;
      keyPairRef.current = null;
    };
  }, [chatId]);

  const sendMessage = useCallback((text: string) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    const key = sessionKeyRef.current;
    if (!key) {
      console.warn("[Crypto] Not sending — handshake not complete, no shared key yet");
      return false;
    }
    const ciphertext = encryptMessage(key, text);
    console.log(`[Crypto] Sending ciphertext: ${ciphertext}`);
    ws.send(JSON.stringify({ type: "message", senderId: "me", ciphertext, timestamp: formatNow() }));
    return true;
  }, []);

  return { status, sendMessage };
}
