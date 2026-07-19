// Opt-in online/typing presence (2026-07, closes docs/06's "Still open: PresenceDO"). See
// workers/messaging/src/durable-objects/PresenceDO.ts's header comment for the server-side protocol
// and the honest "sealed = architectural, not per-frame AEAD" scope note — this hook is the client
// half of that same design, not a stronger guarantee than the server actually provides.
//
// OPT-IN, PER CHAT (docs/05: "Off by default (metadata hygiene)"): this hook only opens a socket when
// `enabled` is true — the caller (ActiveChatPanel, via Chats.tsx's `presenceEnabled` toggle on the
// Chat record) controls that, this hook has no default-on behavior of its own.
//
// SCOPED TO THE ACTIVE CHAT ONLY, same limitation useQueueTransport.ts already has and states
// plainly: a background (non-active) chat has no live socket of any kind, so its list-row "online"
// dot only ever reflects presence that was live while it WAS the active chat, not a continuously
// tracked background state. Running N idle presence sockets for every chat in the list — not just
// the open one — is real future work, not built here (same "not yet needed" scoping docs/06 already
// gives QueueDO's own single-active-chat model).
import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../contexts/AuthContext";

const WS_BASE_URL = import.meta.env.DEV ? "ws://localhost:8789/presence" : "wss://relay.vort.xfeatures.net/presence";

const BASE_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30_000;
// How long a received "typing" signal stays true with no follow-up — a real UI needs SOME decay,
// since the protocol has no explicit "stopped typing" frame (docs/06 PresenceDO entry: relayed
// signals are transient, not stateful on the server). Comfortably longer than any realistic
// keystroke gap, short enough that closing the tab / an actual stop reads correctly within a beat.
const TYPING_DECAY_MS = 4000;
// Client-side throttle on outbound "typing" sends — an onChange-per-keystroke send would otherwise
// flood the relay for no benefit (the peer only needs a decaying "still typing" signal, not one
// event per character).
const TYPING_SEND_INTERVAL_MS = 2000;

type PresenceFrame = { type: "online" } | { type: "offline" } | { type: "typing" };

function isPresenceFrame(v: unknown): v is PresenceFrame {
  const t = (v as { type?: unknown } | null)?.type;
  return t === "online" || t === "offline" || t === "typing";
}

export interface PresenceState {
  peerOnline: boolean;
  peerTyping: boolean;
  /** Call on every draft keystroke — internally throttled, safe to call as often as onChange fires. */
  sendTyping: () => void;
}

export function usePresence(chatId: string | null, enabled: boolean): PresenceState {
  const { token: cap } = useAuth();
  const [peerOnline, setPeerOnline] = useState(false);
  const [peerTyping, setPeerTyping] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const typingDecayRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastTypingSentAtRef = useRef(0);

  useEffect(() => {
    setPeerOnline(false);
    setPeerTyping(false);
    if (typingDecayRef.current) clearTimeout(typingDecayRef.current);
    if (!chatId || !enabled || !cap) return;

    let cancelled = false;
    let attempt = 0;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (cancelled) return;
      const ws = new WebSocket(`${WS_BASE_URL}/${encodeURIComponent(chatId)}?cap=${encodeURIComponent(cap)}`);
      wsRef.current = ws;

      ws.onopen = () => {
        attempt = 0;
      };

      ws.onmessage = (event) => {
        if (cancelled || typeof event.data !== "string") return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(event.data);
        } catch {
          return;
        }
        if (!isPresenceFrame(parsed)) return;
        if (parsed.type === "online") setPeerOnline(true);
        else if (parsed.type === "offline") setPeerOnline(false);
        else if (parsed.type === "typing") {
          setPeerTyping(true);
          if (typingDecayRef.current) clearTimeout(typingDecayRef.current);
          typingDecayRef.current = setTimeout(() => setPeerTyping(false), TYPING_DECAY_MS);
        }
      };

      ws.onclose = () => {
        wsRef.current = null;
        setPeerOnline(false);
        setPeerTyping(false);
        if (cancelled) return;
        const delay = Math.min(BASE_BACKOFF_MS * 2 ** attempt++, MAX_BACKOFF_MS);
        reconnectTimer = setTimeout(connect, delay);
      };
      ws.onerror = () => {};
    };

    connect();
    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (typingDecayRef.current) clearTimeout(typingDecayRef.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [chatId, enabled, cap]);

  const sendTyping = useCallback(() => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const now = Date.now();
    if (now - lastTypingSentAtRef.current < TYPING_SEND_INTERVAL_MS) return;
    lastTypingSentAtRef.current = now;
    ws.send(JSON.stringify({ type: "typing" }));
  }, []);

  return { peerOnline, peerTyping, sendTyping };
}
