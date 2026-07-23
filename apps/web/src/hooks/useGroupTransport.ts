// First group-chat client pass (2026-07) — live transport for one MLS group: WS subscribe to
// GroupDO's blind ordering/fan-out log (reconnect/backoff, same shape as useQueueTransport.ts's
// useQueueSubscription), decrypt inbound entries via MlsGroupSession.processMessage (branching on
// commit vs application message), and push outbound application messages. See lib/group.ts for
// everything this hook does NOT own: creating a group, the invite/join key-package-then-Welcome
// exchange, and sealed session persistence (this hook loads/saves through those same functions).
import { useCallback, useEffect, useRef, useState } from "react";
import type { MlsGroupSession } from "@vorticity/vortic-core";
import { checkAndProcessJoinRequest, loadGroupSession, pushToGroupLog, saveGroupSession } from "../lib/group";

// R26-style relay routing (see workers/ohttp-relay's WS_PROXY_PATTERN, extended to include `group`
// as part of this same pass) — identical convention to useQueueTransport.ts's WS_BASE_URL.
const WS_BASE_URL = import.meta.env.DEV ? "ws://localhost:8789/group" : "wss://relay.vort.xfeatures.net/group";

export type GroupSocketStatus = "connecting" | "online" | "reconnecting" | "offline";

interface WireEntry {
  type: "message";
  seq: number;
  blob: string;
  sizeBucket: number;
  senderQueueId: string | null;
  enqueuedAt: number;
}

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function useGroupTransport(groupId: string | null, cap: string | null, onMessage: (text: string, timestamp: string) => void) {
  const [status, setStatus] = useState<GroupSocketStatus>("offline");
  const [hasSession, setHasSession] = useState(false);
  const sessionRef = useRef<MlsGroupSession | null>(null);
  const maxSeqRef = useRef(0);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;
  // Opaque per-connection anti-echo tag (GroupDO.ts's own term) — stable for this hook instance's
  // lifetime, NOT an identity. Without this, a sender's own push would come straight back through the
  // live fan-out and render as if someone else had sent it (there's no other way to tell "my own
  // message, echoed" apart from "someone else's message" once it's just anonymous ciphertext).
  const senderQueueIdRef = useRef<string>(crypto.randomUUID());

  // Load this group's persisted session whenever the active group changes.
  useEffect(() => {
    sessionRef.current = null;
    maxSeqRef.current = 0;
    setHasSession(false);
    if (!groupId) return;
    let cancelled = false;
    loadGroupSession(groupId).then((s) => {
      if (cancelled) return;
      sessionRef.current = s;
      setHasSession(s !== null);
    });
    return () => {
      cancelled = true;
    };
  }, [groupId]);

  const processEntry = useCallback(
    async (entry: WireEntry) => {
      // Defensive de-dup: a WS reconnect re-flushes the full backlog since whatever `since_seq` this
      // connection attempt opened with — same "at-least-once delivery, dedupe by a monotonic id"
      // reasoning chatReducer.ts's inbound text-message handling already applies for 1:1 chats.
      if (entry.seq <= maxSeqRef.current) return;
      maxSeqRef.current = entry.seq;
      const session = sessionRef.current;
      if (!session || !groupId) return;
      try {
        const wire = b64ToBytes(entry.blob);
        const [isCommitByte, plaintextBytes] = session.processMessage(wire) as [Uint8Array, Uint8Array];
        await saveGroupSession(groupId, session);
        if (isCommitByte.length > 0 && isCommitByte[0] === 1) return; // membership change — nothing to render
        onMessageRef.current(new TextDecoder().decode(plaintextBytes), new Date(entry.enqueuedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
      } catch (err) {
        // A commit/message this session can't process (e.g. arrived before this device finished
        // joining) is dropped, not fatal — same tolerance QueueDO's inbound handling already has for
        // a single bad frame.
        console.warn("[Group] Failed to process inbound entry:", (err as Error).message);
      }
    },
    [groupId],
  );

  useEffect(() => {
    if (!groupId || !cap) {
      setStatus("offline");
      return;
    }
    let cancelled = false;
    let attempt = 0;
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (cancelled) return;
      setStatus(attempt === 0 ? "connecting" : "reconnecting");
      ws = new WebSocket(
        `${WS_BASE_URL}/${encodeURIComponent(groupId)}?cap=${encodeURIComponent(cap)}&since_seq=${maxSeqRef.current}&sender_queue_id=${encodeURIComponent(senderQueueIdRef.current)}`,
      );
      ws.onopen = () => {
        if (cancelled) return;
        attempt = 0;
        setStatus("online");
      };
      ws.onmessage = (event) => {
        if (cancelled || typeof event.data !== "string") return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(event.data);
        } catch {
          return;
        }
        const entry = parsed as Partial<WireEntry>;
        if (entry.type !== "message" || typeof entry.seq !== "number" || typeof entry.blob !== "string") return;
        void processEntry(entry as WireEntry);
      };
      ws.onclose = () => {
        if (cancelled) return;
        setStatus("reconnecting");
        const delay = Math.min(1000 * 2 ** attempt, 15000);
        attempt++;
        reconnectTimer = setTimeout(connect, delay);
      };
      ws.onerror = () => {
        ws?.close();
      };
    };
    connect();
    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [groupId, cap, processEntry]);

  const sendMessage = useCallback(
    async (text: string): Promise<{ ok: boolean }> => {
      const session = sessionRef.current;
      if (!session || !groupId || !cap) return { ok: false };
      try {
        const wire = session.encryptMessage(text);
        await saveGroupSession(groupId, session);
        await pushToGroupLog(groupId, cap, wire, senderQueueIdRef.current);
        return { ok: true };
      } catch (err) {
        console.warn("[Group] Failed to send:", (err as Error).message);
        return { ok: false };
      }
    },
    [groupId, cap],
  );

  /** Called after this device joins (via lib/group.ts's requestToJoinGroup/pollForWelcome flow) —
   * refreshes the in-hook session ref/state without needing a remount, so a just-completed join
   * immediately unlocks send/receive. */
  const refreshSession = useCallback(async () => {
    if (!groupId) return;
    const s = await loadGroupSession(groupId);
    sessionRef.current = s;
    setHasSession(s !== null);
  }, [groupId]);

  /** Inviter side: checks one invite's inbound leg for a prospective member's KeyPackage and, if
   * present, adds them — using THIS hook's own live session object (not a second independently-
   * loaded copy), since `MlsGroupSession` mutates in place and only one instance should ever be
   * live for a group in a single tab. Returns whether a member was actually added this call. */
  const processJoinRequest = useCallback(
    async (inviteId: string): Promise<boolean> => {
      const session = sessionRef.current;
      if (!session || !groupId || !cap) return false;
      return checkAndProcessJoinRequest(groupId, inviteId, cap, session, senderQueueIdRef.current);
    },
    [groupId, cap],
  );

  return { status, hasSession, sendMessage, refreshSession, processJoinRequest };
}
