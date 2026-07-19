// Sharding key: contact-scoped (one instance per chat id — see docs/04 DO catalog). Ephemeral,
// opt-in presence/typing relay for exactly the two parties of one chat.
//
// ISOLATION, same standing as QueueDO/ConvLogDO: this DO holds NO storage at all (not even
// SQLite — there is nothing to schema, nothing to evict, nothing to mirror). It knows only which
// WebSockets are currently attached; it never learns which account/identity is behind either one.
//
// "Sealed" (docs/05's "Opt-in typing/online, sealed") is an ARCHITECTURAL property here, not a
// per-frame AEAD one — stated plainly rather than implied: signals are small plaintext control
// frames (`{type:"online"|"offline"|"typing"}`), the SAME shape as QueueDO's own `{type:"ack"}`
// control frame, not run through useQueueTransport.ts's Double Ratchet. Deliberate, not an
// oversight: a ratchet session advances its chain key (and, for a skipped key, consumes a slot in
// a bounded out-of-order window — packages/vortic-core/src/ratchet.rs) per message; a "typing"
// signal fires on every keystroke, and interleaving that volume through the SAME chain as real
// messages risks exhausting the skipped-key window and breaking real message decryption. Instead,
// confidentiality/metadata-hygiene rests on the same architectural isolation QueueDO already relies
// on: this DO is addressed by the chat's own high-entropy unguessable id (lib/inviteLink.ts) and
// reachable only with a valid session capability (index.ts's `requireCapability` gate on
// `/presence/:chatId/*`) — an outside observer can neither guess the id nor reach the route without
// having already passed the ZK airlock.
//
// NEVER PERSISTED (per this class's own pre-existing TODO): presence is exactly "who is here right
// now" — there is nothing correct to reconstruct after a restart, so unlike QueueDO/ConvLogDO there
// is no eviction alarm, no backlog flush on connect. A fresh connect either sees the peer already
// attached (told immediately, see `handleSubscribe`) or doesn't (peer isn't online — also correct).
import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

type PresenceFrame = { type: "online" } | { type: "offline" } | { type: "typing" };

function isPresenceFrame(v: unknown): v is PresenceFrame {
  const t = (v as { type?: unknown } | null)?.type;
  return t === "online" || t === "offline" || t === "typing";
}

export class PresenceDO extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("PresenceDO only accepts a WebSocket upgrade", { status: 400 });
    }
    return this.handleSubscribe();
  }

  private handleSubscribe(): Response {
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    // Whoever else is already attached is the peer(s) already online — tell the NEW socket right
    // away, and tell EVERY already-attached socket that a peer just joined. Order matters: read the
    // existing set before accepting the new one, or it would see itself.
    const alreadyAttached = this.ctx.getWebSockets();
    this.ctx.acceptWebSocket(server);
    if (alreadyAttached.length > 0) {
      this.send(server, { type: "online" });
      for (const ws of alreadyAttached) this.send(ws, { type: "online" });
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(message);
    } catch {
      return; // malformed frame from an untrusted client — ignore, don't crash the socket
    }
    if (!isPresenceFrame(parsed)) return;
    // "online"/"offline" are relay-only signals the DO itself generates on attach/detach (see
    // handleSubscribe/webSocketClose) — a client claiming either is not this protocol's shape and is
    // dropped rather than trusted. Only "typing" is a real client-originated frame.
    if (parsed.type !== "typing") return;
    this.relayToOthers(ws, parsed);
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean): Promise<void> {
    // Same "already-closing socket must not throw" lesson QueueDO's own header comment documents.
    try {
      ws.close(code, reason);
    } catch {
      // Already closed/closing.
    }
    this.relayToOthers(ws, { type: "offline" });
  }

  override async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    this.relayToOthers(ws, { type: "offline" });
  }

  private relayToOthers(origin: WebSocket, frame: PresenceFrame): void {
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === origin) continue;
      this.send(ws, frame);
    }
  }

  private send(ws: WebSocket, frame: PresenceFrame): void {
    try {
      ws.send(JSON.stringify(frame));
    } catch {
      // A dead/closing socket shouldn't fail the relay for the rest — same tolerance as QueueDO.fanOut.
    }
  }
}
