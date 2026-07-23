// Chat/message type definitions — renamed from mockChats.ts (2026-07): once INITIAL_CHATS (4
// hardcoded contacts) was removed, this file stopped being mock data at all, just shared types +
// formatNow(). Contacts are shown by pseudonymous @alias (docs/03 §8 Public Aliases), never a real
// name — matching Vorticity's own identity model. Real per-conversation op-log data will come from
// ConvLogDO (docs/06 Phase 3) once wired; the chat LIST itself (which contacts exist, not their
// message history) is real now — see lib/chatList.ts.

/** One media attachment. `key`/`mediaId` are opaque to the server (see lib/media.ts) — the server
 * only ever custodies the encrypted blob at `mediaId`; `key` (the symmetric decryption key) travels
 * ONLY inside this ratchet-encrypted message, same as Signal/Telegram's attachment-key pattern. */
export interface AttachmentMeta {
  mediaId: string;
  key: string; // base64, 32-byte AEAD key — never sent to the server on its own
  mime: string;
  name: string;
  size: number;
}

export type MessageStatus = "sending" | "sent" | "delivered" | "read" | "failed";

export interface ChatMessage {
  id: string;
  senderId: "me" | "them";
  text: string;
  timestamp: string;
  /** id of the message this one replies to — may reference a since-deleted message (tombstone still
   * carries its id, see `deleted` below), in which case the UI shows "original message deleted". */
  replyTo?: string;
  attachments?: AttachmentMeta[];
  edited?: boolean;
  /** Tombstone: true once deleted. `text`/`attachments` are cleared at delete time — nothing sensitive
   * lingers in local state under a "deleted" flag alone. */
  deleted?: boolean;
  /** emoji -> which side(s) reacted with it. Small map, not a list — this is a 1:1 chat, at most 2
   * reactors per emoji ever exist. */
  reactions?: Partial<Record<string, ("me" | "them")[]>>;
  /** Only meaningful for `senderId === "me"` — the recipient's copy has no concept of its own status. */
  status?: MessageStatus;
  /** The QueueDO seq this message was assigned on push — how an inbound `receipt`/`read` envelope
   * (keyed by seq, see useQueueTransport.ts) gets correlated back to a specific local message. */
  outSeq?: number;
  /** Local calendar day (`formatDateKey()`) the message was sent/received on this device — `timestamp`
   * above is time-only (for the bubble's own display), this is what the message list groups date
   * separators by. Neither the wire nor the peer carries a real send-time (Sealed Sender++ deliberately
   * doesn't expose that), so both sides stamp it at their own local receipt/send moment, same as
   * `timestamp` already does. */
  dateKey?: string;
}

/** What actually gets JSON-stringified and handed to the ratchet's `encryptMessage` — the wire's
 * plaintext payload shape. Kept in this file (not useQueueTransport.ts) since both that hook and
 * lib/chatReducer.ts need it, and useQueueTransport.ts already imports FROM this file. */
export type MessagePayload =
  | { kind: "text"; id: string; text: string; replyTo?: string; attachments?: AttachmentMeta[] }
  | { kind: "edit"; id: string; targetId: string; text: string }
  | { kind: "delete"; id: string; targetId: string }
  | { kind: "reaction"; id: string; targetId: string; emoji: string | null }; // null = remove my reaction

// PQXDH's handshake is one-sided (see useQueueTransport.ts's header comment): "responder" publishes
// a signed prekey bundle, "initiator" verifies + encapsulates in response. Lives here (not in
// useQueueTransport.ts, which already imports FROM this file) so `Chat` can carry a per-chat role
// without a circular import — contact-bootstrap (lib/inviteLink.ts) is what assigns it per chat.
export type TransportRole = "initiator" | "responder";

export interface Chat {
  id: string;
  alias: string;
  initials: string;
  online: boolean;
  lastMessage: string;
  lastMessageAt: string;
  unreadCount: number;
  messages: ChatMessage[];
  role: TransportRole;
  /** Opt-in, per-chat (docs/05: "Off by default (metadata hygiene)") — whether this device shares
   * online/typing presence for this specific chat. A durable preference (unlike `online` itself,
   * which is a live signal), persisted the same way as the rest of this record — see lib/chatList.ts. */
  presenceEnabled: boolean;
}

export function formatNow(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** Local calendar-day key (`YYYY-MM-DD`, device-local timezone) — see `ChatMessage.dateKey`. */
export function formatDateKey(d: Date = new Date()): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

/** Human label for a date-separator row: "Today" / "Yesterday" / a full date otherwise. */
export function formatDayLabel(dateKey: string): string {
  const today = formatDateKey();
  if (dateKey === today) return "Today";
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  if (dateKey === formatDateKey(yesterday)) return "Yesterday";
  const [y, m, day] = dateKey.split("-").map(Number);
  return new Date(y!, m! - 1, day!).toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
}
