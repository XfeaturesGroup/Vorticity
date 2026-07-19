// Chat/message type definitions — renamed from mockChats.ts (2026-07): once INITIAL_CHATS (4
// hardcoded contacts) was removed, this file stopped being mock data at all, just shared types +
// formatNow(). Contacts are shown by pseudonymous @alias (docs/03 §8 Public Aliases), never a real
// name — matching Vorticity's own identity model. Real per-conversation op-log data will come from
// ConvLogDO (docs/06 Phase 3) once wired; the chat LIST itself (which contacts exist, not their
// message history) is real now — see lib/chatList.ts.
export interface ChatMessage {
  id: string;
  senderId: "me" | "them";
  text: string;
  timestamp: string;
}

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
