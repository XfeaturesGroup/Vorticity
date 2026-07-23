// Pure reducer applying an inbound (decrypted) MessagePayload to a chat's local message list.
// Kept separate from Chats.tsx/useQueueTransport.ts specifically so it's trivial to reason about and
// exercise directly (no wasm/crypto/transport involved) — it only ever sees already-decrypted payloads.
import { formatDateKey, type Chat, type ChatMessage, type MessagePayload } from "./chat";

/** Applies one inbound payload (already decrypted, from the PEER) to `chat`. Returns a new Chat —
 * never mutates the input, same convention every other setChats((prev) => ...) call in this app uses. */
export function applyInboundPayload(chat: Chat, payload: MessagePayload, timestamp: string): Chat {
  switch (payload.kind) {
    case "text": {
      const message: ChatMessage = {
        id: payload.id,
        senderId: "them",
        text: payload.text,
        timestamp,
        dateKey: formatDateKey(),
        ...(payload.replyTo !== undefined ? { replyTo: payload.replyTo } : {}),
        ...(payload.attachments !== undefined ? { attachments: payload.attachments } : {}),
      };
      return { ...chat, messages: [...chat.messages, message] };
    }
    case "edit":
      return {
        ...chat,
        messages: chat.messages.map((m) => (m.id === payload.targetId && !m.deleted ? { ...m, text: payload.text, edited: true } : m)),
      };
    case "delete":
      return {
        ...chat,
        messages: chat.messages.map((m) => {
          if (m.id !== payload.targetId) return m;
          const { attachments: _attachments, reactions: _reactions, ...rest } = m;
          return { ...rest, deleted: true, text: "" };
        }),
      };
    case "reaction":
      return {
        ...chat,
        messages: chat.messages.map((m) => {
          if (m.id !== payload.targetId) return m;
          const reactions = { ...(m.reactions ?? {}) };
          // Remove any PRIOR reaction "them" had under a different emoji first — a real 1:1 reaction
          // bar is "one active reaction per person," same as Telegram's own quick-react behavior, not
          // an accumulating multi-reaction-per-person list.
          for (const key of Object.keys(reactions)) {
            reactions[key] = reactions[key]?.filter((who) => who !== "them");
            if (reactions[key]?.length === 0) delete reactions[key];
          }
          if (payload.emoji !== null) {
            reactions[payload.emoji] = [...(reactions[payload.emoji] ?? []), "them"];
          }
          return { ...m, reactions };
        }),
      };
    default: {
      const _exhaustive: never = payload;
      return _exhaustive;
    }
  }
}

/** Applies MY OWN reaction locally (optimistic) the same way applyInboundPayload does for "them" —
 * factored out so ChatList preview / MessageBubble share identical toggle semantics for either side. */
export function applyOwnReaction(chat: Chat, targetId: string, emoji: string | null): Chat {
  return {
    ...chat,
    messages: chat.messages.map((m) => {
      if (m.id !== targetId) return m;
      const reactions = { ...(m.reactions ?? {}) };
      for (const key of Object.keys(reactions)) {
        reactions[key] = reactions[key]?.filter((who) => who !== "me");
        if (reactions[key]?.length === 0) delete reactions[key];
      }
      if (emoji !== null) {
        reactions[emoji] = [...(reactions[emoji] ?? []), "me"];
      }
      return { ...m, reactions };
    }),
  };
}
