// Chat LIST + MESSAGE HISTORY persistence (2026-07, revised).
//
// Originally (see git history) this persisted only list METADATA (id/alias/initials/role) and
// explicitly NOT message history, reasoning that a restored chat could just start empty and pick up
// whatever arrives live. In practice this meant navigating away from `/chats` (e.g. to `/settings`)
// and back — or any reload — silently wiped the visible conversation, which is a real regression for
// a messenger, not an acceptable "cold start". Message plaintext is now ALSO sealed into the same
// non-extractable AES-GCM vault (lib/secureStore.ts) `useQueueTransport.ts`'s identity material
// already uses — same primitive, same non-extractability guarantee, just a different logical record.
//
// Honest scope: this is LOCAL-DEVICE persistence only — it does not give you your history back on a
// second device, and it does not re-derive anything from the server (QueueDO evicts a message once
// acked, so there is no server-side backlog to re-fetch after the fact; ConvLogDO's real op-log,
// which WOULD give multi-device history, is still separate, not-yet-wired-into-Chats.tsx
// infrastructure — see docs/06 Phase 3). What this DOES fix: the plaintext this device already
// decrypted and rendered once now survives navigating away and back, or a reload, on THIS device.
import { sealToStore, unsealFromStore } from "./secureStore";
import type { Chat, ChatMessage, TransportRole } from "./chat";

const STORE_KEY = "chat-list";

interface PersistedChat {
  id: string;
  alias: string;
  initials: string;
  role: TransportRole;
  lastMessage: string;
  lastMessageAt: string;
  messages: ChatMessage[];
  presenceEnabled: boolean;
}

export async function saveChatList(chats: Chat[]): Promise<void> {
  const persisted: PersistedChat[] = chats.map((c) => ({
    id: c.id,
    alias: c.alias,
    initials: c.initials,
    role: c.role,
    lastMessage: c.lastMessage,
    lastMessageAt: c.lastMessageAt,
    messages: c.messages,
    presenceEnabled: c.presenceEnabled,
  }));
  await sealToStore(STORE_KEY, new TextEncoder().encode(JSON.stringify(persisted)));
}

/** Returns the restored chats, including message history, or `[]` if nothing was persisted or the
 * record is corrupt. `online`/`unreadCount` always restart at their defaults — those are live/session
 * concepts (an unread badge from a session that's over isn't meaningful), not durable history. */
export async function loadChatList(): Promise<Chat[]> {
  const bytes = await unsealFromStore(STORE_KEY);
  if (!bytes) return [];
  try {
    const persisted = JSON.parse(new TextDecoder().decode(bytes)) as PersistedChat[];
    if (!Array.isArray(persisted)) return [];
    return persisted.map((p) => ({
      id: p.id,
      alias: p.alias,
      initials: p.initials,
      role: p.role,
      online: false,
      unreadCount: 0,
      lastMessage: p.lastMessage ?? "",
      lastMessageAt: p.lastMessageAt ?? "",
      messages: Array.isArray(p.messages) ? p.messages : [],
      // `?? false`: a record persisted before this field existed decodes `presenceEnabled` as
      // `undefined`, not `false` — must default explicitly, not just rely on JS's own falsy coercion
      // silently working (it would here, but being explicit avoids relying on that).
      presenceEnabled: p.presenceEnabled ?? false,
    }));
  } catch {
    return [];
  }
}
