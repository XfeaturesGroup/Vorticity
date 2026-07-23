// Group chat LIST + MESSAGE HISTORY persistence — mirrors lib/chatList.ts's exact pattern for 1:1
// chats (same sealed vault, same "local-device-only, no multi-device sync yet" honest scope).
import { sealToStore, unsealFromStore } from "./secureStore";

export interface GroupMessage {
  id: string;
  /** No roster/naming system exists yet (see GroupDO.ts's own header comment: a group is anonymous
   * sockets to this DO, nothing more) — every other member's message is generically "them" for this
   * first pass, same honest v1 scope call as `AttachmentThumb`'s "no thumbnail preview" once was. */
  senderId: "me" | "them";
  text: string;
  timestamp: string;
}

export interface GroupChat {
  id: string;
  name: string;
  /** Best-effort local count — starts at 1 (yourself), increments each time THIS device successfully
   * processes an add-member commit. A device that joined later has no way to learn the true
   * historical count without a real roster mechanism (not built — see lib/group.ts's header comment). */
  memberCount: number;
  lastMessage: string;
  lastMessageAt: string;
  messages: GroupMessage[];
  /** Outstanding invite ids this device has generated for this group and not yet seen claimed —
   * durable (survives navigating away/reloading), so processing a join request doesn't depend on
   * the "Invite" banner still being open in memory. See GroupChats.tsx's background poll, which
   * checks every group's list here, not just whichever one happens to be active. Real bug found
   * live: the original design only polled while a specific ephemeral UI banner was mounted — closing
   * it (or just navigating to another group) silently stranded the invitee polling forever. */
  pendingInviteIds: string[];
}

const STORE_KEY = "group-chat-list";

export async function saveGroupList(groups: GroupChat[]): Promise<void> {
  await sealToStore(STORE_KEY, new TextEncoder().encode(JSON.stringify(groups)));
}

export async function loadGroupList(): Promise<GroupChat[]> {
  const bytes = await unsealFromStore(STORE_KEY);
  if (!bytes) return [];
  try {
    const persisted = JSON.parse(new TextDecoder().decode(bytes)) as GroupChat[];
    if (!Array.isArray(persisted)) return [];
    return persisted.map((g) => ({
      id: g.id,
      name: g.name,
      memberCount: g.memberCount ?? 1,
      lastMessage: g.lastMessage ?? "",
      lastMessageAt: g.lastMessageAt ?? "",
      messages: Array.isArray(g.messages) ? g.messages : [],
      pendingInviteIds: Array.isArray(g.pendingInviteIds) ? g.pendingInviteIds : [],
    }));
  } catch {
    return [];
  }
}
