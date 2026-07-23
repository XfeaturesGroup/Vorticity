// First group-chat client UI (2026-07). Deliberately leaner than 1:1 Chats.tsx — no reactions/edit/
// media/reply for this first pass (honest v1 scope, matching lib/group.ts's own header comment on
// what's genuinely built vs. deferred: no roster/naming system exists yet, so every other member's
// message renders generically as "Member"). Real crypto underneath (X-Wing hybrid PQ MLS), not a
// mock — see lib/group.ts and hooks/useGroupTransport.ts for the actual wire protocol.
import { useEffect, useRef, useState, type FormEvent } from "react";
import { ChevronLeft, Copy, Loader2, Plus, Send, Users, X } from "lucide-react";
import { cn } from "@vorticity/ui";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../contexts/ToastContext";
import { useGroupTransport } from "../hooks/useGroupTransport";
import {
  buildGroupInviteUrl,
  checkAndProcessJoinRequest,
  clearGroupInviteHash,
  createGroup,
  generateInviteId,
  loadGroupSession,
  parseGroupInviteFromLocation,
  pollForWelcome,
  requestToJoinGroup,
} from "../lib/group";
import { loadGroupList, saveGroupList, type GroupChat, type GroupMessage } from "../lib/groupList";

const JOIN_POLL_INTERVAL_MS = 2500;

export function GroupChats() {
  const { token: cap } = useAuth();
  const { showToast } = useToast();
  const [groups, setGroups] = useState<GroupChat[]>([]);
  const [activeGroupId, setActiveGroupId] = useState<string | null>(null);
  const [hasRestored, setHasRestored] = useState(false);
  const [creating, setCreating] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [pendingInvite, setPendingInvite] = useState<{ groupId: string; inviteId: string; url: string } | null>(null);
  const [joining, setJoining] = useState(false);
  const [draft, setDraft] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);
  const hashConsumedRef = useRef(false);

  const activeGroup = groups.find((g) => g.id === activeGroupId) ?? null;

  // Restore persisted groups on mount.
  useEffect(() => {
    let cancelled = false;
    loadGroupList().then((restored) => {
      if (!cancelled) setGroups(restored);
      setHasRestored(true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Persist on every change (mirrors Chats.tsx's own persist-on-change effect).
  useEffect(() => {
    if (!hasRestored) return;
    saveGroupList(groups).catch((err) => console.warn("[GroupChats] Failed to persist group list:", (err as Error).message));
  }, [groups, hasRestored]);

  // Invite-hash consumption (invitee side): open a `#/group-invite/<groupId>/<inviteId>` link ->
  // generate this device's own KeyPackage, send it, then poll for the Welcome. Separate from the
  // base restore above for the same reason Chats.tsx's own invite-hash effect is separate — `cap`
  // resolves asynchronously and this must not race a plain mount-once restore.
  useEffect(() => {
    if (hashConsumedRef.current || !cap) return;
    const invite = parseGroupInviteFromLocation();
    if (!invite) return;
    hashConsumedRef.current = true;
    clearGroupInviteHash();
    setJoining(true);
    (async () => {
      try {
        await requestToJoinGroup(invite.groupId, invite.inviteId, cap);
        const pollTimer = setInterval(async () => {
          try {
            const session = await pollForWelcome(invite.groupId, invite.inviteId, cap);
            if (!session) return;
            clearInterval(pollTimer);
            setJoining(false);
            setGroups((prev) =>
              prev.some((g) => g.id === invite.groupId)
                ? prev
                : [
                    ...prev,
                    {
                      id: invite.groupId,
                      name: invite.groupName ?? "Group",
                      memberCount: 2,
                      lastMessage: "You joined this group",
                      lastMessageAt: formatNow(),
                      messages: [],
                      pendingInviteIds: [],
                    },
                  ],
            );
            setActiveGroupId(invite.groupId);
            showToast(`Joined ${invite.groupName ?? "the group"}`, "success");
          } catch (err) {
            clearInterval(pollTimer);
            setJoining(false);
            showToast(`Failed to join group: ${(err as Error).message}`, "error");
          }
        }, JOIN_POLL_INTERVAL_MS);
      } catch (err) {
        setJoining(false);
        showToast(`Failed to request to join: ${(err as Error).message}`, "error");
      }
    })();
  }, [cap, showToast]);

  const handleIncomingMessage = (text: string, timestamp: string) => {
    if (!activeGroupId) return;
    const message: GroupMessage = { id: crypto.randomUUID(), senderId: "them", text, timestamp };
    setGroups((prev) =>
      prev.map((g) => (g.id === activeGroupId ? { ...g, messages: [...g.messages, message], lastMessage: text, lastMessageAt: timestamp } : g)),
    );
  };

  const { status: socketStatus, hasSession, sendMessage, refreshSession, processJoinRequest } = useGroupTransport(
    activeGroupId,
    cap,
    handleIncomingMessage,
  );

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [activeGroupId, activeGroup?.messages.length]);

  // Durable background poll for ALL outstanding invites across ALL groups — NOT scoped to whichever
  // group happens to be active or whether a specific "Invite" banner is still mounted. Real bug found
  // live: the original design only checked the invite that was still showing in an ephemeral React
  // state variable, so navigating to another group (or a reload) silently stranded the invitee's
  // KeyPackage in the queue forever, with nothing on the creator's side ever coming back to look for
  // it again. `pendingInviteIds` (lib/groupList.ts) persists which invites are still outstanding, so
  // this poll resumes correctly across reloads/navigation as long as the app is open at some point.
  const groupsRef = useRef(groups);
  groupsRef.current = groups;
  const activeGroupIdRef = useRef(activeGroupId);
  activeGroupIdRef.current = activeGroupId;
  const processJoinRequestRef = useRef(processJoinRequest);
  processJoinRequestRef.current = processJoinRequest;
  useEffect(() => {
    if (!cap || !hasRestored) return;
    const timer = setInterval(async () => {
      for (const group of groupsRef.current) {
        if (group.pendingInviteIds.length === 0) continue;
        // The ACTIVE group already has a live `MlsGroupSession` object inside useGroupTransport
        // (kept up to date as messages/commits arrive) — route through its own `processJoinRequest`
        // rather than loading a second, possibly-stale copy from disk, which could otherwise fork the
        // group's state if the live session had unsaved-yet progress at the moment of the poll.
        // Every OTHER group has no live session to conflict with, so loading fresh here is safe.
        const isActive = group.id === activeGroupIdRef.current;
        for (const inviteId of group.pendingInviteIds) {
          try {
            const added = isActive
              ? await processJoinRequestRef.current(inviteId)
              : await (async () => {
                  const session = await loadGroupSession(group.id);
                  return session ? checkAndProcessJoinRequest(group.id, inviteId, cap, session) : false;
                })();
            if (!added) continue;
            setGroups((prev) =>
              prev.map((g) =>
                g.id === group.id ? { ...g, memberCount: g.memberCount + 1, pendingInviteIds: g.pendingInviteIds.filter((id) => id !== inviteId) } : g,
              ),
            );
            showToast(`Someone joined ${group.name}`, "success");
          } catch (err) {
            console.warn(`[GroupChats] Failed to process a join request for ${group.id}:`, (err as Error).message);
          }
        }
      }
    }, JOIN_POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [cap, hasRestored, showToast]);

  // Purely cosmetic: auto-dismiss the "here's your invite link" banner once the background poll
  // above has actually claimed that invite (removed it from the group's persisted pending list).
  useEffect(() => {
    if (!pendingInvite) return;
    const group = groups.find((g) => g.id === pendingInvite.groupId);
    if (group && !group.pendingInviteIds.includes(pendingInvite.inviteId)) setPendingInvite(null);
  }, [groups, pendingInvite]);

  const handleCreateGroup = async () => {
    const name = nameDraft.trim();
    if (!name) return;
    try {
      const { groupId } = await createGroup();
      setGroups((prev) => [
        ...prev,
        { id: groupId, name, memberCount: 1, lastMessage: "You created this group", lastMessageAt: formatNow(), messages: [], pendingInviteIds: [] },
      ]);
      setActiveGroupId(groupId);
      setCreating(false);
      setNameDraft("");
    } catch (err) {
      showToast(`Failed to create group: ${(err as Error).message}`, "error");
    }
  };

  const handleInvite = () => {
    if (!activeGroup) return;
    const inviteId = generateInviteId();
    const url = buildGroupInviteUrl(activeGroup.id, inviteId, activeGroup.name);
    setGroups((prev) => prev.map((g) => (g.id === activeGroup.id ? { ...g, pendingInviteIds: [...g.pendingInviteIds, inviteId] } : g)));
    setPendingInvite({ groupId: activeGroup.id, inviteId, url });
    navigator.clipboard?.writeText(url).then(() => showToast("Invite link copied to clipboard", "success")).catch(() => {});
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const text = draft.trim();
    if (!text || !activeGroupId) return;
    setDraft("");
    const id = crypto.randomUUID();
    const timestamp = formatNow();
    setGroups((prev) =>
      prev.map((g) => (g.id === activeGroupId ? { ...g, messages: [...g.messages, { id, senderId: "me", text, timestamp }], lastMessage: text, lastMessageAt: timestamp } : g)),
    );
    const result = await sendMessage(text);
    if (!result.ok) showToast(hasSession ? "Message failed to send" : "Can't send yet — no other members have joined", "error");
  };

  return (
    <div className="h-full flex flex-col gap-3">
      {joining && (
        <div className="shrink-0 flex items-center gap-3 rounded-xl border border-fluid-peach/30 bg-fluid-peach/10 px-4 py-2.5 text-sm text-white">
          <Loader2 className="w-4 h-4 animate-spin text-fluid-peach shrink-0" />
          Joining group...
        </div>
      )}
      {pendingInvite && pendingInvite.groupId === activeGroupId && (
        <div className="shrink-0 flex items-center gap-3 rounded-xl border border-fluid-peach/30 bg-fluid-peach/10 px-4 py-2.5 text-sm text-white">
          <span className="text-white/70 shrink-0">Invite link (copied — waiting for someone to join):</span>
          <input
            readOnly
            value={pendingInvite.url}
            onFocus={(e) => e.currentTarget.select()}
            className="flex-1 min-w-0 bg-black/30 border border-white/10 rounded-lg px-2 py-1 text-xs text-white/90 font-mono"
          />
          <button
            type="button"
            onClick={() => navigator.clipboard?.writeText(pendingInvite.url).catch(() => {})}
            className="shrink-0 px-3 py-1 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors flex items-center gap-1"
          >
            <Copy className="w-3 h-3" /> Copy
          </button>
          <button type="button" onClick={() => setPendingInvite(null)} className="shrink-0 text-white/40 hover:text-white text-xs px-1">
            Dismiss
          </button>
        </div>
      )}

      <div className="flex-1 min-h-0 flex rounded-2xl border border-white/10 overflow-hidden vx-glass-dimmable">
        <div className={cn("w-80 md:w-96 shrink-0 border-r border-white/10 flex-col h-full min-h-0", activeGroupId ? "hidden md:flex" : "flex")}>
          <div className="p-4 border-b border-white/10 shrink-0">
            {!creating ? (
              <button
                type="button"
                onClick={() => setCreating(true)}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-fluid-peach/15 border border-fluid-peach/20 hover:bg-fluid-peach/25 text-fluid-peach text-sm font-medium transition-colors"
              >
                <Plus className="w-4 h-4" /> Create group
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  autoFocus
                  placeholder="Group name"
                  value={nameDraft}
                  onChange={(e) => setNameDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && void handleCreateGroup()}
                  maxLength={60}
                  className="flex-1 min-w-0 bg-black/30 border border-white/10 rounded-lg py-2 px-3 text-sm text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50"
                />
                <button type="button" onClick={() => void handleCreateGroup()} className="shrink-0 px-3 py-2 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors">
                  Create
                </button>
                <button type="button" onClick={() => setCreating(false)} className="shrink-0 text-white/40 hover:text-white p-1">
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto vx-scrollbar">
            {groups.length === 0 ? (
              <div className="p-6 text-center text-white/30 text-sm">No groups yet.<br />Create one to get started.</div>
            ) : (
              groups.map((g) => (
                <button
                  key={g.id}
                  type="button"
                  onClick={() => setActiveGroupId(g.id)}
                  className={cn(
                    "group w-full flex items-center gap-3.5 px-4 py-3.5 text-left transition-colors border-b border-white/5",
                    g.id === activeGroupId ? "bg-white/[0.06]" : "hover:bg-white/[0.04]",
                  )}
                >
                  <div className="w-12 h-12 rounded-full bg-fluid-purple/15 border border-fluid-purple/20 flex items-center justify-center shrink-0">
                    <Users className="w-5 h-5 text-fluid-purple" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium text-white truncate">{g.name}</span>
                      <span className="text-[10px] text-white/40 shrink-0">{g.lastMessageAt}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 mt-1">
                      <span className="text-xs text-white/50 truncate">{g.lastMessage}</span>
                      <span className="text-[10px] text-white/30 shrink-0">{g.memberCount} member{g.memberCount === 1 ? "" : "s"}</span>
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        <div className={cn((!activeGroupId ? "hidden md:flex" : "flex") + " flex-1 min-w-0 flex-col")}>
          {!activeGroup ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 text-white/30">
              <Users className="w-12 h-12" />
              <p className="text-sm">Select a group to start messaging</p>
            </div>
          ) : (
            <>
              <div className="shrink-0 flex items-center gap-3 px-5 py-4 border-b border-white/10">
                <button type="button" onClick={() => setActiveGroupId(null)} className="md:hidden shrink-0 p-1 -ml-1 rounded-lg text-white/60 hover:text-white hover:bg-white/10 transition-colors">
                  <ChevronLeft className="w-5 h-5" />
                </button>
                <div className="w-10 h-10 rounded-full bg-fluid-purple/15 border border-fluid-purple/20 flex items-center justify-center shrink-0">
                  <Users className="w-4.5 h-4.5 text-fluid-purple" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-white truncate">{activeGroup.name}</div>
                  <div className="text-xs text-white/40">
                    {activeGroup.memberCount} member{activeGroup.memberCount === 1 ? "" : "s"} · {socketStatus}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleInvite}
                  className="shrink-0 px-3 py-1.5 text-xs rounded-lg bg-fluid-peach/15 border border-fluid-peach/20 hover:bg-fluid-peach/25 text-fluid-peach transition-colors"
                >
                  Invite
                </button>
              </div>

              {activeGroup.memberCount <= 1 && (
                <div className="shrink-0 px-5 py-2 bg-fluid-peach/10 border-b border-fluid-peach/20 text-xs text-fluid-peach">
                  Invite someone to start the conversation — a group of one has no one to talk to yet.
                </div>
              )}

              <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto vx-scrollbar px-6 py-5 space-y-1.5">
                {activeGroup.messages.map((m) => (
                  <div key={m.id} className={cn("flex", m.senderId === "me" ? "justify-end" : "justify-start")}>
                    <div
                      className={cn(
                        "max-w-[70%] rounded-2xl px-4 py-3 border text-sm",
                        m.senderId === "me" ? "bg-fluid-peach/10 border-fluid-peach/20 text-white" : "bg-white/5 border-white/10 text-white/90",
                      )}
                    >
                      {m.senderId !== "me" && <div className="text-[11px] text-fluid-purple mb-1">Member</div>}
                      <p className="whitespace-pre-wrap break-words leading-relaxed">{m.text}</p>
                      <span className="block text-[10px] text-white/40 mt-1.5 text-right">{m.timestamp}</span>
                    </div>
                  </div>
                ))}
              </div>

              <form onSubmit={handleSubmit} className="shrink-0 flex items-center gap-2 px-4 py-3 border-t border-white/10">
                <input
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder="Type a message..."
                  className="flex-1 bg-black/30 border border-white/10 rounded-xl py-2.5 px-4 text-sm text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50"
                />
                <button
                  type="submit"
                  disabled={!draft.trim()}
                  className="w-10 h-10 rounded-xl bg-fluid-peach/90 hover:bg-fluid-peach disabled:opacity-30 disabled:cursor-not-allowed text-black flex items-center justify-center shrink-0 transition-colors"
                >
                  <Send className="w-4 h-4" />
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function formatNow(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
