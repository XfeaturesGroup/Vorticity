import { useState } from "react";
import { AtSign, Loader2, Search, UserPlus, X } from "lucide-react";
import type { Chat } from "../../lib/chat";
import { ChatListItem } from "./ChatListItem";

interface ChatListProps {
  chats: Chat[];
  /** True only during the one-time vault restore on mount — shows a loading skeleton instead of the
   * (potentially misleading) "No chats yet" empty state before the persisted list has a chance to
   * arrive. */
  isLoading?: boolean;
  activeChatId: string | null;
  onSelect: (id: string) => void;
  /** `label` is the optional cosmetic "Invited by: X" string — see lib/inviteLink.ts's header
   * comment for what this is and isn't (not a public alias, no discoverability). */
  onCreateInvite: (label?: string) => void;
  onDelete: (id: string) => void;
  /** Alias contact establishment (docs/03 §8) — resolves `nickname` and sends a PoW-gated contact
   * request to whoever holds it. Async (mines real proof-of-work, several seconds) and can fail
   * (no such alias, network error) — returns a result so this component can show it inline rather
   * than Chats.tsx owning composer UI state for a purely presentational form. */
  onAddByAlias: (nickname: string) => Promise<{ ok: true } | { ok: false; error: string }>;
}

export function ChatList({ chats, isLoading, activeChatId, onSelect, onCreateInvite, onDelete, onAddByAlias }: ChatListProps) {
  const [search, setSearch] = useState("");
  const [composerOpen, setComposerOpen] = useState(false);
  const [labelDraft, setLabelDraft] = useState("");
  const [aliasComposerOpen, setAliasComposerOpen] = useState(false);
  const [nicknameDraft, setNicknameDraft] = useState("");
  const [aliasBusy, setAliasBusy] = useState(false);
  const [aliasError, setAliasError] = useState<string | null>(null);
  const filtered = chats.filter((c) => c.alias.toLowerCase().includes(search.trim().toLowerCase()));

  const submitInvite = () => {
    onCreateInvite(labelDraft.trim() || undefined);
    setComposerOpen(false);
    setLabelDraft("");
  };

  const submitAliasRequest = async () => {
    const nickname = nicknameDraft.trim().toLowerCase();
    if (!nickname || aliasBusy) return;
    setAliasBusy(true);
    setAliasError(null);
    const result = await onAddByAlias(nickname);
    setAliasBusy(false);
    if (result.ok) {
      setAliasComposerOpen(false);
      setNicknameDraft("");
    } else {
      setAliasError(result.error);
    }
  };

  return (
    <div className="w-80 md:w-96 shrink-0 border-r border-white/10 flex flex-col h-full min-h-0">
      <div className="p-4 border-b border-white/10 shrink-0 flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <div className="relative flex-1 min-w-0">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/40" />
            <input
              type="text"
              placeholder="Search chats..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-black/30 border border-white/10 rounded-xl py-2.5 pl-9 pr-4 text-sm text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50"
            />
          </div>
          <button
            type="button"
            onClick={() => {
              setAliasComposerOpen((v) => !v);
              setAliasError(null);
            }}
            title="Add contact by @alias"
            className="shrink-0 w-10 h-10 rounded-xl bg-fluid-peach/15 border border-fluid-peach/20 hover:bg-fluid-peach/25 text-fluid-peach flex items-center justify-center transition-colors"
          >
            {aliasComposerOpen ? <X className="w-4 h-4" /> : <AtSign className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={() => setComposerOpen((v) => !v)}
            title="Create invite link"
            className="shrink-0 w-10 h-10 rounded-xl bg-fluid-peach/15 border border-fluid-peach/20 hover:bg-fluid-peach/25 text-fluid-peach flex items-center justify-center transition-colors"
          >
            {composerOpen ? <X className="w-4 h-4" /> : <UserPlus className="w-4 h-4" />}
          </button>
        </div>
        {aliasComposerOpen && (
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <input
                type="text"
                autoFocus
                placeholder="nickname"
                value={nicknameDraft}
                onChange={(e) => setNicknameDraft(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void submitAliasRequest()}
                disabled={aliasBusy}
                maxLength={32}
                className="flex-1 min-w-0 bg-black/30 border border-white/10 rounded-lg py-2 px-3 text-xs text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50 disabled:opacity-50"
              />
              <button
                type="button"
                onClick={() => void submitAliasRequest()}
                disabled={aliasBusy}
                className="shrink-0 px-3 py-2 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors disabled:opacity-50 flex items-center gap-1"
              >
                {aliasBusy && <Loader2 className="w-3 h-3 animate-spin" />}
                {aliasBusy ? "Sending..." : "Request"}
              </button>
            </div>
            {aliasError && <p className="text-[11px] text-signal-danger px-1">{aliasError}</p>}
          </div>
        )}
        {composerOpen && (
          <div className="flex items-center gap-2">
            <input
              type="text"
              autoFocus
              placeholder="Your name (optional, shown to whoever opens the link)"
              value={labelDraft}
              onChange={(e) => setLabelDraft(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submitInvite()}
              maxLength={40}
              className="flex-1 min-w-0 bg-black/30 border border-white/10 rounded-lg py-2 px-3 text-xs text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50"
            />
            <button
              type="button"
              onClick={submitInvite}
              className="shrink-0 px-3 py-2 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors"
            >
              Create
            </button>
          </div>
        )}
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto vx-scrollbar">
        {isLoading ? (
          <div className="p-4 space-y-3" aria-hidden>
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="flex items-center gap-3 animate-pulse">
                <div className="w-11 h-11 rounded-full bg-white/5 shrink-0" />
                <div className="flex-1 min-w-0 space-y-2">
                  <div className="h-3 w-2/3 rounded bg-white/5" />
                  <div className="h-2.5 w-4/5 rounded bg-white/5" />
                </div>
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-6 text-center text-white/30 text-sm">
            {chats.length === 0 ? (
              <>
                No chats yet.
                <br />
                Tap the invite button above to start one.
              </>
            ) : (
              "No chats found"
            )}
          </div>
        ) : (
          filtered.map((chat) => (
            <ChatListItem
              key={chat.id}
              chat={chat}
              isActive={chat.id === activeChatId}
              onClick={() => onSelect(chat.id)}
              onDelete={() => onDelete(chat.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}
