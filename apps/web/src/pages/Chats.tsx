// Split-view messenger UI (Phase 4, real contacts as of 2026-07). Real interactive state, not
// static mockup: selecting a chat clears its unread badge, and sending a message appends it to that
// conversation AND updates the list's preview/timestamp — both driven from one `chats` array here,
// not two disconnected pieces of state. The chat LIST itself is real now (lib/chatList.ts, built from
// actually-created/-joined invites, not a hardcoded mock array), and as of 2026-07 that same module
// ALSO persists message history locally (sealed via lib/secureStore.ts, same non-extractable vault
// `useQueueTransport.ts`'s identity material uses) — navigating away and back, or a reload, no longer
// wipes a visible conversation on THIS device. See lib/chatList.ts's header comment for the honest
// scope: this is local-device-only, not real multi-device sync — that still needs `ConvLogDO`'s
// op-log wired in here, separate, not-yet-built work per docs/06 Phase 3.
import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ChatList } from "../components/chat/ChatList";
import { ActiveChatPanel } from "../components/chat/ActiveChatPanel";
import { useQueueTransport } from "../hooks/useQueueTransport";
import { usePresence } from "../hooks/usePresence";
import { useAliasInbox } from "../hooks/useAliasInbox";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../contexts/ToastContext";
import { formatDateKey, formatNow, type AttachmentMeta, type Chat, type ChatMessage, type MessagePayload } from "../lib/chat";
import { applyInboundPayload, applyOwnReaction } from "../lib/chatReducer";
import { loadChatList, saveChatList } from "../lib/chatList";
import { clearFromStore } from "../lib/secureStore";
import {
  buildInviteUrl,
  clearInviteHash,
  generateInviteChatId,
  parseInviteFromLocation,
  takeStashedPendingInvite,
} from "../lib/inviteLink";
import {
  applyLinkPayload,
  buildLinkPayload,
  buildLinkUrl,
  generateLinkingSecret,
  parseLinkCodeFromLocation,
  putLinkPayload,
  takeLinkPayload,
} from "../lib/deviceLink";
import { buildAcceptedChat, resolveAlias, sendContactRequest, type PendingContactRequest } from "../lib/alias";

export function Chats() {
  const { token: cap } = useAuth();
  const { showToast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const [chats, setChats] = useState<Chat[]>([]);
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [pendingInvite, setPendingInvite] = useState<{ chatId: string; url: string } | null>(null);
  const [pendingDeviceLink, setPendingDeviceLink] = useState<{ chatId: string; url: string } | null>(null);
  // chatId -> id of the first message that was still unread when that chat was last opened —
  // recomputed on every `handleSelect` (see there), read by ActiveChatPanel to render a "New
  // messages" divider. Kept here rather than on `Chat` itself since it's transient per-open UI
  // state, not something that should get sealed into the persisted chat list.
  const [unreadDividers, setUnreadDividers] = useState<Record<string, string>>({});
  // Gates the persist-on-change effect below until the initial restore has actually run — otherwise
  // the very first render's empty `chats` would get saved and clobber whatever was in the vault
  // before the restore even finishes loading it back.
  const hasRestoredRef = useRef(false);
  // Real bug found live (2026-07-23, this pass): invite/link-hash consumption used to live in the
  // SAME effect as the vault restore, keyed on `[cap]`. `cap` legitimately starts `null` and flips to
  // the real token asynchronously (AuthContext's own vault-restore-on-mount), so THIS effect re-runs
  // a second time for a real reason, not just StrictMode noise. The first run would consume the
  // invite hash (clearing it) and locally mutate `restored`, then the SECOND run — cap now
  // available — would call `loadChatList()` fresh again, get back the list WITHOUT the just-added
  // invite chat (the persist-on-change effect hadn't necessarily flushed it to the vault yet), and
  // `setChats(restored)` that stale snapshot, silently wiping the just-joined chat out from under the
  // user. Reproduced live: joining an invite link before the vault-restore had resolved lost the chat
  // every time. Fixed by (1) making the base restore genuinely mount-once (no `cap` dependency at
  // all — it doesn't need one), and (2) moving hash consumption to its own effect that applies its
  // result via a FUNCTIONAL `setChats(prev => ...)` update instead of a locally-mutated snapshot, so
  // it composes correctly regardless of which effect's async work resolves first. `hashConsumedRef`
  // additionally guards the INVITE half specifically against being processed twice even if this
  // effect re-runs for the device-link half's sake (which genuinely does need to wait for `cap`).
  const hashConsumedRef = useRef(false);
  // Mirrors `hasRestoredRef` as real state (not a ref) purely so ChatList can render a loading
  // skeleton instead of a premature "No chats yet" during the one-time vault restore on mount.
  const [isRestoringChats, setIsRestoringChats] = useState(true);

  const activeChat = chats.find((c) => c.id === activeChatId) ?? null;

  // Base restore: mount-once, no `cap` dependency (loading the persisted list needs none). Merges
  // rather than replaces `prev` — the hash-consumption effect below may have already appended a
  // brand-new (not-yet-persisted) invite/link chat before this async load resolves; a plain
  // `setChats(restored)` would silently drop it. Whichever of the two resolves second just layers
  // cleanly on top of the other, regardless of ordering.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const restored = await loadChatList();
      if (cancelled) return;
      setChats((prev) => {
        const notYetPersisted = prev.filter((p) => !restored.some((r) => r.id === p.id));
        return [...restored, ...notYetPersisted];
      });
      hasRestoredRef.current = true;
      setIsRestoringChats(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Invite / device-link hash consumption — separate from the base restore above (see
  // `hashConsumedRef`'s comment for exactly why). Checks the URL hash FIRST, then a stashed invite
  // from sessionStorage (2026-07 fix — see AuthGuard.tsx/lib/inviteLink.ts: someone opening an invite
  // link while NOT yet authenticated gets redirected through SecurityGate -> OAuth -> AuthCallback and
  // lands back here with no hash of its own; the invite survived that trip via the stash, not the URL).
  useEffect(() => {
    if (hashConsumedRef.current) return; // invite half already handled — only device-link may still be pending `cap`
    let cancelled = false;
    (async () => {
      const invite = parseInviteFromLocation() ?? takeStashedPendingInvite();
      if (invite) {
        hashConsumedRef.current = true;
        clearInviteHash();
        setChats((prev) =>
          prev.some((c) => c.id === invite.chatId)
            ? prev
            : [
                ...prev,
                // Contact-bootstrap, joining side: someone opened a link generated by
                // handleCreateInvite below. This side always takes the OPPOSITE role from whoever
                // generated the link ("initiator": per PQXDH's one-sided handshake,
                // useQueueTransport.ts's header comment, this side verifies + encapsulates in
                // response to the responder's signed prekey bundle, which still flows over the
                // queue itself — see lib/inviteLink.ts for why the bundle isn't also embedded in the
                // URL). `invite.label`, if the inviter set one, is a purely cosmetic display name —
                // see lib/inviteLink.ts's header comment for why it's not a public alias.
                {
                  id: invite.chatId,
                  alias: invite.label ? `Invited by: ${invite.label}` : "New contact",
                  initials: invite.label ? invite.label.slice(0, 2).toUpperCase() : "IN",
                  role: "initiator" as const,
                  online: false,
                  unreadCount: 0,
                  lastMessage: "Joined via invite link — waiting for handshake...",
                  lastMessageAt: formatNow(),
                  messages: [],
                  presenceEnabled: false,
                },
              ],
        );
        setActiveChatId(invite.chatId);
        return; // an invite and a device-link code never arrive in the same hash — mutually exclusive
      }

      // Device-linking pass: redeem a `#/device-link/<code>` hash the SAME way an invite hash is
      // read (parse-without-navigating, then clear) — see lib/deviceLink.ts's header comment for why
      // this is a materially higher-stakes secret than an invite code (full chat state, not just "may
      // start a session"). Requires `cap` (this device's own real session capability — DeviceLinkDO
      // is capability-gated, see its header comment for why linking doesn't bypass account auth) — so
      // this branch alone legitimately waits for a real `cap` re-run, unlike the invite branch above.
      const linkSecret = parseLinkCodeFromLocation();
      if (linkSecret && cap) {
        hashConsumedRef.current = true;
        clearInviteHash(); // generic hash-clear, not invite-specific despite the name — see its own doc comment
        try {
          const payload = await takeLinkPayload(linkSecret, cap);
          if (payload && !cancelled) {
            const linkedChat = await applyLinkPayload(payload);
            setChats((prev) => {
              const existingIdx = prev.findIndex((c) => c.id === linkedChat.id);
              if (existingIdx >= 0) return prev.map((c, i) => (i === existingIdx ? linkedChat : c));
              return [...prev, linkedChat];
            });
            setActiveChatId(linkedChat.id);
            console.log(`[DeviceLink] Redeemed a device-link code for chat ${linkedChat.id.slice(0, 12)}... — history + crypto state applied.`);
          } else if (!cancelled) {
            console.warn("[DeviceLink] This code is invalid, already claimed, or expired.");
          }
        } catch (err) {
          console.warn("[DeviceLink] Failed to redeem device-link code:", (err as Error).message);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [cap]);

  // Persist the list, including message history (see lib/chatList.ts), whenever it changes — fires
  // on every message too, not just on create/join, since there's no cheaper signal to distinguish "a
  // chat was added" from "a chat's messages changed" without extra bookkeeping that isn't worth it at
  // this scale (re-sealing the whole list on every message is cheap for an alpha's realistic chat/
  // message counts; revisit if that stops being true).
  useEffect(() => {
    if (!hasRestoredRef.current) return;
    saveChatList(chats).catch((err) => console.warn("[Chats] Failed to persist chat list:", (err as Error).message));
  }, [chats]);

  // Applies an inbound (decrypted) payload — text/edit/delete/reaction — to `chatId`'s history via the
  // pure chatReducer. Only the active chat ever has a live socket (see useQueueTransport's scoping
  // note), so this always targets the conversation currently on screen — no unread-badge bump needed,
  // it's already being read live. List preview reflects the payload kind (a photo/edit/delete should
  // read differently than a plain text last-message, same as any real messenger).
  const handleIncoming = useCallback((chatId: string, payload: MessagePayload, timestamp: string) => {
    setChats((prev) =>
      prev.map((c) => {
        if (c.id !== chatId) return c;
        const next = applyInboundPayload(c, payload, timestamp);
        const preview =
          payload.kind === "text"
            ? payload.attachments?.length
              ? `📎 ${payload.attachments[0]!.name}`
              : payload.text
            : payload.kind === "delete"
              ? "Message deleted"
              : payload.kind === "edit"
                ? `${payload.text} (edited)`
                : c.lastMessage;
        return payload.kind === "reaction" ? next : { ...next, lastMessage: preview, lastMessageAt: timestamp };
      }),
    );
  }, []);

  // Updates the ACTIVE chat's own messages' delivery/read status by matching `outSeq` against the
  // cursor the peer just acknowledged — see useQueueTransport.ts's header comment for why both
  // "receipt"(delivered)/"read" are monotonic cursors, not per-message flags. Never downgrades an
  // already-"read" message back to "delivered" if cursors arrive out of order.
  const handleReceipt = useCallback(
    (kind: "delivered" | "read", upToSeq: number) => {
      setChats((prev) =>
        prev.map((c) =>
          c.id !== activeChatId
            ? c
            : {
                ...c,
                messages: c.messages.map((m) => {
                  if (m.senderId !== "me" || m.outSeq === undefined || m.outSeq > upToSeq) return m;
                  if (m.status === "read") return m; // terminal for this pass — never downgrades
                  return { ...m, status: kind };
                }),
              },
        ),
      );
    },
    [activeChatId],
  );

  // Per-chat role now (was a hardcoded "initiator" for every chat): the 4 mock contacts keep
  // defaulting to "initiator" (mockChats.ts), while invite-bootstrapped chats carry whichever role
  // they were actually assigned above / in handleCreateInvite below — a real two-party exchange needs
  // one side on each role, per PQXDH's one-sided handshake (useQueueTransport.ts's header comment).
  const {
    status: socketStatus,
    sendText,
    editMessage,
    deleteMessage,
    reactToMessage,
    hasLease,
    leaseHeldByOther,
    exportRatchetState,
    getTrustedPeerBundle,
  } = useQueueTransport(activeChatId, activeChat?.role ?? "initiator", handleIncoming, handleReceipt);

  // Opt-in presence (docs/06 "Still open: PresenceDO", closed 2026-07) — only live for the active
  // chat, only connects when that chat's own `presenceEnabled` toggle is on. See usePresence.ts's
  // header comment for why this doesn't try to track every background chat's presence too.
  const { peerOnline, peerTyping, sendTyping } = usePresence(activeChatId, activeChat?.presenceEnabled ?? false);

  // Alias contact establishment (docs/03 §8, "alias contact establishment" pass, 2026-07) — polls
  // this device's own intro queue (if it has a registered alias, see components/AliasPanel.tsx) for
  // incoming contact requests. See useAliasInbox.ts's header comment for the polling design.
  const { pending: pendingRequests, markHandled } = useAliasInbox(cap);

  const handleSelect = (id: string) => {
    // Capture where the "New messages" divider belongs BEFORE zeroing unreadCount below — unread
    // messages are always the tail of `messages` while a chat sits inactive (only the active chat
    // ever has a live socket, see useQueueTransport's scoping note), so the first unread one is
    // simply `messages.length - unreadCount`.
    const target = chats.find((c) => c.id === id);
    if (target && target.unreadCount > 0) {
      const firstUnread = target.messages[target.messages.length - target.unreadCount];
      if (firstUnread) setUnreadDividers((prev) => ({ ...prev, [id]: firstUnread.id }));
    }
    setActiveChatId(id);
    setChats((prev) => prev.map((c) => (c.id === id ? { ...c, unreadCount: 0 } : c)));
    if (pendingInvite && pendingInvite.chatId !== id) setPendingInvite(null);
  };

  // CommandPalette.tsx hands off a selection this way (`?open=<chatId>`) rather than through a
  // shared context — it reads the persisted chat list independently, so this page is what actually
  // owns applying the selection once the id is confirmed to exist in ITS copy of `chats`.
  useEffect(() => {
    const openId = searchParams.get("open");
    if (!openId) return;
    if (chats.some((c) => c.id === openId)) {
      handleSelect(openId);
      setSearchParams(
        (prev) => {
          prev.delete("open");
          return prev;
        },
        { replace: true },
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, chats]);

  // Contact/chat deletion: removes the chat from the local list AND every piece of local crypto
  // state associated with it — a stale identity/prekey-pool/imported-ratchet-state record left
  // behind after "deleting" a chat would be a real residual-data leak, not just visual clutter.
  // LOCAL-DEVICE ONLY (same honest scope as the rest of lib/chatList.ts — see its header comment):
  // this does not tell the peer anything, does not reach any server-side DO (PrekeyDO/PresenceDO/
  // DeviceLeaseDO state for this chat is left to its own TTL/alarm-driven cleanup, same as it already
  // is for an abandoned chat today), and does not delete this chat on any other of the user's own
  // linked devices.
  const handleDeleteChat = async (id: string) => {
    if (!window.confirm("Delete this chat? This removes the local message history and crypto state on this device and cannot be undone.")) {
      return;
    }
    if (activeChatId === id) setActiveChatId(null);
    setChats((prev) => prev.filter((c) => c.id !== id));
    await Promise.all(
      [`ratchet-identity:${id}`, `ratchet-kem:${id}`, `ratchet-kem-rotated-at:${id}`, `ratchet-imported-state:${id}`, `onetime-pool:${id}`].map(
        (key) => clearFromStore(key).catch(() => {}),
      ),
    );
  };

  // Alias contact establishment, requesting side: resolves `nickname` (real PoW-gated lookup),
  // sends a sealed contact request to whoever holds it (real PoW-gated write), and — mirroring
  // `parseInviteFromLocation`'s invite-join above — adds the proposed chat locally as role
  // `"initiator"` immediately, same "waiting for the other side" UX an invite link already has.
  // The request only reaches the recipient's inbox; nothing here assumes it was seen or accepted.
  const handleAddByAlias = async (nickname: string): Promise<{ ok: true } | { ok: false; error: string }> => {
    if (!cap) return { ok: false, error: "Not signed in" };
    try {
      const resolved = await resolveAlias(nickname, cap);
      if (!resolved) return { ok: false, error: `No one has registered @${nickname}` };
      const proposedChatId = await sendContactRequest(resolved, cap);
      setChats((prev) => [
        ...prev,
        {
          id: proposedChatId,
          alias: `@${nickname}`,
          initials: nickname.slice(0, 2).toUpperCase(),
          role: "initiator",
          online: false,
          unreadCount: 0,
          lastMessage: "Contact request sent — waiting for them to accept...",
          lastMessageAt: formatNow(),
          messages: [],
          presenceEnabled: false,
        },
      ]);
      setActiveChatId(proposedChatId);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  };

  // Alias contact establishment, receiving side: the owner accepts an inbox request by adding the
  // proposed chat as role "responder" (mirrors handleCreateInvite exactly — this device's own
  // useQueueTransport mount is what publishes the real signed PQXDH prekey bundle onto that queue;
  // nothing alias-specific happens beyond THIS one-time local bootstrap step) and marks the
  // request handled so it stops reappearing in the inbox.
  const handleAcceptRequest = async (request: PendingContactRequest) => {
    const accepted = buildAcceptedChat(request);
    setChats((prev) =>
      prev.some((c) => c.id === accepted.id)
        ? prev
        : [
            ...prev,
            {
              ...accepted,
              online: false,
              unreadCount: 0,
              lastMessage: "Contact request accepted — waiting for handshake...",
              lastMessageAt: formatNow(),
              messages: [],
              presenceEnabled: false,
            },
          ],
    );
    setActiveChatId(accepted.id);
    await markHandled(request.seq);
  };

  const handleDeclineRequest = async (request: PendingContactRequest) => {
    await markHandled(request.seq);
  };

  const handleTogglePresence = () => {
    if (!activeChatId) return;
    setChats((prev) => prev.map((c) => (c.id === activeChatId ? { ...c, presenceEnabled: !c.presenceEnabled } : c)));
  };

  // Live `online` for the active row only — deliberately NOT written into `chats` state itself (that
  // would re-trigger the persist-on-change effect above on every flicker, sealing the vault far more
  // often than a real preference change warrants). The list/panel render off this derived view instead.
  const displayChats = chats.map((c) => (c.id === activeChatId ? { ...c, online: peerOnline } : c));
  const displayActiveChat = displayChats.find((c) => c.id === activeChatId) ?? null;

  // Contact-bootstrap, generating side: creates a fresh unguessable chat id, adds it to the list as
  // "responder" (so useQueueTransport's existing responder-mount effect publishes a real signed
  // PQXDH prekey bundle onto that queue immediately — QueueDO's backlog-flush-on-connect means
  // whoever opens the link later still receives it, even if this tab has since closed), and surfaces
  // the shareable link (best-effort clipboard copy + a visible fallback banner, since clipboard
  // access can silently fail depending on permissions/context).
  const handleCreateInvite = (label?: string) => {
    const chatId = generateInviteChatId();
    const url = buildInviteUrl(chatId, label);
    setChats((prev) => [
      ...prev,
      {
        id: chatId,
        alias: "New contact",
        initials: "IN",
        role: "responder",
        online: false,
        unreadCount: 0,
        lastMessage: "Invite created — waiting for your contact to join...",
        lastMessageAt: formatNow(),
        messages: [],
        presenceEnabled: false,
      },
    ]);
    setActiveChatId(chatId);
    setPendingInvite({ chatId, url });
    navigator.clipboard
      ?.writeText(url)
      .then(() => showToast("Invite link copied to clipboard", "success"))
      .catch(() => {});
  };

  // Device-linking pass: seals the active chat's full state (identity/KEM/pool for a responder, the
  // live ratchet session if established, and message history) and drops it at DeviceLinkDO for a
  // second device to redeem — see lib/deviceLink.ts's header comment for the sensitivity of what
  // this actually shares (move the resulting link between your OWN devices only). Only offered while
  // `hasLease` — exporting from a read-only device would hand over stale state, see
  // useQueueTransport.ts's `exportRatchetState` doc comment.
  const handleLinkDevice = async () => {
    if (!activeChat || !cap || !hasLease) return;
    try {
      const secret = generateLinkingSecret();
      const payloadBytes = await buildLinkPayload(activeChat, exportRatchetState(), getTrustedPeerBundle());
      await putLinkPayload(secret, cap, payloadBytes);
      const url = buildLinkUrl(secret);
      setPendingDeviceLink({ chatId: activeChat.id, url });
      navigator.clipboard
        ?.writeText(url)
        .then(() => showToast("Device-link code copied to clipboard", "success"))
        .catch(() => {});
    } catch (err) {
      console.warn("[DeviceLink] Failed to create a device-link code:", (err as Error).message);
      showToast("Failed to create a device-link code", "error");
    }
  };

  // Optimistic local echo (instant feedback) with a REAL status lifecycle now (sending -> sent/failed
  // -> delivered -> read, via handleReceipt above) rather than a fire-and-forget append — the id is
  // generated HERE and threaded through to sendText so a later receipt/read cursor, or the user's own
  // reply/edit/reaction against this exact message, all resolve against the same id the wire actually
  // used.
  const handleSend = async (text: string, opts?: { replyTo?: string; attachments?: AttachmentMeta[] }) => {
    if (!activeChatId) return;
    const id = crypto.randomUUID();
    const message: ChatMessage = {
      id,
      senderId: "me",
      text,
      timestamp: formatNow(),
      dateKey: formatDateKey(),
      status: "sending",
      ...(opts?.replyTo !== undefined ? { replyTo: opts.replyTo } : {}),
      ...(opts?.attachments !== undefined ? { attachments: opts.attachments } : {}),
    };
    setChats((prev) =>
      prev.map((c) =>
        c.id === activeChatId ? { ...c, messages: [...c.messages, message], lastMessage: text, lastMessageAt: message.timestamp } : c,
      ),
    );
    const result = await sendText(id, text, opts);
    setChats((prev) =>
      prev.map((c) =>
        c.id !== activeChatId
          ? c
          : {
              ...c,
              messages: c.messages.map((m) =>
                m.id === id ? { ...m, status: result.ok ? "sent" : "failed", ...(result.seq !== undefined ? { outSeq: result.seq } : {}) } : m,
              ),
            },
      ),
    );
    if (!result.ok) showToast("Message failed to send", "error");
  };

  const handleEditMessage = async (targetId: string, text: string) => {
    if (!activeChatId) return;
    setChats((prev) =>
      prev.map((c) => (c.id === activeChatId ? { ...c, messages: c.messages.map((m) => (m.id === targetId ? { ...m, text, edited: true } : m)) } : c)),
    );
    await editMessage(targetId, text);
  };

  const handleDeleteMessage = async (targetId: string) => {
    if (!activeChatId) return;
    setChats((prev) =>
      prev.map((c) =>
        c.id === activeChatId
          ? {
              ...c,
              messages: c.messages.map((m) => {
                if (m.id !== targetId) return m;
                const { attachments: _attachments, reactions: _reactions, ...rest } = m;
                return { ...rest, deleted: true, text: "" };
              }),
            }
          : c,
      ),
    );
    await deleteMessage(targetId);
  };

  const handleReact = async (targetId: string, emoji: string | null) => {
    if (!activeChatId) return;
    setChats((prev) => prev.map((c) => (c.id === activeChatId ? applyOwnReaction(c, targetId, emoji) : c)));
    await reactToMessage(targetId, emoji);
  };

  const showInviteBanner = pendingInvite !== null && pendingInvite.chatId === activeChatId;
  const showDeviceLinkBanner = pendingDeviceLink !== null && pendingDeviceLink.chatId === activeChatId;

  return (
    <div className="h-full flex flex-col gap-3">
      {pendingRequests.map((request) => (
        <div
          key={request.seq}
          className="shrink-0 flex items-center gap-3 rounded-xl border border-fluid-peach/30 bg-fluid-peach/10 px-4 py-2.5 text-sm text-white"
        >
          <span className="text-white/70 shrink-0">
            Contact request{request.fromLabel ? ` from ${request.fromLabel}` : ""} — accept to start a chat.
          </span>
          <span className="flex-1" />
          <button
            type="button"
            onClick={() => void handleAcceptRequest(request)}
            className="shrink-0 px-3 py-1 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors"
          >
            Accept
          </button>
          <button
            type="button"
            onClick={() => void handleDeclineRequest(request)}
            className="shrink-0 px-3 py-1 text-xs rounded-lg bg-white/10 hover:bg-white/20 text-white transition-colors"
          >
            Decline
          </button>
        </div>
      ))}
      {showInviteBanner && (
        <div className="shrink-0 flex items-center gap-3 rounded-xl border border-fluid-peach/30 bg-fluid-peach/10 px-4 py-2.5 text-sm text-white">
          <span className="text-white/70 shrink-0">Invite link (copied to clipboard):</span>
          <input
            readOnly
            value={pendingInvite!.url}
            onFocus={(e) => e.currentTarget.select()}
            className="flex-1 min-w-0 bg-black/30 border border-white/10 rounded-lg px-2 py-1 text-xs text-white/90 font-mono"
          />
          <button
            type="button"
            onClick={() =>
              navigator.clipboard
                ?.writeText(pendingInvite!.url)
                .then(() => showToast("Invite link copied to clipboard", "success"))
                .catch(() => {})
            }
            className="shrink-0 px-3 py-1 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors"
          >
            Copy
          </button>
          <button type="button" onClick={() => setPendingInvite(null)} className="shrink-0 text-white/40 hover:text-white text-xs px-1">
            Dismiss
          </button>
        </div>
      )}
      {showDeviceLinkBanner && (
        <div className="shrink-0 flex items-center gap-3 rounded-xl border border-signal-danger/30 bg-signal-danger/10 px-4 py-2.5 text-sm text-white">
          <span className="text-white/70 shrink-0">
            Device-link code (copied — move to your OWN other device only, valid 10 min):
          </span>
          <input
            readOnly
            value={pendingDeviceLink!.url}
            onFocus={(e) => e.currentTarget.select()}
            className="flex-1 min-w-0 bg-black/30 border border-white/10 rounded-lg px-2 py-1 text-xs text-white/90 font-mono"
          />
          <button
            type="button"
            onClick={() =>
              navigator.clipboard
                ?.writeText(pendingDeviceLink!.url)
                .then(() => showToast("Device-link code copied to clipboard", "success"))
                .catch(() => {})
            }
            className="shrink-0 px-3 py-1 text-xs rounded-lg bg-signal-danger/90 hover:bg-signal-danger text-black transition-colors"
          >
            Copy
          </button>
          <button type="button" onClick={() => setPendingDeviceLink(null)} className="shrink-0 text-white/40 hover:text-white text-xs px-1">
            Dismiss
          </button>
        </div>
      )}
      <div className="flex-1 min-h-0 flex rounded-2xl border border-white/10 overflow-hidden vx-glass-dimmable">
        {/* Mobile (below `md`): only one pane shows at a time, toggled by whether a chat is active —
            list-then-conversation navigation with a back button, not a squeezed two-pane layout.
            `md:flex` on both unconditionally restores the normal side-by-side desktop split. */}
        <div className={activeChatId ? "hidden md:flex" : "flex"}>
          <ChatList
            chats={displayChats}
            isLoading={isRestoringChats}
            activeChatId={activeChatId}
            onSelect={handleSelect}
            onCreateInvite={handleCreateInvite}
            onDelete={handleDeleteChat}
            onAddByAlias={handleAddByAlias}
          />
        </div>
        <div className={(!activeChatId ? "hidden md:flex" : "flex") + " flex-1 min-w-0"}>
          <ActiveChatPanel
            chat={displayActiveChat}
            socketStatus={socketStatus}
            onSend={handleSend}
            onEditMessage={handleEditMessage}
            onDeleteMessage={handleDeleteMessage}
            onReact={handleReact}
            onBack={() => setActiveChatId(null)}
            unreadDividerMessageId={activeChatId ? (unreadDividers[activeChatId] ?? null) : null}
            peerTyping={peerTyping}
            onTypingDraft={sendTyping}
            onTogglePresence={handleTogglePresence}
            onLinkDevice={handleLinkDevice}
            canLinkDevice={hasLease}
            leaseHeldByOther={leaseHeldByOther}
          />
        </div>
      </div>
    </div>
  );
}
