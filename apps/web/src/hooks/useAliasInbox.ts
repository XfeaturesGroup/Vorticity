// Polls this device's own intro queue (if it has a registered alias) for incoming contact
// requests — "alias contact establishment" pass (2026-07). See lib/alias.ts's header comment for
// the overall design and `pullContactRequests`'s doc comment for why already-handled entries are
// filtered client-side rather than acked away (QueueDO's ack is cumulative "everything <= seq",
// wrong semantics for an inbox of independent, individually-actionable requests).
import { useCallback, useEffect, useRef, useState } from "react";
import { loadOwnAlias, pullContactRequests, type OwnAlias, type PendingContactRequest } from "../lib/alias";
import { sealToStore, unsealFromStore } from "../lib/secureStore";

const POLL_INTERVAL_MS = 15_000;
const HANDLED_SEQS_KEY = "alias-inbox-handled-seqs";

async function loadHandledSeqs(): Promise<Set<number>> {
  const bytes = await unsealFromStore(HANDLED_SEQS_KEY);
  if (!bytes) return new Set();
  try {
    const arr = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    return new Set(Array.isArray(arr) ? (arr as number[]) : []);
  } catch {
    return new Set();
  }
}
async function saveHandledSeqs(seqs: Set<number>): Promise<void> {
  await sealToStore(HANDLED_SEQS_KEY, new TextEncoder().encode(JSON.stringify([...seqs])));
}

export function useAliasInbox(cap: string | null) {
  const [pending, setPending] = useState<PendingContactRequest[]>([]);
  const ownAliasRef = useRef<OwnAlias | null>(null);
  const handledRef = useRef<Set<number>>(new Set());
  const handledLoadedRef = useRef(false);

  const poll = useCallback(async () => {
    if (!cap) return;
    if (!handledLoadedRef.current) {
      handledRef.current = await loadHandledSeqs();
      handledLoadedRef.current = true;
    }
    // Re-checks `loadOwnAlias()` every poll until one is found (cheap IndexedDB read), then caches
    // it — covers the case where the user registers an alias mid-session, after this hook already
    // mounted with none.
    const own = ownAliasRef.current ?? (await loadOwnAlias());
    ownAliasRef.current = own;
    if (!own) return;
    try {
      const results = await pullContactRequests(own, cap, handledRef.current);
      setPending(results);
    } catch (err) {
      console.warn("[AliasInbox] poll failed:", (err as Error).message);
    }
  }, [cap]);

  useEffect(() => {
    let cancelled = false;
    void poll();
    const interval = setInterval(() => {
      if (!cancelled) void poll();
    }, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [poll]);

  /** Removes `seq` from the visible pending list and remembers it as handled so a later poll
   * (before the raw QueueDO entry's TTL expires) doesn't resurface it. Call on BOTH accept and
   * decline — either way, this specific request has been dealt with. */
  const markHandled = useCallback(async (seq: number) => {
    handledRef.current.add(seq);
    setPending((prev) => prev.filter((p) => p.seq !== seq));
    await saveHandledSeqs(handledRef.current);
  }, []);

  return { pending, markHandled, pollNow: poll };
}
