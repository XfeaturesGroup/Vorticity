// Public @alias registration widget (docs/03 §8) — "alias contact establishment" pass (2026-07).
// Self-contained like SecureScorePanel: owns its own load/register state, embeddable from
// Settings.tsx with no page-level logic of its own. No update/revoke UI — `AliasDO.ts` doesn't
// support either yet (see its own header comment), so once registered this becomes read-only.
import { useEffect, useState } from "react";
import { AtSign, Loader2 } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { isValidNickname, loadOwnAlias, registerAlias, type OwnAlias } from "../lib/alias";

export function AliasPanel() {
  const { token: cap } = useAuth();
  const [own, setOwn] = useState<OwnAlias | null | "loading">("loading");
  const [draft, setDraft] = useState("");
  const [mining, setMining] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    loadOwnAlias().then((result) => {
      if (!cancelled) setOwn(result);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const submit = async () => {
    if (!cap || mining) return;
    const nickname = draft.trim().toLowerCase();
    if (!isValidNickname(nickname)) {
      setError("3-32 characters, lowercase letters/digits/underscore only");
      return;
    }
    setError(null);
    setMining(true);
    try {
      const result = await registerAlias(nickname, cap);
      setOwn(result);
    } catch (err) {
      setError((err as Error).message.includes("409") ? "That nickname is already taken" : (err as Error).message);
    } finally {
      setMining(false);
    }
  };

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
      <div className="flex items-center gap-2 mb-1">
        <AtSign className="w-4 h-4 text-fluid-peach" />
        <h3 className="text-sm font-semibold text-white">Public Alias</h3>
      </div>
      <p className="text-xs text-white/50 mb-4">
        Opt-in discoverability. The server learns only <span className="text-white/70">@nickname → an intro queue</span> — never your
        real identity. Off by default; once registered, this cannot be changed yet.
      </p>

      {own === "loading" && <div className="text-xs text-white/40">Loading...</div>}

      {own !== "loading" && own !== null && (
        <div className="flex items-center gap-2 text-sm text-white">
          <span className="text-fluid-peach font-mono">@{own.nickname}</span>
          <span className="text-white/40 text-xs">registered on this device</span>
        </div>
      )}

      {own === null && (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="nickname"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void submit()}
              disabled={mining}
              maxLength={32}
              className="flex-1 min-w-0 bg-black/30 border border-white/10 rounded-lg py-2 px-3 text-sm text-white placeholder-white/40 focus:outline-none focus:border-fluid-peach/50 disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => void submit()}
              disabled={mining || !cap}
              className="shrink-0 px-4 py-2 text-xs rounded-lg bg-fluid-peach/90 hover:bg-fluid-peach text-black transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
            >
              {mining && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              {mining ? "Mining proof-of-work..." : "Register"}
            </button>
          </div>
          {mining && <p className="text-[11px] text-white/40">This proves real computational cost to the server (anti-spam) — usually a few seconds.</p>}
          {error && <p className="text-[11px] text-signal-danger">{error}</p>}
        </div>
      )}
    </div>
  );
}
