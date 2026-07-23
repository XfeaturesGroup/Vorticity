// Post-login alias-suggestion prompt (2026-07 redesign pass). Registering a public @alias is
// entirely opt-in (docs/03 §8) — this modal exists purely to make sure people actually discover
// that it's available, without forcing it. Shown once per session unless permanently declined:
// - "Set up alias" -> navigates to Contacts (where AliasPanel actually lives), dismissed this session.
// - "Later" -> dismissed for THIS session only (sessionStorage) — reappears on the next fresh login.
// - "Decline" -> asks for a real confirmation (not a single mis-click away from never seeing this
//   again), then persists permanently (localStorage) and never shows again on this device.
import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AtSign, X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { loadOwnAlias } from "../lib/alias";

const SESSION_DISMISSED_KEY = "vorticity-alias-onboarding-dismissed";
const PERMANENTLY_DECLINED_KEY = "vorticity-alias-onboarding-declined";

export function AliasOnboardingModal() {
  const { token: cap, isRestoring } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [confirmingDecline, setConfirmingDecline] = useState(false);

  useEffect(() => {
    if (isRestoring || !cap) return;
    if (sessionStorage.getItem(SESSION_DISMISSED_KEY) || localStorage.getItem(PERMANENTLY_DECLINED_KEY)) return;
    let cancelled = false;
    loadOwnAlias().then((own) => {
      if (!cancelled && own === null) setOpen(true);
    });
    return () => {
      cancelled = true;
    };
  }, [cap, isRestoring]);

  const dismissForSession = () => {
    sessionStorage.setItem(SESSION_DISMISSED_KEY, "true");
    setOpen(false);
    setConfirmingDecline(false);
  };

  const handleSetUp = () => {
    dismissForSession();
    navigate("/contacts");
  };

  const handleDeclinePermanently = () => {
    localStorage.setItem(PERMANENTLY_DECLINED_KEY, "true");
    setOpen(false);
    setConfirmingDecline(false);
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[80] bg-black/70 backdrop-blur-md flex items-center justify-center p-4"
        >
          <motion.div
            initial={{ opacity: 0, y: 16, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.96 }}
            transition={{ type: "spring", stiffness: 360, damping: 28 }}
            className="relative w-full max-w-sm rounded-3xl border border-white/15 bg-[#090909] p-6 shadow-2xl"
          >
            {!confirmingDecline ? (
              <>
                <div className="w-12 h-12 rounded-2xl bg-fluid-peach/15 border border-fluid-peach/20 flex items-center justify-center mb-4">
                  <AtSign className="w-6 h-6 text-fluid-peach" />
                </div>
                <h2 className="text-lg font-semibold text-white mb-2">Make yourself easier to find</h2>
                <p className="text-sm text-white/60 leading-relaxed mb-6">
                  Register a public @alias so people can look you up and send a contact request — without ever learning your
                  real identity. Completely optional, and you can change your mind later.
                </p>
                <div className="flex flex-col gap-2">
                  <button
                    type="button"
                    onClick={handleSetUp}
                    className="w-full py-2.5 rounded-xl bg-fluid-peach/90 hover:bg-fluid-peach text-black text-sm font-medium transition-colors"
                  >
                    Set up @alias
                  </button>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={dismissForSession}
                      className="flex-1 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-white/80 text-sm font-medium transition-colors"
                    >
                      Later
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmingDecline(true)}
                      className="flex-1 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-white/50 text-sm font-medium transition-colors"
                    >
                      Decline
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => setConfirmingDecline(false)}
                  className="absolute top-4 right-4 text-white/40 hover:text-white transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
                <h2 className="text-lg font-semibold text-white mb-2">Not interested in an alias?</h2>
                <p className="text-sm text-white/60 leading-relaxed mb-6">
                  You won't be asked again on this device. You can still set one up anytime from the{" "}
                  <span className="text-white/80">Contacts</span> tab.
                </p>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setConfirmingDecline(false)}
                    className="flex-1 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-white/80 text-sm font-medium transition-colors"
                  >
                    Go back
                  </button>
                  <button
                    type="button"
                    onClick={handleDeclinePermanently}
                    className="flex-1 py-2.5 rounded-xl bg-signal-danger/90 hover:bg-signal-danger text-black text-sm font-medium transition-colors"
                  >
                    Yes, don't ask again
                  </button>
                </div>
              </>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
