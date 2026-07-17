// Ported from Xfeatures HQ's src/components/ui/Modal.tsx — same API. Fixed to use the obsidian
// surface scale instead of the source kit's raw `bg-[#111]` (an inconsistency in the original:
// every other surface in that kit used the glass pattern — bg-black/NN + backdrop-blur — while
// Modal alone used an opaque hardcoded hex).
import type { ReactNode } from "react";
import { X } from "lucide-react";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}

export function Modal({ isOpen, onClose, title, children }: ModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-obsidian-800/95 backdrop-blur-3xl border border-white/10 rounded-2xl w-full max-w-md shadow-glass overflow-hidden flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between p-4 border-b border-white/10">
          <h2 className="text-white font-semibold">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 text-white/50 hover:text-white transition-colors rounded-lg hover:bg-white/10"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 overflow-y-auto vx-scrollbar">{children}</div>
      </div>
    </div>
  );
}
