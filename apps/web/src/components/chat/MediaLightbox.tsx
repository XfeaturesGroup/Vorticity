import { useEffect } from "react";
import { X } from "lucide-react";

/** Full-screen image viewer — click backdrop, click the X, or Escape to close. No portal library in
 * this app yet; plain `fixed` positioning is enough since nothing in the chat view tree sets a CSS
 * `transform` (which would otherwise trap a `fixed` child inside its own containing block). */
export function MediaLightbox({ src, alt, onClose }: { src: string; alt: string; onClose: () => void }) {
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-6" onClick={onClose}>
      <button
        type="button"
        onClick={onClose}
        title="Close"
        className="absolute top-4 right-4 p-2 rounded-lg text-white/70 hover:text-white hover:bg-white/10 transition-colors"
      >
        <X className="w-6 h-6" />
      </button>
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
      <img src={src} alt={alt} className="max-w-full max-h-full rounded-lg object-contain" onClick={(e) => e.stopPropagation()} />
    </div>
  );
}
