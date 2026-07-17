// Extracted as a shared primitive — both inherited kits apply a global film-grain overlay
// (Xfeatures Web: a `body::before` feTurbulence SVG at opacity 0.04, mix-blend overlay, applied
// site-wide; Xfeatures HQ: the same texture referenced per-section at opacity 0.03, mix-blend
// screen). Inlined as a data URI so packages/ui ships no external asset file.
import { cn } from "../lib/cn";

const NOISE_SVG =
  "data:image/svg+xml;utf8," +
  encodeURIComponent(
    '<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">' +
      '<filter id="n"><feTurbulence type="fractalNoise" baseFrequency="0.75" numOctaves="3" stitchTiles="stitch"/></filter>' +
      '<rect width="100%" height="100%" filter="url(#n)"/></svg>',
  );

interface NoiseOverlayProps {
  className?: string;
  /** 0.03–0.05 matches both source kits; default splits the difference. */
  opacity?: number;
  blendMode?: "overlay" | "screen";
}

export const NoiseOverlay = ({ className, opacity = 0.04, blendMode = "overlay" }: NoiseOverlayProps) => (
  <div
    aria-hidden
    className={cn("pointer-events-none absolute inset-0", className)}
    style={{
      backgroundImage: `url("${NOISE_SVG}")`,
      opacity,
      mixBlendMode: blendMode,
    }}
  />
);
