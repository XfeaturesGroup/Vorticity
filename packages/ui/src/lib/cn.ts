// Identical helper in both inherited kits (Xfeatures HQ + Xfeatures Web) — ported verbatim.
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
