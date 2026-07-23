#!/usr/bin/env bash
# Structural fix for the "git-triggered Pages build is structurally broken" incident
# (docs/deploy-checklist.md §6, 2026-07-19): Cloudflare Pages' build image has no Rust/wasm-pack
# toolchain, so it can never produce `packages/vortic-core/pkg/client` (deliberately git-ignored — a
# build artifact, not source) that `apps/web`'s own build depends on. Every prior deploy that
# "succeeded" via the git-triggered auto-build must actually have been a manual `wrangler pages
# deploy` from a machine with `pkg/` already built on disk, not a real CI build — see that doc's §6
# for the full incident writeup this fixes.
#
# THE FIX: make `apps/web`'s own `build` script self-sufficient — bootstrap a minimal Rust +
# wasm-pack toolchain if one isn't already present (idempotent: a no-op if `wasm-pack` is already on
# PATH, which is every local dev machine and any CI image that happens to already have it cached),
# then build vortic-core's `client-full` wasm output before `vite build` ever runs. This needs NO
# Cloudflare Pages *project setting* changes (build command/root directory stay whatever they already
# are) — the fix lives entirely in this repo, which is the only thing this session can actually
# control without dashboard access.
#
# HONEST COST, not hidden: Cloudflare Pages build containers are very unlikely to cache `~/.cargo`/
# `~/.rustup` across builds, so this bootstrap (rustup install + `cargo install wasm-pack` + compiling
# vortic-core's dependency tree — pairing curves, ML-KEM, Argon2id, etc. — to wasm in release mode)
# probably reruns from scratch on every single push that touches `main`, adding real minutes to every
# deploy. That is a real, accepted tradeoff for a repo-only fix with no dashboard access to configure
# a proper Cloudflare build-cache path for `~/.cargo` instead — revisit if build times become a
# problem in practice.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VORTIC_CORE="$REPO_ROOT/packages/vortic-core"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "[build-wasm] wasm-pack not found on PATH — bootstrapping a minimal Rust + wasm-pack toolchain..."
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
  fi
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
  rustup target add wasm32-unknown-unknown
  cargo install wasm-pack --locked
fi
# shellcheck disable=SC1090
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env" || true

echo "[build-wasm] Building vortic-core (client-full) -> pkg/client..."
cd "$VORTIC_CORE"
wasm-pack build --target web --out-dir pkg/client --features client-full
echo "[build-wasm] Done."
