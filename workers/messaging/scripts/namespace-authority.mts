#!/usr/bin/env -S npx tsx
// Offline tool for R18's "reserved/verified namespaces" feature — the anti-squatting/impersonation
// gap named repeatedly in docs/06's R18 entries ("reserved/verified namespaces" listed as "Not done"
// across three prior passes). Runs ONLY on an operator's own machine, never on a live Worker: the
// namespace authority's signing key never touches Cloudflare at all (unlike the RSABSSA issuer or
// the KT STH key, which sign LIVE per-request and therefore need `.dev.vars`/`wrangler secret put` —
// this authority signs rarely, offline, per reservation grant, so there is no live secret to store
// server-side in the first place. The Worker (AliasDO.ts) only ever needs the PUBLIC half, committed
// in namespace-authority-key.ts, same "public keys are safe to commit" precedent as issuer-keys.ts /
// kt-sth-key.ts).
//
// Reuses the crate's OWN Ed25519 sign/verify (alias_sig.rs, via the already-built pkg/client WASM) —
// no new crypto primitive, no second Ed25519 implementation in play. `alias_lookup_key`/
// `identity_verifying_key`/`alias_sign_action` are all real, already-tested wasm-bindgen exports.
//
// TWO DISTINCT, DOMAIN-SEPARATED SIGNATURE TYPES (never confusable — different literal prefix bytes
// are part of what gets signed, so a signature for one can never verify as the other):
//   "vortic-reserve-v1:"    || lookup_key            -> blocks a namespace from ordinary PoW-only
//                                                        registration (see `reserve` subcommand).
//   "vortic-registrant-v1:" || lookup_key || alias_pub -> authorizes ONE specific alias_pub to claim
//                                                        a reserved namespace (see `authorize`).
// A reserved lookup_key with no matching registrant authorization simply cannot be registered by
// anyone — including the authority itself, without going through `authorize` for a real alias_pub.
//
// USAGE:
//   npx tsx scripts/namespace-authority.mts keygen
//   npx tsx scripts/namespace-authority.mts reserve   --seed=<hex> --nickname=<plaintext>
//   npx tsx scripts/namespace-authority.mts authorize --seed=<hex> --nickname=<plaintext> --alias-pub=<64-hex>
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const pkgDir = join(new URL("../../../packages/vortic-core/pkg/client", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const glue = (await import(`file://${join(pkgDir, "vortic_core.js")}`)) as Record<string, unknown>;
await (glue.default as (opts: { module_or_path: Buffer }) => Promise<void>)({ module_or_path: readFileSync(join(pkgDir, "vortic_core_bg.wasm")) });

const aliasLookupKey = glue.alias_lookup_key as (nickname: string) => Uint8Array;
const identityVerifyingKey = glue.identity_verifying_key as (seed: Uint8Array) => Uint8Array;
const aliasSignAction = glue.alias_sign_action as (seed: Uint8Array, message: Uint8Array) => Uint8Array;

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
function fromHex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}
function getArg(argv: string[], name: string): string | undefined {
  const prefix = `--${name}=`;
  return argv.find((a) => a.startsWith(prefix))?.slice(prefix.length);
}
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

const [, , cmd, ...rest] = process.argv;

if (cmd === "keygen") {
  const seed = crypto.randomBytes(32);
  const pubkey = identityVerifyingKey(seed);
  console.log("Namespace authority keypair generated (SAVE THE SEED OFFLINE — this tool never writes it to disk):");
  console.log(`  seed (SECRET, offline only): ${hex(seed)}`);
  console.log(`  pubkey (safe to commit):     ${hex(pubkey)}`);
  console.log("\nPaste the pubkey into workers/messaging/src/namespace-authority-key.ts under a new `kid`.");
  process.exit(0);
}

if (cmd === "reserve") {
  const seedHex = getArg(rest, "seed");
  const nickname = getArg(rest, "nickname");
  if (!seedHex || !nickname) {
    console.error("usage: reserve --seed=<hex> --nickname=<plaintext>");
    process.exit(2);
  }
  const seed = fromHex(seedHex);
  const lookupKey = aliasLookupKey(nickname);
  const message = concatBytes(new TextEncoder().encode("vortic-reserve-v1:"), lookupKey);
  const sig = aliasSignAction(seed, message);
  console.log(JSON.stringify({ lookup_key: hex(lookupKey), reserve_sig: Buffer.from(sig).toString("base64") }, null, 2));
  console.log(`\n(nickname "${nickname}" -> lookup_key ${hex(lookupKey)}, kept here only for the operator's own record — never sent to the server)`);
  process.exit(0);
}

if (cmd === "authorize") {
  const seedHex = getArg(rest, "seed");
  const nickname = getArg(rest, "nickname");
  const aliasPubHex = getArg(rest, "alias-pub");
  if (!seedHex || !nickname || !aliasPubHex) {
    console.error("usage: authorize --seed=<hex> --nickname=<plaintext> --alias-pub=<64-hex>");
    process.exit(2);
  }
  const seed = fromHex(seedHex);
  const lookupKey = aliasLookupKey(nickname);
  const aliasPub = fromHex(aliasPubHex);
  if (aliasPub.length !== 32) {
    console.error("alias-pub must be exactly 32 bytes (64 hex chars)");
    process.exit(2);
  }
  const message = concatBytes(new TextEncoder().encode("vortic-registrant-v1:"), lookupKey, aliasPub);
  const sig = aliasSignAction(seed, message);
  console.log(
    JSON.stringify(
      { lookup_key: hex(lookupKey), alias_pub: aliasPubHex, registrant_sig: Buffer.from(sig).toString("base64") },
      null,
      2,
    ),
  );
  process.exit(0);
}

console.error("usage: npx tsx scripts/namespace-authority.mts <keygen|reserve|authorize> [--flags]");
process.exit(2);
