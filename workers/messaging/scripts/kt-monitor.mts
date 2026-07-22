#!/usr/bin/env -S npx tsx
// Independent gossip/monitor for KeyTransparencyDO's append-only log — closes the "still not built"
// gap named repeatedly in docs/06's R18 entries and, most precisely, in sth.ts's own header comment:
// "two such STHs compared later (by gossip/monitoring — still not built, see below) constitute
// cryptographic proof of misbehavior." A Signed Tree Head alone only makes equivocation
// DETECTABLE, not impossible — detection requires something that (a) remembers what it saw last
// time independently of whether the server feels like admitting it, and (b) checks the server's new
// claim against that memory, not against itself. That is this script's entire job.
//
// WHY THIS REUSES THE PROJECT'S OWN verifySth/verifyConsistency RATHER THAN REIMPLEMENTING THEM
// FROM SCRATCH: the tempting "more independent" move is a from-scratch reimplementation of RFC 6962
// consistency-proof verification, on the theory that a shared implementation shares bugs. In
// practice a hand-rolled reimplementation of an intricate, easy-to-get-subtly-wrong algorithm
// (§2.1.2's iterative verifier) is MORE likely to introduce a divergent bug than to catch one — a
// monitor with a broken verifier either false-alarms constantly (ignored, defeats the point) or
// silently accepts forks it should catch (worse than not running at all). The property that
// actually matters for equivocation detection — independent, tamper-evident memory of prior state —
// comes from WHERE and HOW this script is run (a separate account/machine/schedule from the Worker
// operator, per this file's own deployment note below), not from divergent arithmetic. See
// ktHash.ts's header comment for the same argument applied to the hash-combine function.
//
// DEPLOYMENT NOTE (the part that actually provides the security property): running this against
// `localhost:8787` from the same machine/account that operates workers/messaging (as this file's own
// live test below does) proves the MECHANISM works, not the THREAT MODEL it exists for — a
// single-operator monitor colludes trivially with a single-operator log. Real value requires a THIRD
// PARTY (or at minimum a separate account/schedule under different control) running this on a cron
// against the public `https://api.vort.xfeatures.net` endpoint, keeping ITS OWN state file the
// primary operator cannot edit. Undeployed as of this pass — see docs/06's R18 entry for this
// pass's honest scope note.
//
// USAGE: npx tsx scripts/kt-monitor.mts [--base-url=http://127.0.0.1:8787] [--state-file=./kt-monitor-state.json] [--history-file=./kt-monitor-history.jsonl]
// EXIT CODES: 0 = OK (or first-run baseline established). 1 = ALARM — real evidence of log
// misbehavior, printed to stderr with both conflicting STHs / the failing proof. 2 = the check could
// not be completed (network error, malformed server response) — deliberately distinct from 1 so an
// unattended cron job's alerting can tell "the log is lying" apart from "this script broke."

import { readFileSync, writeFileSync, appendFileSync, existsSync } from "node:fs";
import { verifySth, type SignedTreeHead } from "../src/sth.js";
import { verifyConsistency } from "../src/merkleConsistency.js";
import { ktCombine, hexToField } from "../src/ktHash.js";
import { CURRENT_KT_STH_PK_PEM } from "../src/kt-sth-key.js";

interface Args {
  baseUrl: string;
  stateFile: string;
  historyFile: string;
}

function parseArgs(argv: string[]): Args {
  const get = (name: string, fallback: string) => {
    const prefix = `--${name}=`;
    const hit = argv.find((a) => a.startsWith(prefix));
    return hit ? hit.slice(prefix.length) : fallback;
  };
  return {
    baseUrl: get("base-url", "http://127.0.0.1:8787"),
    stateFile: get("state-file", "./kt-monitor-state.json"),
    historyFile: get("history-file", "./kt-monitor-history.jsonl"),
  };
}

interface MonitorState {
  baseUrl: string;
  lastVerified: SignedTreeHead;
}

function loadState(path: string): MonitorState | null {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as MonitorState;
}

function saveState(path: string, state: MonitorState): void {
  writeFileSync(path, JSON.stringify(state, null, 2) + "\n", "utf8");
}

function appendHistory(path: string, entry: Record<string, unknown>): void {
  appendFileSync(path, JSON.stringify({ ...entry, checkedAt: Date.now() }) + "\n", "utf8");
}

function alarm(historyFile: string, reason: string, evidence: Record<string, unknown>): never {
  console.error(`\n🚨 KT-MONITOR ALARM: ${reason}`);
  console.error(JSON.stringify(evidence, null, 2));
  appendHistory(historyFile, { verdict: "ALARM", reason, evidence });
  process.exit(1);
}

function operationalError(historyFile: string, reason: string): never {
  console.error(`kt-monitor: could not complete check — ${reason}`);
  appendHistory(historyFile, { verdict: "ERROR", reason });
  process.exit(2);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  let sth: SignedTreeHead;
  try {
    const res = await fetch(`${args.baseUrl}/transparency/sth`);
    if (!res.ok) return operationalError(args.historyFile, `GET /transparency/sth -> HTTP ${res.status}`);
    sth = (await res.json()) as SignedTreeHead;
  } catch (err) {
    return operationalError(args.historyFile, `fetching STH: ${(err as Error).message}`);
  }

  if (!verifySth(CURRENT_KT_STH_PK_PEM, sth)) {
    // A signature failure is itself alarm-worthy (a forged/corrupted STH, or a key mismatch), not a
    // mere operational hiccup — the whole point of signing is that this must never happen silently.
    return alarm(args.historyFile, "STH signature verification FAILED — the fetched STH is not validly signed by the committed key", { sth });
  }

  const prior = loadState(args.stateFile);
  if (!prior) {
    console.log(`kt-monitor: no prior state at ${args.stateFile} — establishing baseline at size=${sth.size}, root=${sth.root.slice(0, 16)}…`);
    saveState(args.stateFile, { baseUrl: args.baseUrl, lastVerified: sth });
    appendHistory(args.historyFile, { verdict: "BASELINE", sth });
    process.exit(0);
  }

  const prev = prior.lastVerified;

  if (sth.size < prev.size) {
    return alarm(args.historyFile, `log SHRANK: previously verified size=${prev.size}, now claims size=${sth.size} — violates append-only`, {
      previouslyVerified: prev,
      nowClaimed: sth,
    });
  }

  if (sth.size === prev.size) {
    if (sth.root !== prev.root) {
      // Two DIFFERENT signed roots for the SAME size — the exact equivocation sth.ts's header
      // comment names: real, non-repudiable, cryptographic proof of dishonest log operation.
      return alarm(args.historyFile, `EQUIVOCATION: two different signed roots for the SAME size=${sth.size}`, {
        previouslyVerified: prev,
        nowClaimed: sth,
      });
    }
    console.log(`kt-monitor: OK — size unchanged (${sth.size}), root unchanged, both independently signed and matching.`);
    saveState(args.stateFile, { baseUrl: args.baseUrl, lastVerified: sth });
    appendHistory(args.historyFile, { verdict: "OK-UNCHANGED", sth });
    process.exit(0);
  }

  // sth.size > prev.size: the log claims to have grown. Demand a real consistency proof, and check
  // it against what THIS monitor already verified last time — not against the server's own
  // (unauthenticated in this response) restatement of the earlier root.
  let consistency: { first: number; second: number; firstRoot: string; secondRoot: string; proof: string[] };
  try {
    const res = await fetch(`${args.baseUrl}/transparency/consistency?first=${prev.size}&second=${sth.size}`);
    if (!res.ok) return operationalError(args.historyFile, `GET /transparency/consistency -> HTTP ${res.status}`);
    consistency = (await res.json()) as typeof consistency;
  } catch (err) {
    return operationalError(args.historyFile, `fetching consistency proof: ${(err as Error).message}`);
  }

  if (consistency.firstRoot !== prev.root) {
    return alarm(args.historyFile, "consistency endpoint's firstRoot does NOT match the root this monitor already independently verified for that size — the server is rewriting history", {
      previouslyVerified: prev,
      consistencyResponse: consistency,
    });
  }
  if (consistency.secondRoot !== sth.root) {
    return alarm(args.historyFile, "consistency endpoint's secondRoot does NOT match the freshly-signed STH's root for the same size — internal inconsistency between /transparency/sth and /transparency/consistency", {
      sth,
      consistencyResponse: consistency,
    });
  }

  const ok = verifyConsistency(
    ktCombine,
    prev.size,
    sth.size,
    hexToField(prev.root),
    hexToField(sth.root),
    consistency.proof.map(hexToField),
  );
  if (!ok) {
    // The strongest possible finding this script can produce: a cryptographic RFC 6962 consistency
    // proof that FAILS between two roots the log itself signed at different times — a real fork.
    return alarm(args.historyFile, "RFC 6962 consistency proof FAILED to verify between the previously-signed root and the newly-signed root — cryptographic evidence of a forked log", {
      previouslyVerified: prev,
      nowClaimed: sth,
      consistencyResponse: consistency,
    });
  }

  console.log(
    `kt-monitor: OK — log grew from size=${prev.size} to size=${sth.size}, consistency proof verified, new root ${sth.root.slice(0, 16)}… is a genuine append-only extension of the prior root ${prev.root.slice(0, 16)}….`,
  );
  saveState(args.stateFile, { baseUrl: args.baseUrl, lastVerified: sth });
  appendHistory(args.historyFile, { verdict: "OK-GREW", from: prev, to: sth, consistencyChecked: true });
  process.exit(0);
}

main().catch((err) => {
  console.error("kt-monitor: unexpected error:", err);
  process.exit(2);
});
