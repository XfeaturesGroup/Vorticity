// R25 LIVE integration test — requires real `wrangler dev` processes already running:
//   workers/enrollment  on :8788  (RSABSSA token issuance, for the real-capability test below)
//   workers/messaging   on :8787  (the Gateway: GET /ohttp/keys, POST /ohttp/gateway)
//   workers/ohttp-relay on :8789  (the Relay, forwarding to :8787)
// This is NOT part of the regular `pnpm test` unit suite's assumptions (those are pure in-process
// round trips against a fresh in-memory `OhttpGateway`) — it is the "did this actually work against
// the real deployed pieces" check, same spirit as this project's other live E2E scripts (scratchpad),
// just written as a vitest file so it can reuse this package's already-working TS/ESM test runner
// instead of fighting Node's raw `.ts` module resolution. Skips itself (not a hard failure) if the
// servers aren't reachable, so `pnpm test` in CI/without wrangler running doesn't false-negative.
import { describe, expect, it } from "vitest";
import { encapsulateRequest } from "./client.js";
import * as snarkjs from "snarkjs";
import { Identity } from "@semaphore-protocol/identity";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const RELAY = "http://127.0.0.1:8789";
const GATEWAY_DIRECT = "http://127.0.0.1:8787";
const ENROLL = "http://127.0.0.1:8788";
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return Buffer.from(bin, "binary").toString("base64");
}
function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
function fieldToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}
const FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
async function hashToField(label: string): Promise<bigint> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(label)));
  let n = 0n;
  for (const b of digest) n = (n << 8n) | BigInt(b);
  return n % FR_MODULUS;
}

/** Mints one real session capability via the full RSABSSA + official-ceremony-Semaphore chain —
 * same sequence every other live E2E script in this project uses, reused rather than re-derived. */
async function getRealCapability(): Promise<string> {
  const wasmGlue = (await import(
    /* @vite-ignore */ "file:///" + path.join(REPO_ROOT, "packages/vortic-core/pkg/client/vortic_core.js").replace(/\\/g, "/")
  )) as Record<string, (...args: never[]) => unknown>;
  const wasmBytes = fs.readFileSync(path.join(REPO_ROOT, "packages/vortic-core/pkg/client/vortic_core_bg.wasm"));
  (wasmGlue.initSync as (opts: { module: Buffer }) => void)({ module: wasmBytes });
  const blindsigBlind = wasmGlue.blindsig_blind as (pk: string, msg: Uint8Array) => Uint8Array;
  const blindsigFinalize = wasmGlue.blindsig_finalize as (pk: string, state: Uint8Array, sig: Uint8Array, msg: Uint8Array) => Uint8Array;

  const issuerPkPem = fs
    .readFileSync(path.join(REPO_ROOT, "apps/web/src/lib/issuerKey.ts"), "utf8")
    .match(/-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----/)![0];

  const MODULUS_BYTES = 384;
  const RANDOMIZER_BYTES = 32;
  const identityMsg = crypto.getRandomValues(new Uint8Array(32));
  const blindingState = blindsigBlind(issuerPkPem, identityMsg);
  const blindedMessage = blindingState.slice(0, MODULUS_BYTES);
  const randomizer = blindingState.slice(MODULUS_BYTES * 2, MODULUS_BYTES * 2 + RANDOMIZER_BYTES);

  const issueRes = await fetch(`${ENROLL}/token/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ blinded: bytesToB64(blindedMessage) }),
  });
  const { blindSig } = (await issueRes.json()) as { blindSig: string };
  const sig = blindsigFinalize(issuerPkPem, blindingState, b64ToBytes(blindSig), identityMsg);

  const identity = new Identity();
  const commitment = fieldToHex(identity.commitment);
  const insertRes = await fetch(`${GATEWAY_DIRECT}/membership/insert`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ msg: bytesToB64(identityMsg), sig: bytesToB64(sig), msgRandomizer: bytesToB64(randomizer), commitment }),
  });
  if (!insertRes.ok) throw new Error(`insert failed: ${JSON.stringify(await insertRes.json())}`);

  const proofRes = await fetch(`${GATEWAY_DIRECT}/membership/proof/${commitment}`);
  const merkleProof = (await proofRes.json()) as { index: number; siblings: string[]; merkleRoot: string };

  const epoch = Math.floor(Date.now() / 1000 / 3600);
  const scope = await hashToField(`vorticity-epoch:${epoch}`);
  const message = await hashToField("vorticity-auth-session");
  const merkleProofSiblings = merkleProof.siblings.map((h) => BigInt(`0x${h}`));
  while (merkleProofSiblings.length < 20) merkleProofSiblings.push(0n);

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    { secret: identity.secretScalar, merkleProofLength: merkleProof.siblings.length, merkleProofIndex: merkleProof.index, merkleProofSiblings, message, scope },
    path.join(REPO_ROOT, "apps/web/public/zk/semaphore-20.wasm"),
    path.join(REPO_ROOT, "apps/web/public/zk/semaphore-20.zkey"),
  );
  const g1 = (p: string[]) => Buffer.concat([Buffer.from(fieldToHex(BigInt(p[0]!)), "hex"), Buffer.from(fieldToHex(BigInt(p[1]!)), "hex")]);
  const g2 = (p: string[][]) =>
    Buffer.concat([
      Buffer.from(fieldToHex(BigInt(p[0]![0]!)), "hex"),
      Buffer.from(fieldToHex(BigInt(p[0]![1]!)), "hex"),
      Buffer.from(fieldToHex(BigInt(p[1]![0]!)), "hex"),
      Buffer.from(fieldToHex(BigInt(p[1]![1]!)), "hex"),
    ]);
  const proofBytes = Buffer.concat([g1(proof.pi_a as string[]), g2(proof.pi_b as string[][]), g1(proof.pi_c as string[])]);
  const [merkleRootHex, nullifierHex, messageHex, scopeHex] = (publicSignals as string[]).map((s) => fieldToHex(BigInt(s)));

  const sessionRes = await fetch(`${GATEWAY_DIRECT}/auth/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ proof: bytesToB64(proofBytes), merkleRoot: merkleRootHex, nullifier: nullifierHex, message: messageHex, scope: scopeHex }),
  });
  if (!sessionRes.ok) throw new Error(`/auth/session failed: ${JSON.stringify(await sessionRes.json())}`);
  const { capability } = (await sessionRes.json()) as { capability: string };
  return capability;
}

// `describe.runIf` is evaluated at COLLECTION time, before any `beforeAll` hook runs — so the
// reachability check must be a top-level `await` (vitest supports top-level await in test files),
// not something resolved inside a hook, or `runIf` would always see the pre-hook initial value.
let serversUp = false;
try {
  const res = await fetch(`${GATEWAY_DIRECT}/health`, { signal: AbortSignal.timeout(2000) });
  serversUp = res.ok;
} catch {
  serversUp = false;
}
if (!serversUp) {
  console.warn("[live.e2e] workers/messaging is not reachable at :8787 — skipping live OHTTP tests (start wrangler dev to run them).");
}

describe.runIf(serversUp)("R25 live OHTTP over real wrangler dev (Client -> Relay :8789 -> Gateway :8787)", () => {
  it("the Relay forwards the Gateway's real Key Config byte-for-byte", async () => {
    const directRes = await fetch(`${GATEWAY_DIRECT}/ohttp/keys`);
    const relayRes = await fetch(`${RELAY}/ohttp/keys`);
    expect(directRes.status).toBe(200);
    expect(relayRes.status).toBe(200);
    expect(directRes.headers.get("content-type")).toBe("application/ohttp-keys");
    const directBytes = new Uint8Array(await directRes.arrayBuffer());
    const relayBytes = new Uint8Array(await relayRes.arrayBuffer());
    expect(Buffer.from(relayBytes).equals(Buffer.from(directBytes))).toBe(true);
  });

  it("a real OHTTP round trip reaches the REAL /membership/proof/:commitment handler and returns its REAL response, encrypted both ways", async () => {
    const keyConfigBytes = new Uint8Array(await (await fetch(`${RELAY}/ohttp/keys`)).arrayBuffer());
    const fakeCommitment = "00".repeat(32);

    const handle = await encapsulateRequest(keyConfigBytes, {
      method: "GET",
      scheme: "https",
      authority: "q.vort.xfeatures.net",
      path: `/membership/proof/${fakeCommitment}`,
      headers: [],
      body: new Uint8Array(0),
    });

    // What actually crosses the wire to the Relay must not contain the plaintext path anywhere.
    const wireAsString = Buffer.from(handle.encapsulatedRequest).toString("latin1");
    expect(wireAsString).not.toContain("membership");
    expect(wireAsString).not.toContain(fakeCommitment);

    const relayRes = await fetch(`${RELAY}/ohttp/gateway`, {
      method: "POST",
      headers: { "Content-Type": "message/ohttp-req" },
      body: handle.encapsulatedRequest as BodyInit,
    });
    expect(relayRes.status).toBe(200);
    expect(relayRes.headers.get("content-type")).toBe("message/ohttp-res");

    const encapsulatedResponse = new Uint8Array(await relayRes.arrayBuffer());
    const decoded = await handle.decapsulateResponse(encapsulatedResponse);
    // A real 404 from MerkleTreeDO for a commitment that was never inserted — the REAL handler ran.
    expect(decoded.status).toBe(404);
    const body = JSON.parse(new TextDecoder().decode(decoded.body)) as { error: string };
    expect(body.error).toContain("not found in the membership tree");
  });

  it("a real POST /membership/insert reaches real blindsig verification through OHTTP (401 on a bogus signature, not bypassed)", async () => {
    const keyConfigBytes = new Uint8Array(await (await fetch(`${RELAY}/ohttp/keys`)).arrayBuffer());
    const handle = await encapsulateRequest(keyConfigBytes, {
      method: "POST",
      scheme: "https",
      authority: "q.vort.xfeatures.net",
      path: "/membership/insert",
      headers: [["content-type", "application/json"]],
      body: new TextEncoder().encode(
        JSON.stringify({
          msg: bytesToB64(new Uint8Array(32)),
          sig: bytesToB64(new Uint8Array(384)),
          msgRandomizer: bytesToB64(new Uint8Array(32)),
          commitment: "11".repeat(32),
        }),
      ),
    });
    const relayRes = await fetch(`${RELAY}/ohttp/gateway`, {
      method: "POST",
      headers: { "Content-Type": "message/ohttp-req" },
      body: handle.encapsulatedRequest as BodyInit,
    });
    const decoded = await handle.decapsulateResponse(new Uint8Array(await relayRes.arrayBuffer()));
    expect(decoded.status).toBe(401);
    const body = JSON.parse(new TextDecoder().decode(decoded.body)) as { error: string };
    expect(body.error).toContain("signature verification failed");
  });

  it("a real POST /queue/:id/push reaches capability verification through OHTTP (401 on a bogus cap, not bypassed)", async () => {
    const keyConfigBytes = new Uint8Array(await (await fetch(`${RELAY}/ohttp/keys`)).arrayBuffer());
    const handle = await encapsulateRequest(keyConfigBytes, {
      method: "POST",
      scheme: "https",
      authority: "q.vort.xfeatures.net",
      path: "/queue/live-test-queue/push",
      headers: [["authorization", "Bearer not-a-real-capability"], ["x-ttl-ms", "60000"], ["x-size-bucket", "0"]],
      body: new TextEncoder().encode("some ciphertext bytes"),
    });
    const relayRes = await fetch(`${RELAY}/ohttp/gateway`, {
      method: "POST",
      headers: { "Content-Type": "message/ohttp-req" },
      body: handle.encapsulatedRequest as BodyInit,
    });
    const decoded = await handle.decapsulateResponse(new Uint8Array(await relayRes.arrayBuffer()));
    expect(decoded.status).toBe(401);
    const body = JSON.parse(new TextDecoder().decode(decoded.body)) as { error: string };
    expect(body.error).toContain("Invalid session capability");
  });

  it(
    "FULL real round trip: mints a real capability, pushes a real message to a real QueueDO through OHTTP, " +
      "and confirms delivery via a direct WS subscribe — the actual highest-frequency traffic path, end to end",
    async () => {
      const capability = await getRealCapability();
      const queueId = `live-ohttp-queue-${crypto.randomUUID()}`;

      // Subscribe directly (WS subscribe is NOT OHTTP-wrapped — see docs/06's R25 entry for why that's
      // structural, not an oversight) so we observe delivery from the REAL send path independently.
      const received: { seq: number; ciphertext: string }[] = [];
      const ws = new WebSocket(`ws://127.0.0.1:8787/queue/${encodeURIComponent(queueId)}?cap=${encodeURIComponent(capability)}`);
      await new Promise<void>((resolve, reject) => {
        ws.addEventListener("open", () => resolve());
        ws.addEventListener("error", () => reject(new Error("WS subscribe failed to open")));
      });
      ws.addEventListener("message", (event) => {
        const wire = JSON.parse(event.data as string) as { type: string; seq: number; ciphertext: string };
        if (wire.type === "message") received.push({ seq: wire.seq, ciphertext: wire.ciphertext });
      });

      const keyConfigBytes = new Uint8Array(await (await fetch(`${RELAY}/ohttp/keys`)).arrayBuffer());
      const plaintextMarker = `real-ohttp-push-${crypto.randomUUID()}`;
      const handle = await encapsulateRequest(keyConfigBytes, {
        method: "POST",
        scheme: "https",
        authority: "q.vort.xfeatures.net",
        path: `/queue/${encodeURIComponent(queueId)}/push`,
        headers: [["authorization", `Bearer ${capability}`], ["x-ttl-ms", "60000"], ["x-size-bucket", "0"]],
        body: new TextEncoder().encode(plaintextMarker),
      });
      const relayRes = await fetch(`${RELAY}/ohttp/gateway`, {
        method: "POST",
        headers: { "Content-Type": "message/ohttp-req" },
        body: handle.encapsulatedRequest as BodyInit,
      });
      expect(relayRes.status).toBe(200);
      const decoded = await handle.decapsulateResponse(new Uint8Array(await relayRes.arrayBuffer()));
      expect(decoded.status).toBe(201);
      const pushBody = JSON.parse(new TextDecoder().decode(decoded.body)) as { seq: number };
      expect(typeof pushBody.seq).toBe("number");

      await new Promise((resolve) => setTimeout(resolve, 500));
      ws.close();
      expect(received.length).toBe(1);
      expect(received[0]!.seq).toBe(pushBody.seq);
      expect(Buffer.from(received[0]!.ciphertext, "base64").toString("utf8")).toBe(plaintextMarker);
    },
    20000,
  );

  it("rejects an encapsulated request sent directly to the Gateway with the wrong Content-Type", async () => {
    const keyConfigBytes = new Uint8Array(await (await fetch(`${RELAY}/ohttp/keys`)).arrayBuffer());
    const handle = await encapsulateRequest(keyConfigBytes, {
      method: "GET",
      scheme: "https",
      authority: "q.vort.xfeatures.net",
      path: "/membership/proof/" + "00".repeat(32),
      headers: [],
      body: new Uint8Array(0),
    });
    const res = await fetch(`${GATEWAY_DIRECT}/ohttp/gateway`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: handle.encapsulatedRequest as BodyInit,
    });
    expect(res.status).toBe(400);
  });

  it(
    "R26 FUNCTIONAL test: a WS subscribe proxied through the Relay still delivers a real-time message correctly. " +
      "NOT a proof the client IP is hidden (see docs/06's R26 entry — that specific property is unverifiable " +
      "in wrangler dev) — this only confirms the proxy doesn't break real-time delivery / force polling.",
    async () => {
      const capability = await getRealCapability();
      const queueId = `live-ws-proxy-queue-${crypto.randomUUID()}`;

      // Connect through the RELAY (:8789), not the Gateway directly — this is the whole point of R26.
      const received: { seq: number; ciphertext: string }[] = [];
      const ws = new WebSocket(`ws://127.0.0.1:8789/queue/${encodeURIComponent(queueId)}?cap=${encodeURIComponent(capability)}`);
      await new Promise<void>((resolve, reject) => {
        ws.addEventListener("open", () => resolve());
        ws.addEventListener("error", () => reject(new Error("WS-via-relay subscribe failed to open")));
      });
      ws.addEventListener("message", (event) => {
        const wire = JSON.parse(event.data as string) as { type: string; seq: number; ciphertext: string };
        if (wire.type === "message") received.push({ seq: wire.seq, ciphertext: wire.ciphertext });
      });

      // Push directly to the Gateway (bypassing OHTTP deliberately here — this test isolates the WS
      // proxy leg specifically, not the request/response OHTTP path already covered by other tests).
      const plaintextMarker = `real-ws-via-relay-${crypto.randomUUID()}`;
      const pushRes = await fetch(`${GATEWAY_DIRECT}/queue/${encodeURIComponent(queueId)}/push`, {
        method: "POST",
        headers: { Authorization: `Bearer ${capability}`, "X-Ttl-Ms": "60000", "X-Size-Bucket": "0" },
        body: new TextEncoder().encode(plaintextMarker),
      });
      expect(pushRes.status).toBe(201);
      const { seq } = (await pushRes.json()) as { seq: number };

      await new Promise((resolve) => setTimeout(resolve, 500));
      ws.close();
      expect(received.length).toBe(1);
      expect(received[0]!.seq).toBe(seq);
      expect(Buffer.from(received[0]!.ciphertext, "base64").toString("utf8")).toBe(plaintextMarker);
    },
    20000,
  );
});
