import { describe, expect, it } from "vitest";
import { encapsulateRequest } from "./client.js";
import { OhttpGateway } from "./gateway.js";

describe("full OHTTP round trip (Client encapsulate -> Gateway decapsulate -> handle -> encapsulate -> Client decapsulate)", () => {
  it("delivers the exact request and the exact response through opaque HPKE-sealed bytes", async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const gateway = await OhttpGateway.create(seed, 7);
    const keyConfigBytes = gateway.keyConfigBytes();

    const originalRequest = {
      method: "POST",
      scheme: "https",
      authority: "q.vort.xfeatures.net",
      path: "/membership/insert",
      headers: [["content-type", "application/json"]] as [string, string][],
      body: new TextEncoder().encode('{"commitment":"0xabc123"}'),
    };

    const handle = await encapsulateRequest(keyConfigBytes, originalRequest);
    // What actually crosses the wire to the Relay is opaque HPKE ciphertext, not the plaintext JSON —
    // sanity check that the encoded bytes don't just contain the plaintext body unencrypted anywhere.
    const bodyAsString = new TextDecoder().decode(handle.encapsulatedRequest);
    expect(bodyAsString).not.toContain("commitment");
    expect(bodyAsString).not.toContain("0xabc123");

    const { request: recoveredRequest, encapsulateResponse } = await gateway.decapsulateRequest(handle.encapsulatedRequest);
    expect(recoveredRequest).toEqual(originalRequest);

    const originalResponse = {
      status: 200,
      headers: [["content-type", "application/json"]] as [string, string][],
      body: new TextEncoder().encode('{"merkleRoot":"0xdeadbeef","index":1}'),
    };
    const encapsulatedResponse = await encapsulateResponse(originalResponse);
    const responseAsString = new TextDecoder().decode(encapsulatedResponse);
    expect(responseAsString).not.toContain("merkleRoot");
    expect(responseAsString).not.toContain("deadbeef");

    const recoveredResponse = await handle.decapsulateResponse(encapsulatedResponse);
    expect(recoveredResponse).toEqual(originalResponse);
  });

  it("two requests from the same client use independent HPKE encapsulations (no key/nonce reuse)", async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const gateway = await OhttpGateway.create(seed, 1);
    const keyConfigBytes = gateway.keyConfigBytes();
    const req = { method: "GET", scheme: "https", authority: "a", path: "/x", headers: [] as [string, string][], body: new Uint8Array(0) };

    const h1 = await encapsulateRequest(keyConfigBytes, req);
    const h2 = await encapsulateRequest(keyConfigBytes, req);
    expect(Buffer.from(h1.encapsulatedRequest).equals(Buffer.from(h2.encapsulatedRequest))).toBe(false);
  });

  it("rejects a request encapsulated under the wrong key_id", async () => {
    const gatewayA = await OhttpGateway.create(crypto.getRandomValues(new Uint8Array(32)), 1);
    const gatewayB = await OhttpGateway.create(crypto.getRandomValues(new Uint8Array(32)), 2);
    const req = { method: "GET", scheme: "https", authority: "a", path: "/x", headers: [] as [string, string][], body: new Uint8Array(0) };
    const handle = await encapsulateRequest(gatewayA.keyConfigBytes(), req);
    await expect(gatewayB.decapsulateRequest(handle.encapsulatedRequest)).rejects.toThrow();
  });

  it("a tampered ciphertext byte fails AEAD verification rather than decoding garbage", async () => {
    const gateway = await OhttpGateway.create(crypto.getRandomValues(new Uint8Array(32)), 1);
    const req = { method: "GET", scheme: "https", authority: "a", path: "/x", headers: [] as [string, string][], body: new Uint8Array(0) };
    const handle = await encapsulateRequest(gateway.keyConfigBytes(), req);
    const tampered = handle.encapsulatedRequest.slice();
    const lastIndex = tampered.length - 1;
    tampered[lastIndex] = tampered[lastIndex]! ^ 0x01;
    await expect(gateway.decapsulateRequest(tampered)).rejects.toThrow();
  });

  it("gateway key config is deterministic from the same seed (Worker cold-start friendly)", async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const g1 = await OhttpGateway.create(seed, 3);
    const g2 = await OhttpGateway.create(seed, 3);
    expect(Buffer.from(g1.keyConfigBytes()).equals(Buffer.from(g2.keyConfigBytes()))).toBe(true);
  });
});
