import { describe, expect, it } from "vitest";
import { decodeBhttpRequest, decodeBhttpResponse, encodeBhttpRequest, encodeBhttpResponse } from "./bhttp.js";

describe("Binary HTTP known-length framing (RFC 9292)", () => {
  it("round-trips a request with headers and a body", () => {
    const req = {
      method: "POST",
      scheme: "https",
      authority: "q.vort.xfeatures.net",
      path: "/membership/insert",
      headers: [
        ["content-type", "application/json"],
        ["x-custom", "value"],
      ] as [string, string][],
      body: new TextEncoder().encode('{"commitment":"0xabc"}'),
    };
    const decoded = decodeBhttpRequest(encodeBhttpRequest(req));
    expect(decoded).toEqual(req);
  });

  it("round-trips a request with zero headers and an empty body", () => {
    const req = { method: "GET", scheme: "https", authority: "q.vort.xfeatures.net", path: "/ohttp/keys", headers: [] as [string, string][], body: new Uint8Array(0) };
    const decoded = decodeBhttpRequest(encodeBhttpRequest(req));
    expect(decoded).toEqual(req);
  });

  it("round-trips a response with headers and a body", () => {
    const res = {
      status: 200,
      headers: [["content-type", "application/json"]] as [string, string][],
      body: new TextEncoder().encode('{"merkleRoot":"0xdead"}'),
    };
    const decoded = decodeBhttpResponse(encodeBhttpResponse(res));
    expect(decoded).toEqual(res);
  });

  it("round-trips a non-2xx status (error response)", () => {
    const res = { status: 409, headers: [] as [string, string][], body: new TextEncoder().encode("conflict") };
    const decoded = decodeBhttpResponse(encodeBhttpResponse(res));
    expect(decoded).toEqual(res);
  });

  it("round-trips a large body without corruption", () => {
    const body = new Uint8Array(50_000);
    crypto.getRandomValues(body);
    const req = { method: "POST", scheme: "https", authority: "a", path: "/", headers: [] as [string, string][], body };
    const decoded = decodeBhttpRequest(encodeBhttpRequest(req));
    expect(Array.from(decoded.body)).toEqual(Array.from(body));
  });

  it("rejects a response decoded as a request and vice versa (framing indicator mismatch)", () => {
    const res = encodeBhttpResponse({ status: 200, headers: [], body: new Uint8Array(0) });
    expect(() => decodeBhttpRequest(res)).toThrow();
    const req = encodeBhttpRequest({ method: "GET", scheme: "https", authority: "a", path: "/", headers: [], body: new Uint8Array(0) });
    expect(() => decodeBhttpResponse(req)).toThrow();
  });

  it("preserves header order and allows duplicate names (no map collapsing)", () => {
    const req = {
      method: "GET",
      scheme: "https",
      authority: "a",
      path: "/",
      headers: [
        ["set-cookie", "a=1"],
        ["set-cookie", "b=2"],
      ] as [string, string][],
      body: new Uint8Array(0),
    };
    const decoded = decodeBhttpRequest(encodeBhttpRequest(req));
    expect(decoded.headers).toEqual(req.headers);
  });
});
