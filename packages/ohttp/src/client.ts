// RFC 9458 Client role: encapsulate a Binary HTTP request under the Gateway's published Key Config,
// send the opaque bytes to a Relay, and later decapsulate the Gateway's response. The Client never
// talks to the Gateway directly — see workers/ohttp-relay for the (dumb, non-cryptographic) Relay hop
// that actually carries these bytes, which is what gives the Relay operator "sees IP, not content"
// and the Gateway "sees content, not IP".
import { decodeBhttpResponse, encodeBhttpRequest, type BhttpRequest, type BhttpResponse } from "./bhttp.js";
import { buildRequestInfo, deriveResponseKeyNonce, encodeHeader, newSuite, responseExportLength, RESPONSE_EXPORT_CONTEXT } from "./hpkeSuite.js";
import { decodeKeyConfig } from "./keyConfig.js";

export interface OhttpRequestHandle {
  /** POST this to the Relay with content-type `message/ohttp-req` (see MEDIA_TYPE_REQUEST). */
  encapsulatedRequest: Uint8Array;
  /** Feed the Relay's response body into this to recover the Gateway's real response. */
  decapsulateResponse(encapsulatedResponse: Uint8Array): Promise<BhttpResponse>;
}

/**
 * Encapsulates one Binary HTTP request under `keyConfigBytes` (a `GET /ohttp/keys` response). Fresh
 * HPKE randomness is drawn internally by `@hpke/core`'s WebCrypto-backed `generateKeyPair` for the
 * ephemeral sender keypair each call — unlike `vortic-core`'s Rust code, this package does not thread
 * caller-supplied seeds through (WebCrypto's own CSPRNG is the appropriate source here, same as any
 * other browser/Workers TLS-adjacent operation, not a place this codebase hand-rolls determinism).
 */
export async function encapsulateRequest(keyConfigBytes: Uint8Array, req: BhttpRequest): Promise<OhttpRequestHandle> {
  const keyConfig = decodeKeyConfig(keyConfigBytes);
  const suite = newSuite();
  if (!keyConfig.algorithms.some((a) => a.kdfId === 0x0001 && a.aeadId === 0x0001)) {
    throw new Error("ohttp: gateway's key config does not offer HKDF-SHA256 + AES-128-GCM, the only suite this client supports");
  }
  const recipientPublicKey = await suite.kem.deserializePublicKey(keyConfig.publicKey);
  const hdr = encodeHeader(keyConfig.keyId);
  const info = buildRequestInfo(hdr);
  const sender = await suite.createSenderContext({ recipientPublicKey, info });

  const bhttpBytes = encodeBhttpRequest(req);
  const ct = await sender.seal(bhttpBytes);

  const encapsulatedRequest = new Uint8Array(hdr.length + sender.enc.byteLength + ct.byteLength);
  encapsulatedRequest.set(hdr, 0);
  encapsulatedRequest.set(new Uint8Array(sender.enc), hdr.length);
  encapsulatedRequest.set(new Uint8Array(ct), hdr.length + sender.enc.byteLength);

  const enc = sender.enc;
  const exportLen = responseExportLength(suite);

  return {
    encapsulatedRequest,
    async decapsulateResponse(encapsulatedResponse: Uint8Array): Promise<BhttpResponse> {
      const nonceLen = exportLen;
      if (encapsulatedResponse.length < nonceLen) throw new Error("ohttp: encapsulated response shorter than the response_nonce field");
      const responseNonce = encapsulatedResponse.slice(0, nonceLen);
      const ct = encapsulatedResponse.slice(nonceLen);

      const exportSecret = await sender.export(RESPONSE_EXPORT_CONTEXT, exportLen);
      const { key, nonce } = await deriveResponseKeyNonce(suite, exportSecret, enc, responseNonce);
      const aeadCtx = suite.aead.createEncryptionContext(key);
      const pt = await aeadCtx.open(nonce, ct, new Uint8Array(0));
      return decodeBhttpResponse(new Uint8Array(pt));
    },
  };
}
