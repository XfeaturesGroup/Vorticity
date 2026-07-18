// RFC 9458 Gateway role: publishes a Key Config, decapsulates a Client's HPKE-sealed Binary HTTP
// request (recovering the real request but never the Client's IP — it only ever sees bytes forwarded
// by the Relay), dispatches it to the real handler, and encapsulates the real response back.
import { AEAD_ID, KDF_ID, KEM_ID, buildRequestInfo, deriveResponseKeyNonce, decodeHeader, newSuite, responseExportLength, RESPONSE_EXPORT_CONTEXT } from "./hpkeSuite.js";
import { decodeBhttpRequest, encodeBhttpResponse, type BhttpRequest, type BhttpResponse } from "./bhttp.js";
import { encodeKeyConfig } from "./keyConfig.js";

const HEADER_LEN = 7; // key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)

export class OhttpGateway {
  private constructor(
    private readonly suite: ReturnType<typeof newSuite>,
    private readonly keyId: number,
    private readonly privateKey: CryptoKey,
    private readonly publicKeyBytes: Uint8Array,
  ) {}

  /** Deterministic from `seed` (32+ bytes, e.g. an `OHTTP_GATEWAY_SEED` Worker secret) — same
   * "caller supplies real entropy once, key material re-derives deterministically" convention as
   * `vortic-core`, so a Worker cold-start never needs to persist a raw private key separately. */
  static async create(seed: Uint8Array, keyId: number): Promise<OhttpGateway> {
    const suite = newSuite();
    const keyPair = await suite.kem.deriveKeyPair(seed);
    const publicKeyBytes = new Uint8Array(await suite.kem.serializePublicKey(keyPair.publicKey));
    return new OhttpGateway(suite, keyId, keyPair.privateKey, publicKeyBytes);
  }

  /** Serve this at `GET /ohttp/keys` with content-type `application/ohttp-keys` (MEDIA_TYPE_KEY_CONFIG). */
  keyConfigBytes(): Uint8Array {
    return encodeKeyConfig(this.keyId, this.publicKeyBytes);
  }

  async decapsulateRequest(
    encapsulatedRequest: Uint8Array,
  ): Promise<{ request: BhttpRequest; encapsulateResponse: (res: BhttpResponse) => Promise<Uint8Array> }> {
    if (encapsulatedRequest.length < HEADER_LEN) throw new Error("ohttp: encapsulated request shorter than the 7-byte header");
    const hdr = encapsulatedRequest.slice(0, HEADER_LEN);
    const { keyId, kemId, kdfId, aeadId } = decodeHeader(hdr);
    if (keyId !== this.keyId) throw new Error(`ohttp: request addressed to key_id ${keyId}, this gateway serves ${this.keyId}`);
    if (kemId !== KEM_ID || kdfId !== KDF_ID || aeadId !== AEAD_ID) {
      throw new Error("ohttp: request uses an unsupported HPKE suite");
    }

    const encSize = this.suite.kem.encSize;
    const enc = encapsulatedRequest.slice(HEADER_LEN, HEADER_LEN + encSize);
    const ct = encapsulatedRequest.slice(HEADER_LEN + encSize);
    if (enc.length !== encSize) throw new Error("ohttp: encapsulated request truncated in the `enc` field");

    const info = buildRequestInfo(hdr);
    const recipient = await this.suite.createRecipientContext({ recipientKey: this.privateKey, enc, info });
    const pt = await recipient.open(ct);
    const request = decodeBhttpRequest(new Uint8Array(pt));

    const suite = this.suite;
    const exportLen = responseExportLength(suite);
    const encapsulateResponse = async (res: BhttpResponse): Promise<Uint8Array> => {
      const responseNonce = new Uint8Array(exportLen);
      crypto.getRandomValues(responseNonce);
      const exportSecret = await recipient.export(RESPONSE_EXPORT_CONTEXT, exportLen);
      const { key, nonce } = await deriveResponseKeyNonce(suite, exportSecret, enc.buffer as ArrayBuffer, responseNonce);
      const aeadCtx = suite.aead.createEncryptionContext(key);
      const sealed = await aeadCtx.seal(nonce, encodeBhttpResponse(res), new Uint8Array(0));
      const out = new Uint8Array(responseNonce.length + sealed.byteLength);
      out.set(responseNonce, 0);
      out.set(new Uint8Array(sealed), responseNonce.length);
      return out;
    };

    return { request, encapsulateResponse };
  }
}
