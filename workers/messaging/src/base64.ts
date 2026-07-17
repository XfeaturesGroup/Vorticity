// Workers isolates have no Node Buffer; btoa/atob only handle Latin1 strings, so binary bytes
// must be mapped through String.fromCharCode/charCodeAt one byte at a time. Shared by any DO that
// needs to put opaque ciphertext into a JSON wire format (QueueDO, ConvLogDO, ...).

export function bufToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64ToBuf(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
