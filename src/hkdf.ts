/**
 * HKDF — Extract and Expand per RFC 5869
 * Uses WebCrypto HMAC-SHA-256
 */

const encoder = new TextEncoder();

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** HKDF-Extract: PRK = HMAC-SHA-256(salt, IKM) */
export async function hkdfExtract(
  ikm: Uint8Array,
  salt: Uint8Array,
): Promise<{ prk: Uint8Array; prkHex: string }> {
  const rawSalt = salt.length > 0 ? salt : new Uint8Array(32);
  const saltKey = await crypto.subtle.importKey(
    'raw', rawSalt.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const prkBuf = await crypto.subtle.sign('HMAC', saltKey, ikm.buffer as ArrayBuffer);
  const prk = new Uint8Array(prkBuf);
  return { prk, prkHex: toHex(prk) };
}

/** HKDF-Expand: OKM = T(1) || T(2) || ... per RFC 5869 §2.3 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<{ okm: Uint8Array; okmHex: string; blocks: string[] }> {
  const n = Math.ceil(length / 32);
  const blocks: string[] = [];
  let prev = new Uint8Array(0);
  const okm = new Uint8Array(n * 32);
  const key = await crypto.subtle.importKey(
    'raw', prk.buffer as ArrayBuffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = i;
    const tBuf = await crypto.subtle.sign('HMAC', key, input);
    prev = new Uint8Array(tBuf);
    okm.set(prev, (i - 1) * 32);
    blocks.push(toHex(prev));
  }
  const result = okm.slice(0, length);
  return { okm: result, okmHex: toHex(result), blocks };
}

/** Full HKDF: extract then expand */
export async function hkdf(
  ikm: string,
  salt: string,
  info: string,
  length: number,
): Promise<{
  prkHex: string;
  okmHex: string;
  blocks: string[];
  timeMs: number;
}> {
  const t0 = performance.now();
  const ikmBytes = encoder.encode(ikm);
  const saltBytes = encoder.encode(salt);
  const infoBytes = encoder.encode(info);
  const { prk, prkHex } = await hkdfExtract(ikmBytes, saltBytes);
  const { okmHex, blocks } = await hkdfExpand(prk, infoBytes, length);
  const timeMs = performance.now() - t0;
  return { prkHex, okmHex, blocks, timeMs };
}
