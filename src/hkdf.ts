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
    'raw', rawSalt as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const prkBuf = await crypto.subtle.sign('HMAC', saltKey, ikm as BufferSource);
  const prk = new Uint8Array(prkBuf);
  return { prk, prkHex: toHex(prk) };
}

/** The one-octet block counter in RFC 5869 §2.3 caps N at 255. */
const HASH_LEN = 32;
export const MAX_OKM_BYTES = 255 * HASH_LEN;

/** HKDF-Expand: OKM = T(1) || T(2) || ... per RFC 5869 §2.3 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<{ okm: Uint8Array; okmHex: string; blocks: string[] }> {
  // RFC 5869 §2.3: "L: length of output keying material in octets (<= 255*HashLen)".
  // The limit is not stylistic — the counter appended to each HMAC input is a
  // SINGLE OCTET, so block 256 would be computed with counter 0 and collide
  // with block 1's input shape. Without this guard the loop below wrote `i` into
  // a Uint8Array, which truncates mod 256 silently: asking for 9000 bytes
  // returned 9000 bytes of confidently wrong, non-conformant OKM with no error.
  // A demo whose own panel recomputes the RFC's test vectors must not ship a
  // derivation that leaves the RFC's stated domain.
  if (!Number.isInteger(length) || length < 1 || length > MAX_OKM_BYTES) {
    throw new RangeError(
      `HKDF-Expand: L must be an integer in 1..${MAX_OKM_BYTES} (255 x HashLen, RFC 5869 §2.3); got ${length}`,
    );
  }
  const n = Math.ceil(length / HASH_LEN);
  const blocks: string[] = [];
  let prev = new Uint8Array(0);
  const okm = new Uint8Array(n * HASH_LEN);
  const key = await crypto.subtle.importKey(
    'raw', prk as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = i;
    const tBuf = await crypto.subtle.sign('HMAC', key, input);
    prev = new Uint8Array(tBuf);
    okm.set(prev, (i - 1) * HASH_LEN);
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
