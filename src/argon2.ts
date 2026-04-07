/**
 * Argon2id — Modern memory-hard password hashing per RFC 9106
 * Uses @noble/hashes argon2id implementation
 */
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

const encoder = new TextEncoder();

export interface Argon2Result {
  hex: string;
  timeMs: number;
  t: number;
  m: number;
  p: number;
  dkLen: number;
}

/**
 * Derive key using Argon2id.
 * Parameters per RFC 9106: t = time cost, m = memory cost (KB), p = parallelism.
 */
export function deriveArgon2id(
  password: string,
  salt: string,
  t: number,
  m: number,
  p: number,
  dkLen: number,
): Argon2Result {
  const saltBytes = encoder.encode(salt);
  // RFC 9106 requires salt >= 8 bytes; pad if needed
  const safeSalt = saltBytes.length >= 8
    ? saltBytes
    : new Uint8Array(8).map((_, i) => saltBytes[i % saltBytes.length] || 0);
  const t0 = performance.now();
  const dk = nobleArgon2id(encoder.encode(password), safeSalt, { t, m, p, dkLen });
  const timeMs = performance.now() - t0;
  return { hex: toHex(dk), timeMs, t, m, p, dkLen };
}
