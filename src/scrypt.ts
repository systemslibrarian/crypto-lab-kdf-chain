/**
 * scrypt — Memory-hard password stretching per RFC 7914
 * Uses @noble/hashes scrypt implementation
 */
import { scryptAsync as nobleScrypt } from '@noble/hashes/scrypt.js';

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

const encoder = new TextEncoder();

export interface ScryptResult {
  hex: string;
  timeMs: number;
  N: number;
  r: number;
  p: number;
  memoryEstimateMB: number;
}

/**
 * Derive key using scrypt.
 * Memory estimate: 128 × N × r bytes (per RFC 7914 §2)
 */
export async function deriveScrypt(
  password: string,
  salt: string,
  N: number,
  r: number,
  p: number,
  dkLen: number,
): Promise<ScryptResult> {
  const t0 = performance.now();
  const dk = await nobleScrypt(encoder.encode(password), encoder.encode(salt), { N, r, p, dkLen });
  const timeMs = performance.now() - t0;
  const memoryEstimateMB = (128 * N * r) / (1024 * 1024);
  return { hex: toHex(dk), timeMs, N, r, p, memoryEstimateMB };
}

/**
 * Benchmark scrypt at multiple N values.
 */
export async function scryptBenchmark(
  password: string, salt: string, nValues: number[], r: number, p: number, dkLen: number,
): Promise<ScryptResult[]> {
  const results: ScryptResult[] = [];
  for (const N of nValues) {
    results.push(await deriveScrypt(password, salt, N, r, p, dkLen));
  }
  return results;
}
