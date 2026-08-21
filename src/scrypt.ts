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
 * Ceiling on a single derivation's scrypt working set, in bytes.
 *
 * The budget is 1 GiB of RFC 7914 §2 working set — 128·N·r — which is exactly
 * what this panel's top-of-range N=2^20 at r=8 asks for, and the largest
 * allocation a browser tab can be expected to survive. Anything past it still
 * throws, which is the "N too large for browser memory" branch the N-comparison
 * panel renders.
 *
 * It has to be stated rather than left to @noble/hashes' default because that
 * default (`1024**3 + 1024`) was sized with no margin for exactly this case,
 * and the accounting underneath it moved. Through 2.0.1 noble charged
 * `128·r·(N + p)`; from 2.2.0 it also counts its one shared `tmp` scratch
 * block, `128·r·(N + p + 1)`. The same N=2^20, r=8, p=1 derivation therefore
 * went 1024 bytes over a cap it used to land on precisely, and the 2^20 row of
 * the comparison started reporting itself as too large for the browser. Nothing
 * about the memory this demo asks for changed — only noble's tally of it — so
 * noble's own overhead — the p parallel blocks and the scratch block, which are
 * not part of the RFC's 128·N·r working set — is added on top of the budget
 * rather than taken out of it.
 */
function scryptMaxmem(r: number, p: number): number {
  return 1024 ** 3 + 128 * r * (p + 1);
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
  const dk = await nobleScrypt(encoder.encode(password), encoder.encode(salt), {
    N, r, p, dkLen, maxmem: scryptMaxmem(r, p),
  });
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
