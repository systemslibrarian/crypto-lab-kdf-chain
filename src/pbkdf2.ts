/**
 * PBKDF2 — Password-Based Key Derivation Function 2 per RFC 8018
 * Uses WebCrypto SubtleCrypto.deriveBits — no reimplementation
 */

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const encoder = new TextEncoder();

export interface Pbkdf2Result {
  hex: string;
  timeMs: number;
  hash: string;
  iterations: number;
}

async function derivePbkdf2(
  password: string,
  salt: string,
  iterations: number,
  hash: 'SHA-256' | 'SHA-512',
  length: number,
): Promise<Pbkdf2Result> {
  const baseKey = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits'],
  );
  const t0 = performance.now();
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: encoder.encode(salt), iterations, hash },
    baseKey,
    length * 8,
  );
  const timeMs = performance.now() - t0;
  return { hex: toHex(bits), timeMs, hash, iterations };
}

/** PBKDF2-HMAC-SHA-256 */
export async function pbkdf2Sha256(
  password: string, salt: string, iterations: number, length: number,
): Promise<Pbkdf2Result> {
  return derivePbkdf2(password, salt, iterations, 'SHA-256', length);
}

/** PBKDF2-HMAC-SHA-512 */
export async function pbkdf2Sha512(
  password: string, salt: string, iterations: number, length: number,
): Promise<Pbkdf2Result> {
  return derivePbkdf2(password, salt, iterations, 'SHA-512', length);
}

/**
 * Run PBKDF2-SHA-256 at multiple iteration counts and return timings.
 */
export async function pbkdf2Benchmark(
  password: string, salt: string, counts: number[], length: number,
): Promise<Pbkdf2Result[]> {
  const results: Pbkdf2Result[] = [];
  for (const c of counts) {
    results.push(await derivePbkdf2(password, salt, c, 'SHA-256', length));
  }
  return results;
}
