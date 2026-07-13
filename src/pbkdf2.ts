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
 * Expose the PBKDF2 iteration chain for the FIRST output block so the UI can
 * SHOW the mechanism RFC 8018 §5.2 defines, instead of merely asserting it:
 *
 *   U_1 = PRF(password, salt ‖ INT(1))
 *   U_j = PRF(password, U_{j-1})            for j = 2 … c
 *   T_1 = U_1 XOR U_2 XOR … XOR U_c
 *
 * This is the real algorithm (HMAC-SHA-256 as the PRF, computed with WebCrypto),
 * not a stand-in — the same math WebCrypto runs internally, surfaced one link at
 * a time. To keep the visual responsive we walk the chain for the first block
 * only and cap how many U_j we retain for display (the running XOR still folds
 * in every iteration up to `iterations`, so the accumulator is exact).
 */
export interface Pbkdf2ChainStep {
  /** 1-based iteration index j. */
  j: number;
  /** U_j = HMAC(password, U_{j-1}) — the new link, hex. */
  uHex: string;
  /** Running T_1 = U_1 ⊕ … ⊕ U_j after folding this link in, hex. */
  accHex: string;
}

export interface Pbkdf2ChainResult {
  steps: Pbkdf2ChainStep[];
  /** True if `iterations` exceeded the retained-step cap (chain elided in UI). */
  truncated: boolean;
  iterations: number;
  /** Final T_1 after folding ALL `iterations` links, hex (spec-exact). */
  finalHex: string;
  timeMs: number;
}

function xorInto(acc: Uint8Array, u: Uint8Array): void {
  for (let i = 0; i < acc.length; i++) acc[i] ^= u[i];
}

/**
 * Compute the PBKDF2 iteration chain for output block 1, retaining up to
 * `maxSteps` links for display. HMAC-SHA-256 PRF, 32-byte blocks.
 */
export async function pbkdf2Chain(
  password: string,
  salt: string,
  iterations: number,
  maxSteps = 24,
): Promise<Pbkdf2ChainResult> {
  const t0 = performance.now();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(password), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const hmac = async (msg: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await crypto.subtle.sign('HMAC', key, msg as BufferSource));

  // U_1 = HMAC(password, salt ‖ INT(1))
  const saltBytes = encoder.encode(salt);
  const first = new Uint8Array(saltBytes.length + 4);
  first.set(saltBytes, 0);
  first.set([0, 0, 0, 1], saltBytes.length); // INT(1), big-endian
  let u = await hmac(first);
  const acc = new Uint8Array(u); // T_1 starts as U_1
  const steps: Pbkdf2ChainStep[] = [{ j: 1, uHex: toHex(u), accHex: toHex(acc) }];

  const count = Math.max(iterations, 1);
  for (let j = 2; j <= count; j++) {
    u = await hmac(u);
    xorInto(acc, u);
    if (steps.length < maxSteps) {
      steps.push({ j, uHex: toHex(u), accHex: toHex(acc) });
    }
  }
  return {
    steps,
    truncated: count > maxSteps,
    iterations: count,
    finalHex: toHex(acc),
    timeMs: performance.now() - t0,
  };
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
