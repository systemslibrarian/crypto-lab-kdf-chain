/**
 * attack.ts — Attacker-cost projection for password KDFs
 *
 * Converts a defender's per-guess cost into an attacker's offline
 * crack time. The whole point of a password KDF is attacker cost, so
 * these estimates turn "X milliseconds for me" into "Y years for them."
 *
 * The model is deliberately simple and grounded in published hardware
 * specs (a single high-end consumer GPU, RTX 4090 class). It is an
 * order-of-magnitude teaching estimate, not a security proof.
 */

/** Raw SHA-256 throughput of one high-end GPU, hashes/sec (~22 GH/s). */
const GPU_SHA256_HPS = 22e9;
/** Raw SHA-512 throughput of one high-end GPU, hashes/sec (~7 GH/s). */
const GPU_SHA512_HPS = 7e9;
/** Memory bandwidth of one high-end GPU, bytes/sec (~1 TB/s). */
const GPU_MEM_BW = 1e12;

export interface AttackEstimate {
  /** Guesses/sec one high-end GPU can sustain against this KDF + params. */
  guessesPerSec: number;
  /** Plain-language formula shown to the learner. */
  formula: string;
  /** Whether the bottleneck is cheap compute (parallel) or memory bandwidth. */
  bottleneck: 'compute (GPU-parallel)' | 'memory bandwidth';
}

/**
 * PBKDF2 is compute-bound: an attacker needs ~2 hash compressions per
 * iteration. SHA cores are tiny, so GPUs run thousands in parallel and
 * scale almost for free — this is why PBKDF2 is "embarrassingly parallel."
 */
export function pbkdf2Attack(iterations: number, hash: 'SHA-256' | 'SHA-512'): AttackEstimate {
  const raw = hash === 'SHA-512' ? GPU_SHA512_HPS : GPU_SHA256_HPS;
  const guessesPerSec = raw / (2 * Math.max(iterations, 1));
  return {
    guessesPerSec,
    formula: `${(raw / 1e9).toFixed(0)} GH/s raw ${hash} ÷ (2 × ${iterations.toLocaleString()} iterations)`,
    bottleneck: 'compute (GPU-parallel)',
  };
}

/**
 * scrypt is memory-bound: each guess streams ~2 × (128·N·r) bytes through
 * memory, so the attacker is capped by GPU memory bandwidth, not core count.
 * You cannot cheaply add bandwidth — this is why memory hardness resists
 * GPUs and ASICs where PBKDF2 collapses.
 */
export function scryptAttack(N: number, r: number): AttackEstimate {
  const bytesPerGuess = 2 * 128 * r * N;
  const guessesPerSec = GPU_MEM_BW / bytesPerGuess;
  const memMB = bytesPerGuess / 2 / (1024 * 1024);
  return {
    guessesPerSec,
    formula: `1 TB/s GPU memory bandwidth ÷ (2 × ${memMB.toFixed(1)} MB touched per guess)`,
    bottleneck: 'memory bandwidth',
  };
}

/**
 * Argon2id is memory-bound: each guess fills m KB of memory t times, so the
 * attacker is again capped by memory bandwidth. Raising m or t directly
 * raises attacker cost with no shortcut.
 */
export function argon2Attack(t: number, mKB: number): AttackEstimate {
  const bytesPerGuess = t * mKB * 1024;
  const guessesPerSec = GPU_MEM_BW / bytesPerGuess;
  return {
    guessesPerSec,
    formula: `1 TB/s GPU memory bandwidth ÷ (${t} pass × ${(mKB / 1024).toFixed(1)} MB per guess)`,
    bottleneck: 'memory bandwidth',
  };
}

/** Representative target passwords. keyspace = size of the search space. */
export interface Target {
  label: string;
  keyspace: number;
  bits: number;
}

export const TARGETS: Target[] = [
  { label: 'Reused/leaked password (~10⁹ wordlist)', keyspace: 1e9, bits: Math.log2(1e9) },
  { label: 'Weak — 8 lowercase letters (26⁸)', keyspace: 26 ** 8, bits: 8 * Math.log2(26) },
  { label: 'Common — 8 chars a–z A–Z 0–9 (62⁸)', keyspace: 62 ** 8, bits: 8 * Math.log2(62) },
  { label: 'Strong — 12 chars full keyboard (95¹²)', keyspace: 95 ** 12, bits: 12 * Math.log2(95) },
];

/**
 * How much cheaper specialized hardware (ASIC) makes the attack.
 * Compute-bound KDFs (PBKDF2): SHA cores are tiny and cheap, so ASICs add
 * thousands of them per chip — the attack collapses. Memory-bound KDFs
 * (scrypt, Argon2id): the cost IS memory bandwidth, which ASICs cannot make
 * cheap, so they barely move. This asymmetry is the whole case for memory hardness.
 */
export function asicFactor(bottleneck: AttackEstimate['bottleneck']): number {
  return bottleneck === 'memory bandwidth' ? 5 : 5000;
}

/** Average guesses to crack = half the keyspace. */
export function crackSeconds(keyspace: number, guessesPerSec: number): number {
  return keyspace / 2 / guessesPerSec;
}

/** Format a duration in seconds into a human, order-of-magnitude string. */
export function humanDuration(seconds: number): string {
  if (!isFinite(seconds)) return '∞';
  if (seconds < 1) return '< 1 second';
  const units: [number, string][] = [
    [60, 'second'],
    [60, 'minute'],
    [24, 'hour'],
    [365.25, 'day'],
    [100, 'year'],
    [10, 'century'],
    [Infinity, 'millennium'],
  ];
  let val = seconds;
  let name = 'second';
  for (const [factor, label] of units) {
    name = label;
    if (val < factor) break;
    val /= factor;
  }
  if (name === 'millennium') {
    if (val >= 1e6) return `${(val / 1e3).toExponential(1)} million millennia`;
    return `${Math.round(val).toLocaleString()} millennia`;
  }
  const rounded = val >= 10 ? Math.round(val) : Math.round(val * 10) / 10;
  const plural = rounded === 1 ? name : name === 'century' ? 'centuries' : `${name}s`;
  return `${rounded.toLocaleString()} ${plural}`;
}

/** Crack-time summary for a given attack estimate and target. */
export function crackSummary(est: AttackEstimate, target: Target): string {
  const secsOneGpu = crackSeconds(target.keyspace, est.guessesPerSec);
  const secsFarm = secsOneGpu / 1000;
  const factor = asicFactor(est.bottleneck);
  const secsAsic = secsOneGpu / factor;
  const gps = est.guessesPerSec < 1
    ? est.guessesPerSec.toExponential(1)
    : Math.round(est.guessesPerSec).toLocaleString();
  return (
    `≈ ${gps} guesses/sec per GPU (bottleneck: ${est.bottleneck}).\n` +
    `Crack "${target.label}":\n` +
    `  • one GPU:        ${humanDuration(secsOneGpu)}\n` +
    `  • 1,000-GPU farm: ${humanDuration(secsFarm)}\n` +
    `  • ASIC (~${factor.toLocaleString()}× faster, ${est.bottleneck === 'memory bandwidth' ? 'memory resists ASICs' : 'cheap SHA cores'}): ${humanDuration(secsAsic)}`
  );
}
