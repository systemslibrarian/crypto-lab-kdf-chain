/**
 * chain.ts — The KDF chain this project is named for.
 *
 * The real-world pattern (TLS 1.3, Signal, password vaults):
 *   password --Argon2id (slow, memory-hard)--> root key
 *   root key --HKDF-Expand info="enc"--> encryption key
 *   root key --HKDF-Expand info="mac"--> MAC key
 *   root key --HKDF-Expand info="vault"--> storage key
 *
 * Argon2id does the expensive stretching once; HKDF-Expand then fans the
 * single root key out into one key per distinct info label — cheaply.
 * Separation comes from the labels, not from the number of branches: two
 * branches with the same root, the same output length and byte-identical
 * info get byte-identical keys (RFC 5869 §2.3 — HKDF-Expand is a function
 * of PRK, info and L only).
 */
import { deriveArgon2id } from './argon2.ts';
import { hkdfExpand } from './hkdf.ts';

const encoder = new TextEncoder();

export interface ChainLink {
  info: string;
  keyHex: string;
}

/**
 * Group branch indices whose info labels encode to identical bytes. With the
 * same root and output length, HKDF-Expand is then given identical inputs, so
 * those branches receive the same key. Returns one array of indices per
 * repeated label (only groups of two or more); empty when every label differs.
 */
export function duplicateInfoGroups(infos: string[]): number[][] {
  const byBytes = new Map<string, number[]>();
  infos.forEach((info, i) => {
    const k = Array.from(encoder.encode(info)).join(',');
    const g = byBytes.get(k);
    if (g) g.push(i); else byBytes.set(k, [i]);
  });
  return [...byBytes.values()].filter(g => g.length > 1);
}

export interface ChainResult {
  rootHex: string;
  argonTimeMs: number;
  links: ChainLink[];
  totalTimeMs: number;
}

/**
 * Run the full chain: stretch the password with Argon2id, then expand the
 * resulting root key into one derived key per `info` label.
 */
export async function deriveChain(
  password: string,
  salt: string,
  infos: string[],
  argon: { t: number; m: number; p: number } = { t: 2, m: 19456, p: 1 },
): Promise<ChainResult> {
  const t0 = performance.now();
  const root = await deriveArgon2id(password, salt, argon.t, argon.m, argon.p, 32);
  const rootBytes = new Uint8Array(root.hex.match(/../g)!.map(h => parseInt(h, 16)));

  const links: ChainLink[] = [];
  for (const info of infos) {
    const { okmHex } = await hkdfExpand(rootBytes, encoder.encode(info), 32);
    links.push({ info, keyHex: okmHex });
  }
  return {
    rootHex: root.hex,
    argonTimeMs: root.timeMs,
    links,
    totalTimeMs: performance.now() - t0,
  };
}
