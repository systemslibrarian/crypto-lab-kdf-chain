/**
 * Salt and Context Binding demos — Panel 6
 */
import { pbkdf2Sha256 } from './pbkdf2';
import { hkdf } from './hkdf';

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Show that same password + no salt = same output (rainbow table vulnerable) */
export async function demoNoSalt(password: string): Promise<{ hex1: string; hex2: string; match: boolean }> {
  const r1 = await pbkdf2Sha256(password, '', 100_000, 32);
  const r2 = await pbkdf2Sha256(password, '', 100_000, 32);
  return { hex1: r1.hex, hex2: r2.hex, match: r1.hex === r2.hex };
}

/** Show that same password + random salt = different output each time */
export async function demoWithSalt(password: string): Promise<{ salt1: string; salt2: string; hex1: string; hex2: string; match: boolean }> {
  const salt1 = randomHex(16);
  const salt2 = randomHex(16);
  const r1 = await pbkdf2Sha256(password, salt1, 100_000, 32);
  const r2 = await pbkdf2Sha256(password, salt2, 100_000, 32);
  return { salt1, salt2, hex1: r1.hex, hex2: r2.hex, match: r1.hex === r2.hex };
}

/** HKDF context binding: same root key, different info strings → different keys */
export async function demoContextBinding(
  rootKey: string,
  salt: string,
): Promise<{ encKey: string; macKey: string; match: boolean }> {
  const enc = await hkdf(rootKey, salt, 'encryption key', 32);
  const mac = await hkdf(rootKey, salt, 'MAC key', 32);
  return { encKey: enc.okmHex, macKey: mac.okmHex, match: enc.okmHex === mac.okmHex };
}

/** Domain separation: different info strings produce fully independent keys */
export async function demoDomainSeparation(
  rootKey: string,
  salt: string,
): Promise<{ tls: string; file: string; match: boolean }> {
  const tls = await hkdf(rootKey, salt, 'TLS 1.3 derived', 32);
  const file = await hkdf(rootKey, salt, 'file encryption', 32);
  return { tls: tls.okmHex, file: file.okmHex, match: tls.okmHex === file.okmHex };
}
