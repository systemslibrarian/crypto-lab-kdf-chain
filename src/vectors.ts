/**
 * vectors.ts — Known-answer tests against published RFC test vectors.
 *
 * Reproducing the standards' own vectors turns "trust me, this is HKDF"
 * into "here is the RFC's vector, recomputed in your browser."
 */
import { hkdfExtract, hkdfExpand } from './hkdf.ts';
import { pbkdf2Sha256 } from './pbkdf2.ts';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export interface VectorResult {
  name: string;
  ref: string;
  field: string;
  expected: string;
  got: string;
  pass: boolean;
}

export const vectors: { name: string; ref: string; run: () => Promise<VectorResult[]> }[] = [
  {
    name: 'HKDF-SHA-256 — basic',
    ref: 'RFC 5869 Test Case 1',
    run: async () => {
      const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      const salt = hexToBytes('000102030405060708090a0b0c');
      const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
      const expectedPrk = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
      const expectedOkm =
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';
      const { prk, prkHex } = await hkdfExtract(ikm, salt);
      const { okmHex } = await hkdfExpand(prk, info, 42);
      return [
        { name: 'HKDF', ref: 'RFC 5869 TC1', field: 'PRK', expected: expectedPrk, got: prkHex, pass: prkHex === expectedPrk },
        { name: 'HKDF', ref: 'RFC 5869 TC1', field: 'OKM (42 B)', expected: expectedOkm, got: okmHex, pass: okmHex === expectedOkm },
      ];
    },
  },
  {
    name: 'HKDF-SHA-256 — empty salt & info',
    ref: 'RFC 5869 Test Case 3',
    run: async () => {
      const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      const expectedPrk = '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04';
      const expectedOkm =
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8';
      const { prk, prkHex } = await hkdfExtract(ikm, new Uint8Array(0));
      const { okmHex } = await hkdfExpand(prk, new Uint8Array(0), 42);
      return [
        { name: 'HKDF', ref: 'RFC 5869 TC3', field: 'PRK', expected: expectedPrk, got: prkHex, pass: prkHex === expectedPrk },
        { name: 'HKDF', ref: 'RFC 5869 TC3', field: 'OKM (42 B)', expected: expectedOkm, got: okmHex, pass: okmHex === expectedOkm },
      ];
    },
  },
  {
    name: 'PBKDF2-HMAC-SHA-256',
    ref: 'RFC 7914 §10 (c=1)',
    run: async () => {
      const expected =
        '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
        '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783';
      const { hex } = await pbkdf2Sha256('passwd', 'salt', 1, 64);
      return [
        { name: 'PBKDF2', ref: 'RFC 7914 §10', field: 'DK (64 B, c=1)', expected, got: hex, pass: hex === expected },
      ];
    },
  },
];
