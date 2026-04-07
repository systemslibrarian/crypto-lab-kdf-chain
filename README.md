# crypto-lab-kdf-chain

HKDF · PBKDF2 · scrypt · Argon2id · HMAC-SHA-256

Live demo: https://systemslibrarian.github.io/crypto-lab-kdf-chain/

## Overview

crypto-lab-kdf-chain is a browser-based interactive demonstration of four key derivation functions: HKDF, PBKDF2, scrypt, and Argon2id. It is built to show how each construction works, what security problem it solves, where it fails, and why choosing the wrong KDF still causes real-world compromise.

The demo is entirely client-side. HKDF and PBKDF2 use the WebCrypto API. scrypt and Argon2id use @noble/hashes. Benchmarks are measured in the browser with real performance.now timings instead of static numbers.

## KDFs Covered

- HKDF per RFC 5869 for extract-and-expand key derivation from high-entropy input material.
- PBKDF2 per RFC 8018 for password stretching in legacy and FIPS-constrained environments.
- scrypt per RFC 7914 for memory-hard password stretching where Argon2id is unavailable.
- Argon2id per RFC 9106 as the modern default for new password storage systems.

## Primitives Used

- WebCrypto SubtleCrypto.deriveBits for PBKDF2.
- WebCrypto HMAC-SHA-256 for RFC 5869 HKDF extract and expand.
- @noble/hashes scrypt implementation for RFC 7914.
- @noble/hashes Argon2id implementation for RFC 9106.

## Running Locally

```bash
npm install
npm run dev
```

For a production build:

```bash
npm run build
```

For GitHub Pages deployment:

```bash
npm run deploy
```

## Security Notes

- Never use HKDF for passwords. HKDF assumes the input key material already has high entropy.
- Never use an unsalted KDF for password storage. Identical passwords must not produce identical stored outputs.
- Argon2id is the correct default for new password storage systems.
- PBKDF2 remains acceptable for legacy and FIPS-constrained systems, but OWASP recommends at least 600,000 iterations for PBKDF2-HMAC-SHA-256.

## Accessibility

The interface is built for WCAG 2.1 AA conformance with keyboard navigation, visible focus states, descriptive labels, live-region status updates, reduced-motion support, and screen-reader-friendly structure throughout the demo.

## Why This Matters

Billions of leaked passwords are still cracked because developers chose the wrong KDF, chose too few iterations, or stored unsalted hashes. In 2026, low-iteration PBKDF2 and unsalted legacy digests still show up in breach disclosures. The difference between HKDF, PBKDF2, scrypt, and Argon2id is not academic; it determines how expensive an attacker’s offline search becomes.

## Related Demos

- https://systemslibrarian.github.io/crypto-lab/
- https://systemslibrarian.github.io/crypto-lab-shadow-vault/
- https://systemslibrarian.github.io/crypto-lab-ratchet-wire/
- https://systemslibrarian.github.io/crypto-lab-mac-race/
- https://github.com/systemslibrarian/crypto-compare

So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31