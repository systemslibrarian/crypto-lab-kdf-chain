# crypto-lab-kdf-chain

HKDF · PBKDF2 · scrypt · Argon2id · HMAC-SHA-256

Live demo: https://systemslibrarian.github.io/crypto-lab-kdf-chain/

## What It Is

crypto-lab-kdf-chain is an interactive browser demo of four key derivation functions: HKDF (RFC 5869), PBKDF2 (RFC 8018), scrypt (RFC 7914), and Argon2id (RFC 9106). It shows what security problem each KDF solves, how their parameters affect cost, and why choosing the wrong one leads to real-world compromise. All four operate under a symmetric security model — they transform shared secrets or passwords into derived key material using HMAC-SHA-256 as the underlying pseudorandom function. The demo is entirely client-side: HKDF and PBKDF2 use the WebCrypto API; scrypt and Argon2id use @noble/hashes.

## When to Use It

- **You need to teach or learn what KDFs actually do** — the demo derives real keys with real timing so you can see how iteration count, memory cost, and salt affect output and performance.
- **You are choosing between HKDF, PBKDF2, scrypt, and Argon2id** — the built-in decision tree walks through input entropy, multi-key derivation, and FIPS constraints to recommend the right KDF.
- **You want to demonstrate why salt matters** — the salt panel shows identical passwords producing identical output without salt and independent output with salt, making rainbow-table risk concrete.
- **You need to benchmark KDF cost in a specific browser** — PBKDF2 iteration benchmarks and scrypt N-value comparisons use real `performance.now()` timing on whatever hardware you run.
- **Do not use this demo for production key derivation** — it runs in a browser with no secure memory management, no constant-time guarantees, and user-supplied parameters that may be too weak.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-kdf-chain/](https://systemslibrarian.github.io/crypto-lab-kdf-chain/)

The demo has six interactive panels. You can derive HKDF keys by entering IKM, salt, info string, and output length; derive PBKDF2 keys with configurable iterations and compare SHA-256 vs SHA-512 timing; tune scrypt N/r/p parameters and compare memory cost at different N values; derive Argon2id keys with adjustable time cost, memory cost, and parallelism; run a decision tree that recommends a KDF based on your constraints; and run salt and context-binding demonstrations that show rainbow-table vulnerability, salt protection, HKDF context binding, and domain separation.

## What Can Go Wrong

- **Using HKDF for passwords** — HKDF assumes high-entropy input key material. Fed a low-entropy password, it provides no stretching, and an attacker can brute-force the output at near-hash speed.
- **Low PBKDF2 iteration count** — PBKDF2 is embarrassingly parallel; GPUs can test millions of passwords per second. Below 600,000 iterations (OWASP minimum for PBKDF2-HMAC-SHA-256), offline attacks become trivially cheap.
- **Omitting salt** — any KDF without a unique random salt maps identical passwords to identical outputs, enabling precomputed rainbow-table and multi-target attacks across an entire credential database.
- **Under-provisioning scrypt memory (low N)** — scrypt's security depends on requiring large sequential memory reads. If N is too low, the memory-hardness guarantee disappears and GPU/ASIC attacks become practical.
- **Reusing HKDF info strings across contexts** — HKDF derives cryptographically independent keys only when the info string differs. Reusing the same info for encryption and MAC keys destroys domain separation and can enable key-reuse attacks.

## Real-World Usage

- **TLS 1.3** — uses HKDF-Expand and HKDF-Extract (RFC 5869) as the key schedule to derive handshake and application traffic keys from the shared secret.
- **Signal Protocol** — uses HKDF with distinct info strings to derive root keys, chain keys, and message keys in the Double Ratchet, providing forward secrecy and domain separation.
- **WireGuard** — uses HKDF in its Noise IK handshake to extract and expand chaining keys and transport data keys from each Diffie-Hellman output.
- **1Password / Bitwarden** — use PBKDF2-HMAC-SHA-256 (or Argon2id in newer configurations) to stretch the user's master password into an encryption key for the vault.
- **Linux libsodium (pwhash)** — uses Argon2id as the default password hashing algorithm, with tunable time and memory cost, to protect stored credentials against GPU and ASIC attacks.

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

## Related Demos

- https://systemslibrarian.github.io/crypto-lab/
- https://systemslibrarian.github.io/crypto-lab-shadow-vault/
- https://systemslibrarian.github.io/crypto-lab-ratchet-wire/
- https://systemslibrarian.github.io/crypto-lab-mac-race/
- https://github.com/systemslibrarian/crypto-compare

> *"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
