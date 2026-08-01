# crypto-lab-kdf-chain

## What It Is

crypto-lab-kdf-chain is an interactive browser demo of four key derivation functions: HKDF (RFC 5869), PBKDF2 (RFC 8018), scrypt (RFC 7914), and Argon2id (RFC 9106). It shows what security problem each KDF solves, how their parameters affect cost, and why choosing the wrong one leads to real-world compromise. All four operate under a symmetric security model — they transform shared secrets or passwords into derived key material on top of a keyed hash. HKDF and PBKDF2 use HMAC-SHA-256 directly; scrypt wraps PBKDF2-HMAC-SHA-256 around a Salsa20/8-based mixing core; Argon2id is built on BLAKE2b (RFC 9106 §1), not HMAC-SHA-256. The demo is entirely client-side: HKDF and PBKDF2 use the WebCrypto API; scrypt and Argon2id use @noble/hashes.

## When to Use It

- **You need to teach or learn what KDFs actually do** — the demo derives real keys with real timing so you can see how iteration count, memory cost, and salt affect output and performance.
- **You are choosing between HKDF, PBKDF2, scrypt, and Argon2id** — the built-in decision tree walks through input entropy, multi-key derivation, and FIPS constraints to recommend the right KDF.
- **You want to demonstrate why salt matters** — the salt panel shows identical passwords producing identical output without salt and independent output with salt, making rainbow-table risk concrete.
- **You need to benchmark KDF cost in a specific browser** — PBKDF2 iteration benchmarks and scrypt N-value comparisons use real `performance.now()` timing on whatever hardware you run.
- Do not use this demo for production key derivation — it runs in a browser with no secure memory management, no constant-time guarantees, and user-supplied parameters that may be too weak.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-kdf-chain](https://systemslibrarian.github.io/crypto-lab-kdf-chain/)**

A **guided path** at the top walks newcomers through the demo in six ordered steps; experienced users can jump straight to any panel.

The demo has ten interactive panels. You can derive HKDF keys by entering IKM (the secret you start with), salt, info string, and output length — and watch a two-phase **extract→expand diagram** animate your real bytes flowing salt+IKM into an HMAC box that emits the PRK (a condensed random seed), then the PRK feeding a loop that concatenates T(i-1)‖info‖counter to build T(1), T(2), … so the mechanism is visible, not just the hex; derive PBKDF2 keys with configurable iterations and compare SHA-256 vs SHA-512 timing, with a live **iteration-chain visual** (U₁ → U₂ → … with a running XOR accumulator and a slider) that shows the U₁…Uₙ-XORed mechanism the standard defines — verified byte-for-byte against WebCrypto's own PBKDF2; tune scrypt N/r/p parameters and compare memory cost at different N values; derive Argon2id keys with adjustable time cost, memory cost, and parallelism; see a **memory-hardness visual** whose grid scales to the N (scrypt) / m (Argon2id) you choose and shows 48 GPU cores stalling on the single memory bus while the block fills; run the **KDF chain** (Argon2id → HKDF-Expand fan-out) that turns one password into multiple domain-separated keys; run a **cost comparison** that pushes one password through every KDF and renders both your derivation time and the attacker's projected offline crack time; run a decision tree that recommends a KDF based on your constraints; run salt and context-binding demonstrations that show rainbow-table vulnerability, salt protection, HKDF context binding, and domain separation; and run **RFC known-answer tests** that recompute published RFC 5869 and RFC 7914 vectors in your browser and check them byte-for-byte.

Every password-KDF panel also shows an **attacker-cost estimate**: pick a target password — from a reused/leaked-list password up to a strong random one — and see how long an offline search would take on one GPU, a 1,000-GPU farm, and a specialized ASIC. An expandable **"assumptions" note sits inline next to the numbers** (RTX 4090-class hardware, keyspace ÷ 2, ASIC ~5000× for compute-bound / ~5× for memory-bound), so the model's inputs are visible where the numbers are read. The estimates are grounded in published hardware specs (raw SHA-256 throughput and GPU memory bandwidth) and model why compute-bound PBKDF2 collapses against ASICs while memory-bound scrypt/Argon2id barely move. These are order-of-magnitude teaching estimates, not security proofs.

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

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-kdf-chain
cd crypto-lab-kdf-chain
npm install
npm run dev
```

## Related Demos

- [crypto-lab-kdf-arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — sibling KDF benchmark that times HKDF/PBKDF2/scrypt/Argon2id side by side.
- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — Argon2id plus ChaCha20-Poly1305 file encryption.
- [crypto-lab-ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/) — Double Ratchet that derives message keys with HKDF.
- [crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — HMAC and other MACs, the PRF underneath these KDFs.
- [crypto-lab-bcrypt-forge](https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/) — bcrypt cost-factor tuning, the other major password-hashing family.

## Building and Testing

For a production build:

```bash
npm run build
```

To run the test suite (RFC known-answer vectors, chain key-independence, and attacker-cost math) — requires Node ≥ 22.18 for native TypeScript:

```bash
npm test
```

For GitHub Pages deployment:

```bash
npm run deploy
```

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
