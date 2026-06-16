/**
 * kdf.test.ts — runs with `node --test` (native TypeScript, no extra deps).
 *
 * Covers the parts most likely to break silently: the RFC known-answer
 * vectors, the chain's key independence, and the attacker-cost math.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { vectors } from '../src/vectors.ts';
import { hkdf } from '../src/hkdf.ts';
import { deriveChain } from '../src/chain.ts';
import { decide } from '../src/decision.ts';
import { demoNoSalt, demoWithSalt } from '../src/salt.ts';
import {
  pbkdf2Attack, scryptAttack, argon2Attack, asicFactor,
  crackSeconds, humanDuration, crackSummary, TARGETS,
} from '../src/attack.ts';

test('every RFC known-answer vector reproduces byte-for-byte', async () => {
  for (const group of vectors) {
    for (const r of await group.run()) {
      assert.ok(r.pass, `${group.name} — ${r.field}\n  expected ${r.expected}\n  got      ${r.got}`);
    }
  }
});

test('HKDF is deterministic and context-bound', async () => {
  const a = await hkdf('ikm', 'salt', 'info-A', 32);
  const a2 = await hkdf('ikm', 'salt', 'info-A', 32);
  const b = await hkdf('ikm', 'salt', 'info-B', 32);
  assert.equal(a.okmHex, a2.okmHex, 'same inputs → same output');
  assert.notEqual(a.okmHex, b.okmHex, 'different info → different output');
  assert.equal(a.okmHex.length, 64, '32 bytes → 64 hex chars');
});

test('the chain fans one password into independent, domain-separated keys', async () => {
  const infos = ['encryption key', 'MAC key', 'vault storage key'];
  const fast = { t: 1, m: 1024, p: 1 };
  const r = await deriveChain('pw', 'salt-1234', infos, fast);
  assert.equal(r.links.length, 3);
  const keys = r.links.map(l => l.keyHex);
  assert.equal(new Set(keys).size, 3, 'all derived keys are distinct');
  const again = await deriveChain('pw', 'salt-1234', infos, fast);
  assert.deepEqual(again.links.map(l => l.keyHex), keys, 'chain is deterministic');
});

test('salt demos behave as taught', async () => {
  assert.equal((await demoNoSalt('password123')).match, true, 'no salt → identical output');
  assert.equal((await demoWithSalt('password123')).match, false, 'random salt → different output');
});

test('decision tree routes each branch correctly', () => {
  assert.equal(decide(true, false, false).kdf, 'HKDF', 'high-entropy → HKDF');
  assert.equal(decide(false, false, true).kdf, 'PBKDF2', 'legacy/FIPS → PBKDF2');
  assert.equal(decide(false, false, false).kdf, 'Argon2id', 'password default → Argon2id');
  assert.equal(decide(false, true, false).kdf, 'Argon2id', 'multi-key password → Argon2id');
});

test('humanDuration formats across magnitudes without artifacts', () => {
  assert.equal(humanDuration(0.5), '< 1 second');
  assert.equal(humanDuration(1), '1 second');
  assert.equal(humanDuration(3600), '1 hour');
  assert.equal(humanDuration(86400), '1 day');
  for (const s of [1, 90, 3600, 9e4, 1e9, 1e13, 1e25]) {
    const out = humanDuration(s);
    assert.doesNotMatch(out, /century…|NaN|undefined/, `clean output for ${s}: ${out}`);
  }
});

test('attacker cost: more work for the defender means more work for the attacker', () => {
  assert.ok(pbkdf2Attack(100_000, 'SHA-256').guessesPerSec > pbkdf2Attack(600_000, 'SHA-256').guessesPerSec);
  assert.ok(scryptAttack(2 ** 14, 8).guessesPerSec > scryptAttack(2 ** 17, 8).guessesPerSec);
  assert.ok(argon2Attack(2, 19456).guessesPerSec > argon2Attack(2, 65536).guessesPerSec);
});

test('memory-hard KDFs resist ASICs far better than compute-bound ones', () => {
  assert.equal(asicFactor(pbkdf2Attack(600_000, 'SHA-256').bottleneck), 5000);
  assert.equal(asicFactor(argon2Attack(2, 19456).bottleneck), 5);
  assert.equal(asicFactor(scryptAttack(2 ** 14, 8).bottleneck), 5);
});

test('crackSeconds and targets scale as expected', () => {
  const est = pbkdf2Attack(600_000, 'SHA-256');
  assert.ok(crackSeconds(TARGETS[3].keyspace, est.guessesPerSec) > crackSeconds(TARGETS[0].keyspace, est.guessesPerSec));
  for (let i = 1; i < TARGETS.length; i++) {
    assert.ok(TARGETS[i].keyspace > TARGETS[i - 1].keyspace, 'targets ordered weakest → strongest');
  }
  const summary = crackSummary(est, TARGETS[0]);
  assert.match(summary, /one GPU:/);
  assert.match(summary, /1,000-GPU farm:/);
  assert.match(summary, /ASIC/);
});
