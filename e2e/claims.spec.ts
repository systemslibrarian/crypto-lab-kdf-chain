import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate for the claims this page makes.
 *
 * The a11y spec proves the page is reachable; this one proves it is TRUE.
 * Every headline verdict, counter and teaching path is asserted against a
 * value the page itself computed — recomputed independently with WebCrypto in
 * the page, or checked for internal consistency (blocks summing to the output,
 * every chain link checked against its predecessor, bar widths matching their
 * own milliseconds) — rather than compared to a hardcoded string.
 */

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

const HEX = /^[0-9a-f]+$/;

/** Text of a locator, trimmed. */
async function txt(page: Page, sel: string): Promise<string> {
  return ((await page.locator(sel).first().textContent()) ?? '').trim();
}

/** Strip the trailing ellipsis the UI adds to truncated hex chips. */
function unElide(s: string): string {
  return s.replace(/…\s*$/, '').trim();
}

/** Parse "12,345" / "1.2e-3" style guess counts out of the attacker readout. */
function parseGuesses(summary: string): number {
  const m = summary.match(/≈\s*([\d,.e+-]+)\s*guesses\/sec/);
  expect(m, `attacker readout should state guesses/sec:\n${summary}`).not.toBeNull();
  return Number(m![1].replace(/,/g, ''));
}

function xorHex(a: string, b: string): string {
  const n = Math.min(a.length, b.length);
  let out = '';
  for (let i = 0; i < n; i += 2) {
    const v = parseInt(a.slice(i, i + 2), 16) ^ parseInt(b.slice(i, i + 2), 16);
    out += v.toString(16).padStart(2, '0');
  }
  return out;
}

/** Click a panel button by its visible label. */
async function press(page: Page, panel: string, name: string): Promise<void> {
  await page.locator(`${panel} button.btn`).filter({ hasText: name }).first().click();
}

/* ------------------------------------------------------------------ */
/*  Panel 9 — RFC known-answer tests (the page's headline "proof")     */
/* ------------------------------------------------------------------ */

test('every RFC known-answer row passes, and each verdict matches its own bytes', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  await press(page, '#panel-vectors', 'Run Test Vectors');

  const rows = page.locator('#vectors-results .vector-row');
  await expect(rows).toHaveCount(5);
  await expect(page.locator('#vectors-results .vector-fail')).toHaveCount(0);

  const parsed = await rows.evaluateAll((els) =>
    els.map((e) => ({
      badge: (e.querySelector('.vector-badge')?.textContent ?? '').trim(),
      title: (e.querySelector('.vector-title')?.textContent ?? '').trim(),
      detail: (e.querySelector('.vector-detail')?.textContent ?? '').trim(),
    })),
  );

  for (const r of parsed) {
    const m = r.detail.match(/expected:\s*([0-9a-f]+)\s*got:\s*([0-9a-f]+)/);
    expect(m, `row "${r.title}" should show expected/got hex, saw:\n${r.detail}`).not.toBeNull();
    const [, expectedHex, gotHex] = m!;
    // The PASS badge must be the page's own comparison, not decoration.
    expect(gotHex, `${r.title}: recomputed bytes must equal the RFC's`).toBe(expectedHex);
    expect(r.badge).toContain('PASS');
  }

  // The five rows are the RFCs the README names.
  const titles = parsed.map((r) => r.title).join(' | ');
  expect(titles).toContain('RFC 5869 TC1');
  expect(titles).toContain('RFC 5869 TC3');
  expect(titles).toContain('RFC 7914 §10');

  // And the "got" column is a real derivation: recompute RFC 5869 TC1's PRK
  // with WebCrypto from the RFC's own inputs and match what the page printed.
  const tc1 = parsed.find((r) => r.title.includes('TC1') && r.title.includes('PRK'))!;
  const gotTc1 = tc1.detail.match(/got:\s*([0-9a-f]+)/)![1];
  const refTc1 = await page.evaluate(async () => {
    const unhex = (h: string) => new Uint8Array(h.match(/../g)!.map((p) => parseInt(p, 16)));
    const key = await crypto.subtle.importKey(
      'raw', unhex('000102030405060708090a0b0c'),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    const sig = await crypto.subtle.sign(
      'HMAC', key, unhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'));
    return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
  });
  expect(gotTc1).toBe(refTc1);
});

/* ------------------------------------------------------------------ */
/*  Panel 1 — HKDF                                                    */
/* ------------------------------------------------------------------ */

test('HKDF: OKM is exactly the T(i) blocks concatenated and truncated', async ({ page }) => {
  test.setTimeout(60_000);
  await page.goto('.');
  await page.locator('#hkdf-len').fill('80');
  await press(page, '#panel-hkdf', 'Derive Key');
  await expect(page.locator('#hkdf-okm')).not.toHaveText('—');

  const okm = await txt(page, '#hkdf-okm');
  const prk = await txt(page, '#hkdf-prk');
  const blocksText = await txt(page, '#hkdf-blocks');

  expect(prk).toMatch(HEX);
  expect(prk).toHaveLength(64); // HMAC-SHA-256 → 32 bytes
  expect(okm).toHaveLength(160); // 80 bytes requested

  // ceil(80/32) = 3 blocks, and the whole is the sum of its parts.
  const blocks = blocksText.split('\n').map((l) => l.replace(/^T\(\d+\):\s*/, '').trim());
  expect(blocks).toHaveLength(3);
  for (const b of blocks) expect(b).toMatch(HEX);
  expect(blocks.join('').slice(0, 160)).toBe(okm);

  // The diagram shows THIS derivation: same block count, PRK chip is a prefix
  // of the real PRK, and the first block is fed by the empty T(0).
  await expect(page.locator('#hkdf-d-blocks .hkdf-block')).toHaveCount(3);
  const diagPrk = unElide(await txt(page, '#hkdf-d-prk-v'));
  expect(prk.startsWith(diagPrk)).toBe(true);
  expect(await txt(page, '#hkdf-d-blocks .hkdf-block')).toContain('T(0) = empty');
  expect(await txt(page, '#hkdf-timing')).toMatch(/Derived in [\d.]+ ms/);

  // Independent WebCrypto recomputation of extract-then-expand — RFC 5869 §2
  // written out here, sharing no code with src/hkdf.ts.
  const ikm = await page.locator('#hkdf-ikm').inputValue();
  const salt = await page.locator('#hkdf-salt').inputValue();
  const info = await page.locator('#hkdf-info').inputValue();
  const ref = await page.evaluate(async ([ikmV, saltV, infoV]) => {
    const enc = new TextEncoder();
    const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
    const mac = async (rawKey: Uint8Array, msg: Uint8Array) => {
      const k = await crypto.subtle.importKey(
        'raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
    };
    const saltBytes = saltV.length ? enc.encode(saltV) : new Uint8Array(32);
    const prkBytes = await mac(saltBytes, enc.encode(ikmV));
    const infoBytes = enc.encode(infoV);
    const blocks: string[] = [];
    let prev = new Uint8Array(0);
    for (let i = 1; i <= Math.ceil(80 / 32); i++) {
      const msg = new Uint8Array(prev.length + infoBytes.length + 1);
      msg.set(prev, 0);
      msg.set(infoBytes, prev.length);
      msg[prev.length + infoBytes.length] = i;
      prev = await mac(prkBytes, msg);
      blocks.push(hex(prev));
    }
    return { prk: hex(prkBytes), blocks, okm: blocks.join('').slice(0, 160) };
  }, [ikm, salt, info] as const);
  expect(prk).toBe(ref.prk);
  expect(okm).toBe(ref.okm);
  expect(blocks).toEqual(ref.blocks);
});

test('HKDF: the info string binds the context — change it and the key changes', async ({ page }) => {
  test.setTimeout(60_000);
  await page.goto('.');

  const derive = async (info: string) => {
    await page.locator('#hkdf-info').fill(info);
    await page.locator('#hkdf-okm').evaluate((e) => { e.textContent = '—'; });
    await press(page, '#panel-hkdf', 'Derive Key');
    await expect(page.locator('#hkdf-okm')).not.toHaveText('—');
    return { okm: await txt(page, '#hkdf-okm'), prk: await txt(page, '#hkdf-prk') };
  };

  const a = await derive('TLS 1.3 derived');
  const b = await derive('file encryption');
  const a2 = await derive('TLS 1.3 derived');

  expect(a.okm).not.toBe(b.okm);
  expect(a.okm).toBe(a2.okm); // deterministic
  // Extract does not see info, so the PRK is unchanged — only Expand differs.
  expect(a.prk).toBe(b.prk);
});

/* ------------------------------------------------------------------ */
/*  Panel 2 — PBKDF2 and its iteration chain                          */
/* ------------------------------------------------------------------ */

test('PBKDF2: the derived keys are WebCrypto PBKDF2, and SHA-512 differs from SHA-256', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  await page.locator('#pbkdf2-iter').fill('5000');
  await press(page, '#panel-pbkdf2', 'Derive Key');
  await expect(page.locator('#pbkdf2-sha256')).not.toHaveText('—');

  const sha256 = await txt(page, '#pbkdf2-sha256');
  const sha512 = await txt(page, '#pbkdf2-sha512');
  expect(sha256).toHaveLength(64);
  expect(sha512).toHaveLength(64);
  expect(sha256).not.toBe(sha512);

  const pw = await page.locator('#pbkdf2-pw').inputValue();
  const salt = await page.locator('#pbkdf2-salt').inputValue();
  const ref = await page.evaluate(async ([pwv, saltv]) => {
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(pwv), 'PBKDF2', false, ['deriveBits']);
    const one = async (hash: string) => {
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: enc.encode(saltv), iterations: 5000, hash }, base, 256);
      return Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, '0')).join('');
    };
    return { s256: await one('SHA-256'), s512: await one('SHA-512') };
  }, [pw, salt] as const);

  expect(sha256).toBe(ref.s256);
  expect(sha512).toBe(ref.s512);
  expect(await txt(page, '#pbkdf2-timing')).toMatch(/SHA-256: [\d.]+ ms \| SHA-512: [\d.]+ ms/);
});

test('PBKDF2 chain visual: every link is HMAC of its predecessor and the XOR sums to T1', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('.');
  const pw = await page.locator('#pbkdf2-pw').inputValue();
  const salt = await page.locator('#pbkdf2-salt').inputValue();

  for (const c of [1, 4, 9, 16]) {
    await page.locator('#pb-chain-iter').fill(String(c));
    await page.locator('#pb-chain-iter').dispatchEvent('input');
    await expect(page.locator('#pb-links .pb-link')).toHaveCount(c);

    const links = await page.locator('#pb-links .pb-link').evaluateAll((els) =>
      els.map((e) => ({
        head: (e.querySelector('.pb-link-h')?.textContent ?? '').trim(),
        src: (e.querySelector('.pb-link-src')?.textContent ?? '').trim(),
        val: (e.querySelector('.pb-link-v')?.textContent ?? '').trim().replace(/…$/, ''),
      })),
    );
    const acc = unElide(await txt(page, '#pb-acc-v'));

    // Each link names its own predecessor: U1 is seeded from salt‖INT(1),
    // U_j (j>1) from U_{j-1}. That is the RFC 8018 §5.2 recurrence.
    expect(links[0].head).toBe('U1');
    expect(links[0].src).toBe('HMAC(pw, salt ‖ INT(1))');
    for (let j = 2; j <= c; j++) {
      expect(links[j - 1].head).toBe(`U${j}`);
      expect(links[j - 1].src).toBe(`HMAC(pw, U${j - 1})`);
    }

    // The accumulator is the XOR of every displayed link — checked on the
    // rendered bytes, so the panel is consistent with itself.
    const width = links[0].val.length;
    let folded = links[0].val;
    for (let i = 1; i < links.length; i++) folded = xorHex(folded, links[i].val);
    expect(acc.slice(0, width)).toBe(folded);

    // …and every link matches an independent WebCrypto recomputation.
    const ref = await page.evaluate(async ([pwv, saltv, count]) => {
      const enc = new TextEncoder();
      const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
      const key = await crypto.subtle.importKey(
        'raw', enc.encode(pwv as string), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const mac = async (msg: Uint8Array) =>
        new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
      const s = enc.encode(saltv as string);
      const first = new Uint8Array(s.length + 4);
      first.set(s, 0);
      first.set([0, 0, 0, 1], s.length);
      let u = await mac(first);
      const a = new Uint8Array(u);
      const us = [hex(u)];
      for (let j = 2; j <= (count as number); j++) {
        u = await mac(u);
        for (let i = 0; i < a.length; i++) a[i] ^= u[i];
        us.push(hex(u));
      }
      return { us, acc: hex(a) };
    }, [pw, salt, c] as const);

    for (let i = 0; i < c; i++) {
      expect(ref.us[i].startsWith(links[i].val)).toBe(true);
    }
    expect(ref.acc.startsWith(acc)).toBe(true);
  }
});

test('PBKDF2 chain visual equals WebCrypto PBKDF2 block 1 at the same iteration count', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  const c = 11;
  await page.locator('#pb-chain-iter').fill(String(c));
  await page.locator('#pb-chain-iter').dispatchEvent('input');
  await expect(page.locator('#pb-links .pb-link')).toHaveCount(c);
  const acc = unElide(await txt(page, '#pb-acc-v'));
  expect(acc.length).toBeGreaterThan(16);

  // The panel's own PBKDF2 run at c iterations must start with that same T1.
  await page.locator('#pbkdf2-iter').fill(String(c));
  await press(page, '#panel-pbkdf2', 'Derive Key');
  await expect(page.locator('#pbkdf2-sha256')).not.toHaveText('—');
  const dk = await txt(page, '#pbkdf2-sha256');
  expect(dk.startsWith(acc)).toBe(true);
});

test('PBKDF2 attacker cost is exactly 22 GH/s ÷ (2 × iterations) and collapses to ASICs', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  for (const iter of [1000, 50_000]) {
    await page.locator('#pbkdf2-iter').fill(String(iter));
    await page.locator('#pbkdf2-attack').evaluate((e) => { e.textContent = '—'; });
    await press(page, '#panel-pbkdf2', 'Derive Key');
    await expect(page.locator('#pbkdf2-attack')).toContainText('guesses/sec');
    const summary = await txt(page, '#pbkdf2-attack');
    expect(parseGuesses(summary)).toBe(Math.round(22e9 / (2 * iter)));
    expect(summary).toContain('bottleneck: compute (GPU-parallel)');
    expect(summary).toContain('one GPU:');
    expect(summary).toContain('1,000-GPU farm:');
    expect(summary).toContain('ASIC (~5,000× faster, cheap SHA cores)');
  }
});

/* ------------------------------------------------------------------ */
/*  Panel 3 — scrypt                                                  */
/* ------------------------------------------------------------------ */

test('scrypt: the printed memory estimate is exactly 128·N·r bytes', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('.');
  for (const [N, r, len] of [[4096, 4, 32], [16384, 8, 64]] as const) {
    await page.locator('#scrypt-n').fill(String(N));
    await page.locator('#scrypt-r').fill(String(r));
    await page.locator('#scrypt-len').fill(String(len));
    await page.locator('#scrypt-out').evaluate((e) => { e.textContent = '—'; });
    await press(page, '#panel-scrypt', 'Derive Key');
    await expect(page.locator('#scrypt-out')).not.toHaveText('—', { timeout: 60_000 });

    expect(await txt(page, '#scrypt-out')).toHaveLength(len * 2);
    const timing = await txt(page, '#scrypt-timing');
    const mem = Number(timing.match(/Memory estimate: ([\d.]+) MB/)![1]);
    expect(mem).toBeCloseTo((128 * N * r) / (1024 * 1024), 2);

    // Attacker cost is bandwidth ÷ bytes touched — same N and r, no fudge.
    const summary = await txt(page, '#scrypt-attack');
    expect(parseGuesses(summary)).toBe(Math.round(1e12 / (2 * 128 * r * N)));
    expect(summary).toContain('bottleneck: memory bandwidth');
    expect(summary).toContain('ASIC (~5× faster, memory resists ASICs)');
  }
});

test('scrypt: raising N raises both memory and time, in step', async ({ page }) => {
  test.setTimeout(300_000);
  await page.goto('.');
  await press(page, '#panel-scrypt', 'Compare N values');
  await expect(page.locator('#scrypt-bench')).not.toHaveText('—', { timeout: 240_000 });

  const lines = (await txt(page, '#scrypt-bench')).split('\n');
  expect(lines).toHaveLength(3);
  const seen: { n: number; ms: number; mb: number }[] = [];
  for (const line of lines) {
    const m = line.match(/N=2\^(\d+): ([\d.]+) ms, ~([\d.]+) MB/);
    expect(m, `unparsable benchmark row: ${line}`).not.toBeNull();
    seen.push({ n: Number(m![1]), ms: Number(m![2]), mb: Number(m![3]) });
  }
  expect(seen.map((s) => s.n)).toEqual([14, 17, 20]);
  // Memory must be the same 128·N·r formula the panel prints elsewhere (r=8).
  for (const s of seen) {
    expect(s.mb).toBeCloseTo((128 * 2 ** s.n * 8) / (1024 * 1024), 1);
  }
  // 8× the memory cannot be free: each step must cost strictly more time.
  expect(seen[1].ms).toBeGreaterThan(seen[0].ms);
  expect(seen[2].ms).toBeGreaterThan(seen[1].ms);
});

/* ------------------------------------------------------------------ */
/*  Panel 4 — Argon2id                                                */
/* ------------------------------------------------------------------ */

test('Argon2id: tag length and memory readout follow the parameters given', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('.');
  for (const [t, m, len] of [[2, 19456, 32], [1, 32768, 64]] as const) {
    await page.locator('#argon2-t').fill(String(t));
    await page.locator('#argon2-m').fill(String(m));
    await page.locator('#argon2-len').fill(String(len));
    await page.locator('#argon2-out').evaluate((e) => { e.textContent = '—'; });
    await press(page, '#panel-argon2', 'Derive Key');
    await expect(page.locator('#argon2-out')).not.toHaveText('—', { timeout: 90_000 });

    expect(await txt(page, '#argon2-out')).toHaveLength(len * 2);
    const timing = await txt(page, '#argon2-timing');
    expect(Number(timing.match(/Memory: ([\d.]+) MiB/)![1])).toBeCloseTo(m / 1024, 1);

    const summary = await txt(page, '#argon2-attack');
    expect(parseGuesses(summary)).toBe(Math.round(1e12 / (t * m * 1024)));
    expect(summary).toContain('bottleneck: memory bandwidth');
    expect(summary).toContain('ASIC (~5× faster, memory resists ASICs)');
  }
});

/* ------------------------------------------------------------------ */
/*  Panel 6 — Salt and context binding: the four failure/teaching paths */
/* ------------------------------------------------------------------ */

test('salt panel: every verdict matches the bytes printed above it', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('.');

  // 1. No salt — the FAILURE the README warns about, and it says why.
  await press(page, '#panel-salt', 'Same Password, No Salt');
  await expect(page.locator('#salt-nosalt')).toContainText('Identical:', { timeout: 90_000 });
  const noSalt = await txt(page, '#salt-nosalt');
  const [d1, d2] = [...noSalt.matchAll(/Derivation \d: ([0-9a-f]{64})/g)].map((m) => m[1]);
  expect(d1).toBe(d2);
  expect(noSalt).toContain('Identical: YES — rainbow table vulnerable!');

  // 2. Random salts — the fix, and the outputs really do diverge.
  await press(page, '#panel-salt', 'Same Password, Random Salts');
  await expect(page.locator('#salt-withsalt')).toContainText('Identical:', { timeout: 90_000 });
  const salted = await txt(page, '#salt-withsalt');
  const salts = [...salted.matchAll(/Salt \d: ([0-9a-f]{32})/g)].map((m) => m[1]);
  const outs = [...salted.matchAll(/Output \d: ([0-9a-f]{64})/g)].map((m) => m[1]);
  expect(salts).toHaveLength(2);
  expect(salts[0]).not.toBe(salts[1]);
  expect(outs[0]).not.toBe(outs[1]);
  expect(salted).toContain('Identical: NO — salt prevents rainbow tables');
  // Same password as the unsalted run — so the difference is the salt, nothing else.
  expect(outs).not.toContain(d1);

  // 3. HKDF context binding.
  await press(page, '#panel-salt', 'Context Binding');
  await expect(page.locator('#salt-context')).toContainText('Identical:', { timeout: 90_000 });
  const ctx = await txt(page, '#salt-context');
  const ctxKeys = [...ctx.matchAll(/: *([0-9a-f]{64})/g)].map((m) => m[1]);
  expect(ctxKeys).toHaveLength(2);
  expect(ctxKeys[0]).not.toBe(ctxKeys[1]);
  expect(ctx).toContain('Identical: NO — different info → different keys');

  // 4. Domain separation.
  await press(page, '#panel-salt', 'Domain Separation');
  await expect(page.locator('#salt-domain')).toContainText('Identical:', { timeout: 90_000 });
  const dom = await txt(page, '#salt-domain');
  const domKeys = [...dom.matchAll(/: *([0-9a-f]{64})/g)].map((m) => m[1]);
  expect(domKeys).toHaveLength(2);
  expect(domKeys[0]).not.toBe(domKeys[1]);
  expect(dom).toContain('Identical: NO — domain separation ensures independent keys');

  // All four derived key pairs are mutually distinct — no panel is echoing another.
  expect(new Set([...ctxKeys, ...domKeys]).size).toBe(4);
});

/* ------------------------------------------------------------------ */
/*  Panel 7 — The KDF chain                                           */
/* ------------------------------------------------------------------ */

test('KDF chain: every leaf is HKDF-Expand of the root it hangs from', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('.');
  await press(page, '#panel-chain', 'Run the Chain');
  await expect(page.locator('#chain-flow .chain-node')).toHaveCount(5, { timeout: 120_000 });

  const nodes = await page.locator('#chain-flow .chain-node').evaluateAll((els) =>
    els.map((e) => ({
      cls: e.className,
      label: (e.querySelector('.chain-node-label')?.textContent ?? '').trim(),
      value: (e.querySelector('.chain-node-value')?.textContent ?? '').trim(),
      sub: (e.querySelector('.chain-node-sub')?.textContent ?? '').trim(),
    })),
  );

  const root = nodes.find((n) => n.cls.includes('chain-root'))!;
  const leaves = nodes.filter((n) => n.cls.includes('chain-leaf'));
  expect(root.value).toHaveLength(64);
  expect(leaves).toHaveLength(3);
  expect(new Set(leaves.map((l) => l.value)).size).toBe(3); // independent keys

  // Each leaf must be exactly HKDF-Expand(root, info, 32) — the root is the
  // predecessor of every link, and we check the link against it.
  const infos = leaves.map((l) => l.label.match(/^info = "(.*)"$/)![1]);
  expect(infos).toEqual(['encryption key', 'MAC key', 'vault storage key']);
  const ref = await page.evaluate(async ([rootHex, labels]) => {
    const enc = new TextEncoder();
    const unhex = (h: string) => new Uint8Array(h.match(/../g)!.map((p) => parseInt(p, 16)));
    const key = await crypto.subtle.importKey(
      'raw', unhex(rootHex as string), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const out: string[] = [];
    for (const info of labels as string[]) {
      const i = enc.encode(info);
      const msg = new Uint8Array(i.length + 1);
      msg.set(i, 0);
      msg[i.length] = 1;
      const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
      out.push(Array.from(sig).map((b) => b.toString(16).padStart(2, '0')).join(''));
    }
    return out;
  }, [root.value, infos] as const);
  expect(leaves.map((l) => l.value)).toEqual(ref);

  // The counter is internally consistent: the whole chain took at least as long
  // as the Argon2id step it contains, and it names the number of keys shown.
  const timing = await txt(page, '#chain-timing');
  const total = Number(timing.match(/Whole chain: ([\d.]+) ms/)![1]);
  const argon = Number(root.sub.match(/([\d.]+) ms/)![1]);
  expect(timing).toContain(`(${leaves.length} keys from one password)`);
  expect(total).toBeGreaterThanOrEqual(argon);

  // And the expensive step really is the Argon2id one.
  expect(argon / total).toBeGreaterThan(0.5);
});

test('KDF chain: changing one info string changes only that key', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('.');
  const run = async () => {
    await page.locator('#chain-flow').evaluate((e) => { e.innerHTML = ''; });
    await press(page, '#panel-chain', 'Run the Chain');
    await expect(page.locator('#chain-flow .chain-node')).toHaveCount(5, { timeout: 120_000 });
    return page.locator('#chain-flow .chain-node').evaluateAll((els) =>
      els.map((e) => (e.querySelector('.chain-node-value')?.textContent ?? '').trim()),
    );
  };

  const before = await run();
  await page.locator('#chain-info3').fill('backup archive key');
  const after = await run();

  expect(after[1]).toBe(before[1]); // root unchanged — same password/salt
  expect(after[2]).toBe(before[2]); // encryption key unchanged
  expect(after[3]).toBe(before[3]); // MAC key unchanged
  expect(after[4]).not.toBe(before[4]); // the changed context gives a new key

  // Blank an info string and the fan-out shrinks accordingly.
  await page.locator('#chain-info2').fill('');
  await page.locator('#chain-flow').evaluate((e) => { e.innerHTML = ''; });
  await press(page, '#panel-chain', 'Run the Chain');
  await expect(page.locator('#chain-flow .chain-node')).toHaveCount(4, { timeout: 120_000 });
  await expect(page.locator('#chain-timing')).toContainText('(2 keys from one password)');
});

/* ------------------------------------------------------------------ */
/*  Panel 8 — Cost comparison                                         */
/* ------------------------------------------------------------------ */

test('cost comparison: bar widths are consistent with the milliseconds they report', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('.');
  await press(page, '#panel-cost', 'Run All KDFs');
  await expect(page.locator('#cost-bars .cost-row')).toHaveCount(4, { timeout: 180_000 });

  const rows = await page.locator('#cost-bars .cost-row').evaluateAll((els) =>
    els.map((e) => ({
      name: (e.querySelector('.cost-name')?.textContent ?? '').trim(),
      ms: (e.querySelector('.cost-ms')?.textContent ?? '').trim(),
      width: (e.querySelector('.cost-fill') as HTMLElement | null)?.style.width ?? '',
      attack: (e.querySelector('.cost-attack')?.textContent ?? '').trim(),
    })),
  );

  expect(rows.map((r) => r.name)).toEqual([
    'PBKDF2 (100k)', 'PBKDF2 (600k)', 'scrypt (N=2¹⁴)', 'Argon2id (19 MiB)',
  ]);

  const ms = rows.map((r) => Number(r.ms.match(/([\d.]+) ms/)![1]));
  const pct = rows.map((r) => Number(r.width.replace('%', '')));
  const max = Math.max(...ms);

  // Exactly one bar is full, and it is the slowest KDF.
  expect(pct.filter((p) => p === 100)).toHaveLength(1);
  expect(ms[pct.indexOf(100)]).toBe(max);
  for (let i = 0; i < rows.length; i++) {
    const expected = Math.max(4, Math.round((ms[i] / max) * 100));
    // ±1 absorbs the rounding of the displayed millisecond value only.
    expect(Math.abs(pct[i] - expected)).toBeLessThanOrEqual(1);
  }
  // Bars rank the same way the numbers do. Stated as monotonicity rather than
  // a strict permutation, because two KDFs whose real timings differ can still
  // round to the same integer percentage under machine load.
  for (let i = 0; i < rows.length; i++) {
    for (let j = 0; j < rows.length; j++) {
      if (ms[i] < ms[j]) {
        expect(pct[i], `${rows[i].name} is faster than ${rows[j].name}, so its bar cannot be longer`)
          .toBeLessThanOrEqual(pct[j]);
      }
    }
  }

  // Six times the iterations is exactly six times harder for the attacker…
  const g100 = parseGuesses(rows[0].attack);
  const g600 = parseGuesses(rows[1].attack);
  expect(g100).toBe(Math.round(22e9 / 200_000));
  expect(g600).toBe(Math.round(22e9 / 1_200_000));

  // …and the ASIC asymmetry the README teaches shows up per row.
  expect(rows[0].attack).toContain('ASIC (~5,000× faster, cheap SHA cores)');
  expect(rows[1].attack).toContain('ASIC (~5,000× faster, cheap SHA cores)');
  expect(rows[2].attack).toContain('ASIC (~5× faster, memory resists ASICs)');
  expect(rows[3].attack).toContain('ASIC (~5× faster, memory resists ASICs)');
  expect(rows[2].attack).toContain('bottleneck: memory bandwidth');
  expect(rows[3].attack).toContain('bottleneck: memory bandwidth');
});

/* ------------------------------------------------------------------ */
/*  Panel 5 — Decision tree                                           */
/* ------------------------------------------------------------------ */

test('decision tree: every branch reaches its documented recommendation and says why', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');

  const ask = async (entropy: string, multi: string, legacy: string) => {
    await page.locator(`#dt-entropy-${entropy}`).check();
    await page.locator(`#dt-multi-${multi}`).check();
    await page.locator(`#dt-legacy-${legacy}`).check();
    await press(page, '#panel-decision', 'Get Recommendation');
    return {
      kdf: await txt(page, '#decision-result .decision-kdf'),
      why: await txt(page, '#decision-result .decision-reasoning'),
    };
  };

  // High entropy short-circuits everything else.
  for (const [m, l] of [['no', 'no'], ['yes', 'yes'], ['yes', 'no']] as const) {
    const r = await ask('high', m, l);
    expect(r.kdf).toContain('Recommendation: HKDF');
    expect(r.kdf).toContain('RECOMMENDED');
    expect(r.why).toContain('high entropy');
    expect(r.why).toContain('not suitable for passwords');
  }

  // Legacy/FIPS beats the memory-hard default, and warns you what it costs.
  for (const m of ['yes', 'no'] as const) {
    const r = await ask('low', m, 'yes');
    expect(r.kdf).toContain('Recommendation: PBKDF2');
    expect(r.kdf).toContain('ACCEPTABLE');
    expect(r.why).toContain('600,000');
    expect(r.why).toContain('embarrassingly');
  }

  // Password + multiple keys → Argon2id feeding HKDF-Expand (this demo's chain).
  const multi = await ask('low', 'yes', 'no');
  expect(multi.kdf).toContain('Recommendation: Argon2id');
  expect(multi.kdf).toContain('RECOMMENDED DEFAULT');
  expect(multi.why).toContain('HKDF-Expand');
  expect(multi.why).toContain('domain');

  // Plain password storage → Argon2id with the OWASP parameters.
  const plain = await ask('low', 'no', 'no');
  expect(plain.kdf).toContain('Recommendation: Argon2id');
  expect(plain.why).toContain('t=2, m=19456');
  expect(plain.why).not.toBe(multi.why); // the two Argon2id paths explain themselves differently
});

test('comparison table renders real status chips, not serialised markup', async ({ page }) => {
  // Regression: the Status column used to stringify the chip to .outerHTML,
  // drop it in as text, and re-parse it with a greedy /Status: (.+)/, so every
  // cell displayed — and announced — `RECOMMENDED DEFAULT">…</span>`.
  await page.goto('.');
  const cells = page.locator('.comparison-table tbody tr td:last-child');
  await expect(cells).toHaveCount(4);

  const chips = await cells.locator('.status-chip').evaluateAll((els) =>
    els.map((e) => ({ text: (e.textContent ?? '').trim(), aria: e.getAttribute('aria-label') ?? '' })),
  );
  expect(chips.map((c) => c.text)).toEqual([
    'RECOMMENDED (high-entropy)',
    'ACCEPTABLE (legacy)',
    'RECOMMENDED (if no Argon2id)',
    'RECOMMENDED DEFAULT',
  ]);
  for (const c of chips) {
    // The chip used to carry `aria-label="Status: <text>"`. `aria-label` is
    // PROHIBITED on a role-less <span>: the browser discards it, so the name a
    // screen reader announces was always the chip's own text — which is what
    // the assertion above already pins. Asserting the attribute was asserting a
    // value nothing on the page ever used, and it held a real
    // `aria-prohibited-attr` finding in place. Its absence is now the claim.
    expect(c.aria).toBe('');
    expect(c.text).not.toContain('<');
    expect(c.text).not.toContain('>');
    expect(c.text).not.toContain('span');
  }
  // The cell holds the chip and nothing else.
  for (const t of await cells.allTextContents()) {
    expect(t.trim()).not.toMatch(/[<>]/);
  }
});

/* ------------------------------------------------------------------ */
/*  Memory-hardness visual, guided path, assumptions note             */
/* ------------------------------------------------------------------ */

test('memory grid: one cell per MiB, at every step of the slider, matching its own label', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  const slider = page.locator('#mem-cost');
  const max = Number(await slider.getAttribute('max'));
  expect(max).toBe(4);

  for (let i = 0; i <= max; i++) {
    await slider.fill(String(i));
    await slider.dispatchEvent('input');
    const label = await txt(page, '#mem-cost-value');
    const mib = Number(label.match(/(\d+) MiB/)![1]);
    await expect(page.locator('#mem-grid .mem-cell')).toHaveCount(mib);
  }

  // Animating fills every cell of the selected block and names the step.
  await slider.fill('0');
  await slider.dispatchEvent('input');
  await press(page, '#panel-memory', 'Animate memory access');
  await expect(page.locator('#mem-grid .mem-cell.filled')).toHaveCount(4, { timeout: 30_000 });
  await expect(page.locator('#mem-cap')).toContainText('4 MiB');
  await expect(page.locator('#mem-cap')).toContainText('Streaming 4 cells');

  // The compute-bound side is the contrast: 48 cores, always busy, and 48
  // stalled counterparts on the memory-bound side.
  await expect(page.locator('.mem-cores .mem-core')).toHaveCount(48);
  await expect(page.locator('.mem-stall .mem-core-stall')).toHaveCount(48);
});

test('README promises a reader can see: guided path, RFC citations, inline assumptions', async ({ page }) => {
  await page.goto('.');

  // Six ordered guided-path steps, each anchoring a panel that exists.
  const steps = page.locator('.guide-steps li');
  await expect(steps).toHaveCount(6);
  const targets = await page.locator('.guide-steps a').evaluateAll((els) =>
    els.map((e) => {
      const href = e.getAttribute('href') ?? '';
      return { href, exists: !!document.querySelector(href) };
    }),
  );
  for (const t of targets) expect(t.exists, `${t.href} should resolve to a panel`).toBe(true);
  expect(targets.map((t) => t.href)).toEqual([
    '#panel-hkdf', '#panel-pbkdf2', '#panel-memory', '#panel-chain', '#panel-cost', '#panel-vectors',
  ]);

  // Ten panels, each citing the standard it implements where one exists.
  await expect(page.locator('.panels .panel')).toHaveCount(10);
  const cites = (await page.locator('.panel .rfc-ref').allTextContents()).join(' | ');
  for (const rfc of ['RFC 5869', 'RFC 8018', 'RFC 7914', 'RFC 9106']) {
    expect(cites).toContain(rfc);
  }

  // The attacker-cost assumptions sit inline next to the numbers, one per
  // attacker readout, and state the model's inputs.
  const notes = page.locator('details.assumptions');
  await expect(notes).toHaveCount(await page.locator('.attack-out').count());
  await expect(notes).toHaveCount(3);
  for (const t of await notes.allTextContents()) {
    expect(t).toContain('RTX 4090');
    expect(t).toContain('keyspace ÷ 2');
    expect(t).toContain('~5000×');
    expect(t).toContain('~5×');
  }

  // Before any run, each attacker readout says so rather than showing a number.
  for (const t of await page.locator('.attack-out').allTextContents()) {
    expect(t.trim()).toBe('Derive a key to estimate attacker cost.');
  }
});
