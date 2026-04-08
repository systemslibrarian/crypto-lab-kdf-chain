/**
 * ui.ts — Panel controller for six-panel KDF demo
 * Handles DOM creation, event binding, and result rendering
 */

import { hkdf } from './hkdf';
import { pbkdf2Sha256, pbkdf2Sha512, pbkdf2Benchmark } from './pbkdf2';
import { deriveScrypt } from './scrypt';
import { deriveArgon2id } from './argon2';
import { decide, comparisonTable, type DecisionResult } from './decision';
import { demoNoSalt, demoWithSalt, demoContextBinding, demoDomainSeparation } from './salt';

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: Record<string, string>,
  ...children: (string | Node)[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (attrs) Object.entries(attrs).forEach(([k, v]) => {
    if (k.startsWith('aria-') || k === 'role' || k === 'for' || k === 'tabindex') e.setAttribute(k, v);
    else (e as unknown as Record<string, string>)[k] = v;
  });
  children.forEach(c => e.append(typeof c === 'string' ? document.createTextNode(c) : c));
  return e;
}

function statusChip(label: string): HTMLElement {
  const cls = label.includes('DEFAULT') ? 'chip-recommended-default'
    : label.includes('RECOMMENDED') ? 'chip-recommended'
    : label.includes('ACCEPTABLE') ? 'chip-acceptable'
    : 'chip-info';
  const chip = el('span', { className: `status-chip ${cls}`, 'aria-label': `Status: ${label}` }, label);
  return chip;
}

function inputGroup(id: string, labelText: string, type: string, value: string, extra?: Record<string, string>): HTMLElement {
  const wrap = el('div', { className: 'input-group' });
  const lbl = el('label', { 'for': id }, labelText);
  const attrs: Record<string, string> = { id, type, className: 'input-field', value, ...extra ?? {} };
  if (type === 'range') {
    attrs['aria-label'] = labelText;
  }
  const inp = el('input', attrs);
  wrap.append(lbl, inp);
  if (type === 'range') {
    const vSpan = el('span', { className: 'range-value', id: `${id}-value`, 'aria-live': 'polite' }, value);
    wrap.append(vSpan);
    inp.addEventListener('input', () => {
      vSpan.textContent = inp.value;
    });
  }
  return wrap;
}

function outputBox(id: string, label: string): HTMLElement {
  const wrap = el('div', { className: 'output-group' });
  const lbl = el('span', { className: 'output-label', 'aria-label': label }, label);
  const box = el('pre', { className: 'output-hex', id, 'aria-label': `${label} output`, tabindex: '0' }, '—');
  wrap.append(lbl, box);
  return wrap;
}

function setOutput(id: string, text: string) {
  const e = document.getElementById(id);
  if (e) e.textContent = text;
}

function button(text: string, ariaLabel: string, onClick: () => void): HTMLElement {
  const btn = el('button', { className: 'btn', 'aria-label': ariaLabel }, text);
  btn.addEventListener('click', onClick);
  return btn;
}

function liveRegion(id: string): HTMLElement {
  return el('div', { id, className: 'sr-only', 'aria-live': 'assertive', role: 'status' });
}

function announce(id: string, msg: string) {
  const e = document.getElementById(id);
  if (e) e.textContent = msg;
}

function sectionHeading(title: string, chip: HTMLElement, rfcRef: string): HTMLElement {
  const h = el('h2', { className: 'panel-title' });
  h.append(title, ' ', chip);
  const cite = el('cite', { className: 'rfc-ref' }, rfcRef);
  const wrap = el('div', { className: 'panel-heading' }, h, cite);
  return wrap;
}

function panel(id: string, ...children: (string | Node)[]): HTMLElement {
  const sec = el('section', { id, className: 'panel', 'aria-labelledby': `${id}-title`, tabindex: '0' });
  children.forEach(c => sec.append(typeof c === 'string' ? document.createTextNode(c) : c));
  return sec;
}

function infoBox(text: string): HTMLElement {
  return el('div', { className: 'info-box', role: 'note' }, text);
}

function timingDisplay(id: string): HTMLElement {
  return el('div', { className: 'timing', id, 'aria-live': 'polite' }, '');
}

/* ------------------------------------------------------------------ */
/*  Panel 1 — HKDF                                                    */
/* ------------------------------------------------------------------ */

function buildHkdfPanel(): HTMLElement {
  const heading = sectionHeading('HKDF: Extract and Expand', statusChip('RECOMMENDED'), 'RFC 5869');
  heading.querySelector('h2')!.id = 'panel-hkdf-title';

  const form = el('div', { className: 'panel-form' },
    inputGroup('hkdf-ikm', 'Input Key Material (IKM)', 'text', 'my-high-entropy-secret-key-material'),
    inputGroup('hkdf-salt', 'Salt', 'text', 'random-salt-value'),
    inputGroup('hkdf-info', 'Info String (context)', 'text', 'TLS 1.3 derived'),
    inputGroup('hkdf-len', 'Output Length (bytes)', 'number', '32', { min: '1', max: '255' }),
  );

  const live = liveRegion('hkdf-live');
  const timing = timingDisplay('hkdf-timing');

  const derivBtn = button('Derive Key', 'Derive HKDF key', async () => {
    const ikm = (document.getElementById('hkdf-ikm') as HTMLInputElement).value;
    const salt = (document.getElementById('hkdf-salt') as HTMLInputElement).value;
    const info = (document.getElementById('hkdf-info') as HTMLInputElement).value;
    const len = parseInt((document.getElementById('hkdf-len') as HTMLInputElement).value, 10) || 32;
    try {
      const r = await hkdf(ikm, salt, info, len);
      setOutput('hkdf-prk', r.prkHex);
      setOutput('hkdf-okm', r.okmHex);
      setOutput('hkdf-blocks', r.blocks.map((b, i) => `T(${i + 1}): ${b}`).join('\n'));
      document.getElementById('hkdf-timing')!.textContent = `Derived in ${r.timeMs.toFixed(2)} ms`;
      announce('hkdf-live', `HKDF derivation complete in ${r.timeMs.toFixed(2)} milliseconds`);
    } catch (err) {
      announce('hkdf-live', `Error: ${(err as Error).message}`);
    }
  });

  const note = infoBox(
    'HKDF is not for passwords — it assumes high-entropy input. Changing the info string produces completely different output (context binding). ' +
    'Use cases: TLS 1.3 key schedule, Signal Protocol, WireGuard.'
  );

  return panel('panel-hkdf',
    heading, note, form, derivBtn, live, timing,
    el('h3', {}, 'Extract Phase'),
    outputBox('hkdf-prk', 'PRK = HMAC-SHA-256(salt, IKM)'),
    el('h3', {}, 'Expand Phase'),
    outputBox('hkdf-okm', 'Output Key Material (OKM)'),
    outputBox('hkdf-blocks', 'Expand Blocks T(i)'),
  );
}

/* ------------------------------------------------------------------ */
/*  Panel 2 — PBKDF2                                                  */
/* ------------------------------------------------------------------ */

function buildPbkdf2Panel(): HTMLElement {
  const heading = sectionHeading('PBKDF2: Password Stretching', statusChip('ACCEPTABLE'), 'RFC 8018');
  heading.querySelector('h2')!.id = 'panel-pbkdf2-title';

  const form = el('div', { className: 'panel-form' },
    inputGroup('pbkdf2-pw', 'Password', 'text', 'correct horse battery staple'),
    inputGroup('pbkdf2-salt', 'Salt', 'text', 'unique-random-salt'),
    inputGroup('pbkdf2-iter', 'Iterations', 'number', '600000', { min: '1', max: '10000000' }),
    inputGroup('pbkdf2-len', 'Output Length (bytes)', 'number', '32', { min: '1', max: '64' }),
  );

  const live = liveRegion('pbkdf2-live');
  const timing = timingDisplay('pbkdf2-timing');

  const derivBtn = button('Derive Key', 'Derive PBKDF2 key', async () => {
    const pw = (document.getElementById('pbkdf2-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('pbkdf2-salt') as HTMLInputElement).value;
    const iter = parseInt((document.getElementById('pbkdf2-iter') as HTMLInputElement).value, 10) || 600000;
    const len = parseInt((document.getElementById('pbkdf2-len') as HTMLInputElement).value, 10) || 32;
    try {
      const [r256, r512] = await Promise.all([
        pbkdf2Sha256(pw, salt, iter, len),
        pbkdf2Sha512(pw, salt, iter, len),
      ]);
      setOutput('pbkdf2-sha256', r256.hex);
      setOutput('pbkdf2-sha512', r512.hex);
      document.getElementById('pbkdf2-timing')!.textContent =
        `SHA-256: ${r256.timeMs.toFixed(2)} ms | SHA-512: ${r512.timeMs.toFixed(2)} ms`;
      announce('pbkdf2-live', `PBKDF2 derivation complete. SHA-256 in ${r256.timeMs.toFixed(2)} ms, SHA-512 in ${r512.timeMs.toFixed(2)} ms`);
    } catch (err) {
      announce('pbkdf2-live', `Error: ${(err as Error).message}`);
    }
  });

  const benchBtn = button('Benchmark (100k / 600k / 1M)', 'Benchmark PBKDF2 at multiple iteration counts', async () => {
    const pw = (document.getElementById('pbkdf2-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('pbkdf2-salt') as HTMLInputElement).value;
    const len = parseInt((document.getElementById('pbkdf2-len') as HTMLInputElement).value, 10) || 32;
    announce('pbkdf2-live', 'Running benchmark…');
    try {
      const results = await pbkdf2Benchmark(pw, salt, [100_000, 600_000, 1_000_000], len);
      const text = results.map(r => `${(r.iterations / 1000).toFixed(0)}k iterations: ${r.timeMs.toFixed(2)} ms`).join('\n');
      setOutput('pbkdf2-bench', text);
      announce('pbkdf2-live', 'Benchmark complete');
    } catch (err) {
      announce('pbkdf2-live', `Error: ${(err as Error).message}`);
    }
  });

  const note = infoBox(
    'PBKDF2 is embarrassingly parallel — GPUs can test many passwords simultaneously. ' +
    'OWASP recommends minimum 600,000 iterations for PBKDF2-HMAC-SHA-256. ' +
    'Prefer Argon2id for new systems. Iteration chain: U₁, U₂, … Uₙ XORed together.'
  );

  return panel('panel-pbkdf2',
    heading, note, form, derivBtn, benchBtn, live, timing,
    outputBox('pbkdf2-sha256', 'PBKDF2-HMAC-SHA-256'),
    outputBox('pbkdf2-sha512', 'PBKDF2-HMAC-SHA-512'),
    outputBox('pbkdf2-bench', 'Benchmark Results'),
  );
}

/* ------------------------------------------------------------------ */
/*  Panel 3 — scrypt                                                  */
/* ------------------------------------------------------------------ */

function buildScryptPanel(): HTMLElement {
  const heading = sectionHeading('scrypt: Memory-Hard Stretching', statusChip('RECOMMENDED'), 'RFC 7914');
  heading.querySelector('h2')!.id = 'panel-scrypt-title';

  const form = el('div', { className: 'panel-form' },
    inputGroup('scrypt-pw', 'Password', 'text', 'correct horse battery staple'),
    inputGroup('scrypt-salt', 'Salt', 'text', 'unique-random-salt'),
    inputGroup('scrypt-n', 'N (CPU/memory cost, power of 2)', 'number', '16384', { min: '2', max: '1048576', step: '2' }),
    inputGroup('scrypt-r', 'r (block size)', 'number', '8', { min: '1', max: '64' }),
    inputGroup('scrypt-p', 'p (parallelism)', 'number', '1', { min: '1', max: '16' }),
    inputGroup('scrypt-len', 'Output Length (bytes)', 'number', '32', { min: '1', max: '64' }),
  );

  const live = liveRegion('scrypt-live');
  const timing = timingDisplay('scrypt-timing');

  const derivBtn = button('Derive Key', 'Derive scrypt key', () => {
    const pw = (document.getElementById('scrypt-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('scrypt-salt') as HTMLInputElement).value;
    const N = parseInt((document.getElementById('scrypt-n') as HTMLInputElement).value, 10) || 16384;
    const r = parseInt((document.getElementById('scrypt-r') as HTMLInputElement).value, 10) || 8;
    const p = parseInt((document.getElementById('scrypt-p') as HTMLInputElement).value, 10) || 1;
    const len = parseInt((document.getElementById('scrypt-len') as HTMLInputElement).value, 10) || 32;
    try {
      const res = deriveScrypt(pw, salt, N, r, p, len);
      setOutput('scrypt-out', res.hex);
      document.getElementById('scrypt-timing')!.textContent =
        `Derived in ${res.timeMs.toFixed(2)} ms | Memory estimate: ${res.memoryEstimateMB.toFixed(2)} MB`;
      announce('scrypt-live', `scrypt derivation complete in ${res.timeMs.toFixed(2)} ms, estimated memory ${res.memoryEstimateMB.toFixed(2)} MB`);
    } catch (err) {
      announce('scrypt-live', `Error: ${(err as Error).message}`);
    }
  });

  const benchBtn = button('Compare N values (2¹⁴ vs 2¹⁷ vs 2²⁰)', 'Benchmark scrypt at different N values', () => {
    const pw = (document.getElementById('scrypt-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('scrypt-salt') as HTMLInputElement).value;
    const r = parseInt((document.getElementById('scrypt-r') as HTMLInputElement).value, 10) || 8;
    const p = parseInt((document.getElementById('scrypt-p') as HTMLInputElement).value, 10) || 1;
    const len = parseInt((document.getElementById('scrypt-len') as HTMLInputElement).value, 10) || 32;
    announce('scrypt-live', 'Running N-value comparison…');
    try {
      const results = [2 ** 14, 2 ** 17, 2 ** 20].map(N => {
        try { return deriveScrypt(pw, salt, N, r, p, len); }
        catch { return null; }
      });
      const text = results.map(res => {
        if (!res) return 'N too large for browser memory';
        return `N=2^${Math.log2(res.N)}: ${res.timeMs.toFixed(2)} ms, ~${res.memoryEstimateMB.toFixed(1)} MB`;
      }).join('\n');
      setOutput('scrypt-bench', text);
      announce('scrypt-live', 'N-value comparison complete');
    } catch (err) {
      announce('scrypt-live', `Error: ${(err as Error).message}`);
    }
  });

  const note = infoBox(
    'scrypt uses ROMix and BlockMix to create memory-hard computation. Memory access patterns resist GPU attacks because ' +
    'GPUs have limited on-chip memory per core. Memory estimate: 128 × N × r bytes (RFC 7914 §2).'
  );

  return panel('panel-scrypt',
    heading, note, form, derivBtn, benchBtn, live, timing,
    outputBox('scrypt-out', 'Derived Key'),
    outputBox('scrypt-bench', 'N-value Comparison'),
  );
}

/* ------------------------------------------------------------------ */
/*  Panel 4 — Argon2id                                                */
/* ------------------------------------------------------------------ */

function buildArgon2Panel(): HTMLElement {
  const heading = sectionHeading('Argon2id: Modern Password Hashing', statusChip('RECOMMENDED DEFAULT'), 'RFC 9106');
  heading.querySelector('h2')!.id = 'panel-argon2-title';

  const form = el('div', { className: 'panel-form' },
    inputGroup('argon2-pw', 'Password', 'text', 'correct horse battery staple'),
    inputGroup('argon2-salt', 'Salt (min 8 chars)', 'text', 'random-salt-value-16'),
    inputGroup('argon2-t', 'Time Cost (iterations)', 'number', '2', { min: '1', max: '16' }),
    inputGroup('argon2-m', 'Memory Cost (KB)', 'number', '19456', { min: '1024', max: '1048576' }),
    inputGroup('argon2-p', 'Parallelism', 'number', '1', { min: '1', max: '16' }),
    inputGroup('argon2-len', 'Tag Length (bytes)', 'number', '32', { min: '4', max: '64' }),
  );

  const live = liveRegion('argon2-live');
  const timing = timingDisplay('argon2-timing');

  const derivBtn = button('Derive Key', 'Derive Argon2id key', () => {
    const pw = (document.getElementById('argon2-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('argon2-salt') as HTMLInputElement).value;
    const t = parseInt((document.getElementById('argon2-t') as HTMLInputElement).value, 10) || 2;
    const m = parseInt((document.getElementById('argon2-m') as HTMLInputElement).value, 10) || 19456;
    const p = parseInt((document.getElementById('argon2-p') as HTMLInputElement).value, 10) || 1;
    const dkLen = parseInt((document.getElementById('argon2-len') as HTMLInputElement).value, 10) || 32;
    try {
      const res = deriveArgon2id(pw, salt, t, m, p, dkLen);
      setOutput('argon2-out', res.hex);
      document.getElementById('argon2-timing')!.textContent =
        `Derived in ${res.timeMs.toFixed(2)} ms | Memory: ${(m / 1024).toFixed(1)} MiB`;
      announce('argon2-live', `Argon2id derivation complete in ${res.timeMs.toFixed(2)} milliseconds`);
    } catch (err) {
      announce('argon2-live', `Error: ${(err as Error).message}`);
    }
  });

  const note = infoBox(
    'Argon2id combines data-dependent (Argon2d) and data-independent (Argon2i) memory access patterns. ' +
    'Argon2d resists GPU/ASIC but is vulnerable to side-channel; Argon2i resists side-channel but is weaker against GPU. ' +
    'Argon2id uses Argon2i for the first pass and Argon2d thereafter — the best of both. ' +
    'OWASP recommends: t=2, m=19456 (19 MiB), p=1. Memory cost makes ASIC/GPU attacks economically impractical.'
  );

  return panel('panel-argon2',
    heading, note, form, derivBtn, live, timing,
    outputBox('argon2-out', 'Derived Key (Argon2id)'),
  );
}

/* ------------------------------------------------------------------ */
/*  Panel 5 — Decision Tree                                           */
/* ------------------------------------------------------------------ */

function buildDecisionPanel(): HTMLElement {
  const heading = sectionHeading('KDF Decision Tree', statusChip('GUIDE'), '');
  heading.querySelector('h2')!.id = 'panel-decision-title';

  const q1 = el('fieldset', { className: 'decision-question' },
    el('legend', {}, '1. Is your input high-entropy (key material) or low-entropy (password)?'),
    radioOption('dt-entropy', 'high', 'High-entropy key material'),
    radioOption('dt-entropy', 'low', 'Low-entropy password', true),
  );
  const q2 = el('fieldset', { className: 'decision-question' },
    el('legend', {}, '2. Do you need multiple independent keys from one root?'),
    radioOption('dt-multi', 'yes', 'Yes'),
    radioOption('dt-multi', 'no', 'No', true),
  );
  const q3 = el('fieldset', { className: 'decision-question' },
    el('legend', {}, '3. Are you in a legacy/FIPS-constrained environment?'),
    radioOption('dt-legacy', 'yes', 'Yes'),
    radioOption('dt-legacy', 'no', 'No', true),
  );

  const live = liveRegion('decision-live');
  const resultDiv = el('div', { id: 'decision-result', className: 'decision-result', 'aria-live': 'polite' });

  const evalBtn = button('Get Recommendation', 'Evaluate KDF decision tree', () => {
    const high = (document.querySelector('input[name="dt-entropy"]:checked') as HTMLInputElement)?.value === 'high';
    const multi = (document.querySelector('input[name="dt-multi"]:checked') as HTMLInputElement)?.value === 'yes';
    const legacy = (document.querySelector('input[name="dt-legacy"]:checked') as HTMLInputElement)?.value === 'yes';
    const res: DecisionResult = decide(high, multi, legacy);
    resultDiv.innerHTML = '';
    resultDiv.append(
      el('div', { className: 'decision-kdf' }, `Recommendation: ${res.kdf} `, statusChip(res.chip)),
      el('p', { className: 'decision-reasoning' }, res.reasoning),
    );
    announce('decision-live', `Recommendation: ${res.kdf}. ${res.reasoning}`);
  });

  // Comparison table
  const table = el('table', { className: 'comparison-table', 'aria-label': 'KDF comparison table' });
  const thead = el('thead', {},
    el('tr', {},
      ...['KDF', 'Input Type', 'Memory Hardness', 'GPU Resistance', 'FIPS', 'Recommended Parameters', 'Status']
        .map(h => el('th', {}, h))
    ));
  const tbody = el('tbody', {});
  comparisonTable.forEach(row => {
    tbody.append(el('tr', {},
      el('td', { className: 'td-kdf' }, row.kdf),
      el('td', {}, row.inputType),
      el('td', {}, row.memoryHardness),
      el('td', {}, row.gpuResistance),
      el('td', {}, row.fips),
      el('td', {}, row.recommendedParams),
      el('td', {}, statusChip(row.status).outerHTML),
    ));
  });
  // Re-parse the HTML in status column
  tbody.querySelectorAll('td:last-child').forEach(td => {
    const raw = td.textContent || '';
    if (raw) {
      const match = raw.match(/Status: (.+)/);
      if (match) {
        td.innerHTML = '';
        td.append(statusChip(match[1]));
      }
    }
  });
  table.append(thead, tbody);

  const tableWrap = el('div', { className: 'table-scroll', role: 'region', 'aria-label': 'KDF comparison', tabindex: '0' }, table);

  return panel('panel-decision', heading, q1, q2, q3, evalBtn, live, resultDiv, el('h3', {}, 'Comparison'), tableWrap);
}

function radioOption(name: string, value: string, label: string, checked?: boolean): HTMLElement {
  const id = `${name}-${value}`;
  const wrap = el('div', { className: 'radio-option' });
  const inp = el('input', { type: 'radio', name, value, id, ...(checked ? { checked: 'true' } : {}) });
  if (checked) inp.checked = true;
  const lbl = el('label', { 'for': id }, label);
  wrap.append(inp, lbl);
  return wrap;
}

/* ------------------------------------------------------------------ */
/*  Panel 6 — Salt and Context Binding                                */
/* ------------------------------------------------------------------ */

function buildSaltPanel(): HTMLElement {
  const heading = sectionHeading('Salt and Context Binding', statusChip('ESSENTIAL'), '');
  heading.querySelector('h2')!.id = 'panel-salt-title';

  const live = liveRegion('salt-live');

  // Sub-demo 1: no salt
  const noSaltBtn = button('Same Password, No Salt', 'Demonstrate rainbow table vulnerability with no salt', async () => {
    announce('salt-live', 'Deriving with no salt…');
    const r = await demoNoSalt('password123');
    setOutput('salt-nosalt', `Derivation 1: ${r.hex1}\nDerivation 2: ${r.hex2}\nIdentical: ${r.match ? 'YES — rainbow table vulnerable!' : 'No'}`);
    announce('salt-live', r.match ? 'Outputs are identical — rainbow table attack possible' : 'Outputs differ');
  });

  // Sub-demo 2: with salt
  const saltBtn = button('Same Password, Random Salts', 'Demonstrate salt protection', async () => {
    announce('salt-live', 'Deriving with random salts…');
    const r = await demoWithSalt('password123');
    setOutput('salt-withsalt',
      `Salt 1: ${r.salt1}\nOutput 1: ${r.hex1}\n\nSalt 2: ${r.salt2}\nOutput 2: ${r.hex2}\n\nIdentical: ${r.match ? 'YES' : 'NO — salt prevents rainbow tables'}`);
    announce('salt-live', r.match ? 'Outputs match unexpectedly' : 'Outputs differ — salt prevents rainbow tables');
  });

  // Sub-demo 3: context binding
  const ctxBtn = button('Context Binding (HKDF info)', 'Demonstrate HKDF context binding', async () => {
    announce('salt-live', 'Deriving with different info strings…');
    const r = await demoContextBinding('master-secret-key', 'app-salt');
    setOutput('salt-context',
      `Info "encryption key": ${r.encKey}\nInfo "MAC key":        ${r.macKey}\n\nIdentical: ${r.match ? 'YES' : 'NO — different info → different keys'}`);
    announce('salt-live', 'Context binding demonstration complete');
  });

  // Sub-demo 4: domain separation
  const domBtn = button('Domain Separation', 'Demonstrate domain separation with HKDF', async () => {
    announce('salt-live', 'Deriving with different domains…');
    const r = await demoDomainSeparation('master-secret-key', 'app-salt');
    setOutput('salt-domain',
      `Info "TLS 1.3 derived":  ${r.tls}\nInfo "file encryption": ${r.file}\n\nIdentical: ${r.match ? 'YES' : 'NO — domain separation ensures independent keys'}`);
    announce('salt-live', 'Domain separation demonstration complete');
  });

  const note = infoBox(
    'A KDF without salt means identical passwords always produce identical outputs — enabling rainbow table attacks. ' +
    'Random salt ensures each derivation is unique. HKDF info strings enable context binding and domain separation: ' +
    'keys for different purposes are derived with different context so they are cryptographically independent.'
  );

  return panel('panel-salt',
    heading, note, live,
    el('div', { className: 'salt-demos' },
      el('div', { className: 'salt-demo-group' },
        el('h3', {}, 'Rainbow Table Attack'), noSaltBtn, outputBox('salt-nosalt', 'No-salt comparison')),
      el('div', { className: 'salt-demo-group' },
        el('h3', {}, 'Salt Protection'), saltBtn, outputBox('salt-withsalt', 'Salted comparison')),
      el('div', { className: 'salt-demo-group' },
        el('h3', {}, 'HKDF Context Binding'), ctxBtn, outputBox('salt-context', 'Context binding')),
      el('div', { className: 'salt-demo-group' },
        el('h3', {}, 'Domain Separation'), domBtn, outputBox('salt-domain', 'Domain separation')),
    ),
  );
}

/* ------------------------------------------------------------------ */
/*  Theme toggle                                                      */
/* ------------------------------------------------------------------ */

function buildThemeToggle(): HTMLElement {
  const isDark = () => document.documentElement.getAttribute('data-theme') !== 'light';

  const btn = el('button', {
    className: 'theme-toggle',
    'aria-label': isDark() ? 'Switch to light mode' : 'Switch to dark mode',
    id: 'theme-toggle',
  });
  btn.setAttribute('style', 'position: absolute; top: 0; right: 0');
  btn.textContent = isDark() ? '🌙' : '☀️';

  btn.addEventListener('click', () => {
    const newTheme = isDark() ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    btn.textContent = newTheme === 'dark' ? '🌙' : '☀️';
    btn.setAttribute('aria-label', newTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  });

  return btn;
}

/* ------------------------------------------------------------------ */
/*  Header / Footer / Cross-links                                     */
/* ------------------------------------------------------------------ */

function buildHeader(): HTMLElement {
  const header = el('header', { className: 'site-header' });
  const chip = el('span', { className: 'category-chip' }, 'KDF');
  const title = el('h1', { className: 'site-title' }, chip, ' KDF Chain');
  const subtitle = el('p', { className: 'site-subtitle' }, 'Interactive key derivation function comparison');
  const primitives = el('div', { className: 'primitive-chips', 'aria-label': 'Cryptographic primitives used' },
    ...['HKDF', 'PBKDF2', 'scrypt', 'Argon2id', 'HMAC-SHA-256'].map(p =>
      el('span', { className: 'primitive-chip' }, p)));
  header.append(buildThemeToggle(), title, subtitle, primitives);
  return header;
}

function buildWhySection(): HTMLElement {
  const sec = el('section', { className: 'why-section', 'aria-labelledby': 'why-heading' });
  sec.innerHTML = `
    <h2 id="why-heading">Why This Matters</h2>
    <p>Billions of leaked passwords are cracked because developers chose the wrong KDF — PBKDF2 with low iterations
    or unsalted MD5 is still found in production breaches in 2026. The difference between HKDF, PBKDF2, scrypt, and
    Argon2id is not academic; it determines how expensive an attacker's offline search becomes.</p>`;
  return sec;
}

function buildCrossLinks(): HTMLElement {
  const links = [
    { href: 'https://systemslibrarian.github.io/crypto-lab-shadow-vault/', label: 'Shadow Vault' },
    { href: 'https://systemslibrarian.github.io/crypto-lab-ratchet-wire/', label: 'Ratchet Wire' },
    { href: 'https://systemslibrarian.github.io/crypto-lab-mac-race/', label: 'MAC Race' },
    { href: 'https://github.com/systemslibrarian/crypto-compare', label: 'crypto-compare' },
  ];
  const nav = el('nav', { className: 'cross-links', 'aria-label': 'Related crypto demos' });
  nav.append(el('span', { className: 'cross-label' }, 'Related:'));
  links.forEach(l => {
    nav.append(el('a', { href: l.href, className: 'cross-link', target: '_blank', rel: 'noopener noreferrer' }, l.label));
  });
  return nav;
}

function buildFooter(): HTMLElement {
  const footer = el('footer', { className: 'site-footer' });
  footer.append(
    el('a', {
      href: 'https://github.com/systemslibrarian/crypto-lab-kdf-chain',
      className: 'github-badge',
      target: '_blank',
      rel: 'noopener noreferrer',
      'aria-label': 'View source on GitHub',
    }, '⬡ GitHub'),
    el('p', { className: 'footer-verse' },
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31'),
  );
  return footer;
}

/* ------------------------------------------------------------------ */
/*  Init                                                              */
/* ------------------------------------------------------------------ */

export function initUI() {
  const app = document.getElementById('app')!;
  app.innerHTML = '';
  app.append(
    buildHeader(),
    buildWhySection(),
    el('main', { className: 'panels', role: 'main' },
      buildHkdfPanel(),
      buildPbkdf2Panel(),
      buildScryptPanel(),
      buildArgon2Panel(),
      buildDecisionPanel(),
      buildSaltPanel(),
    ),
    buildCrossLinks(),
    buildFooter(),
  );
}
