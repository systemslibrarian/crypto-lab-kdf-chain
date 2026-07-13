/**
 * ui.ts — Panel controller for six-panel KDF demo
 * Handles DOM creation, event binding, and result rendering
 */

import { hkdf } from './hkdf.ts';
import { pbkdf2Sha256, pbkdf2Sha512, pbkdf2Benchmark, pbkdf2Chain } from './pbkdf2.ts';
import { deriveScrypt } from './scrypt.ts';
import { deriveArgon2id } from './argon2.ts';
import { decide, comparisonTable, type DecisionResult } from './decision.ts';
import { demoNoSalt, demoWithSalt, demoContextBinding, demoDomainSeparation } from './salt.ts';
import { deriveChain } from './chain.ts';
import { vectors } from './vectors.ts';
import {
  pbkdf2Attack, scryptAttack, argon2Attack,
  TARGETS, crackSummary, type Target,
} from './attack.ts';

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

/**
 * An inline term with a plain-language gloss. Renders the acronym followed by a
 * short parenthetical so a newcomer meets the definition the first time the word
 * appears, while the acronym stays visible for the professional. Also carries a
 * `title` so the gloss is available on hover/focus for the full form.
 */
function glossTerm(term: string, gloss: string): HTMLElement {
  const span = el('span', { className: 'gloss', title: `${term}: ${gloss}` }, term);
  span.append(el('span', { className: 'gloss-def' }, ` (${gloss})`));
  return span;
}

/** Short truncation of a hex string for compact diagram chips. */
function shortHex(hex: string, keep = 16): string {
  if (hex.length <= keep + 3) return hex;
  return `${hex.slice(0, keep)}…`;
}

/**
 * A collapsible "assumptions" note rendered with native <details> so it is
 * keyboard-accessible and needs no custom ARIA. Used to put the attacker-cost
 * model's inputs right next to the scary numbers instead of only in the README.
 */
function assumptionsNote(summary: string, ...body: (string | Node)[]): HTMLElement {
  const d = el('details', { className: 'assumptions' });
  d.append(el('summary', {}, summary), el('div', { className: 'assumptions-body' }, ...body));
  return d;
}

function timingDisplay(id: string): HTMLElement {
  return el('div', { className: 'timing', id, 'aria-live': 'polite' }, '');
}

/** Labelled <select> populated from the shared TARGETS list. */
function targetSelect(id: string): HTMLElement {
  const wrap = el('div', { className: 'input-group' });
  const lbl = el('label', { 'for': id }, 'Attacker target password');
  const sel = el('select', { id, className: 'input-field', 'aria-label': 'Attacker target password' });
  TARGETS.forEach((t, i) => {
    const opt = el('option', { value: String(i) }, t.label);
    if (i === 0) opt.setAttribute('selected', 'selected');
    sel.append(opt);
  });
  wrap.append(lbl, sel);
  return wrap;
}

function readTarget(id: string): Target {
  const sel = document.getElementById(id) as HTMLSelectElement | null;
  return TARGETS[sel ? parseInt(sel.value, 10) : 0] ?? TARGETS[0];
}

/** Output region for an attacker-cost projection (styled, aria-live). */
function attackBox(id: string): HTMLElement {
  const wrap = el('div', { className: 'attack-group' });
  const lbl = el('span', { className: 'output-label' }, '⚔️ Attacker cost (offline GPU search)');
  const box = el('pre', {
    className: 'attack-out', id,
    'aria-label': 'Attacker cost estimate', 'aria-live': 'polite', tabindex: '0',
  }, 'Derive a key to estimate attacker cost.');
  wrap.append(lbl, box, attackerAssumptions());
  return wrap;
}

/**
 * The attacker-cost model's assumptions, shown INLINE next to the scary numbers
 * (previously only in the README). Keeps the honesty the RFC-vectors panel
 * establishes: precise-looking crack times without visible inputs teach false
 * certainty. Collapsed by default so it doesn't crowd the primary readout.
 */
function attackerAssumptions(): HTMLElement {
  return assumptionsNote(
    'Assumptions behind these numbers (order-of-magnitude estimate, not a proof)',
    el('ul', { className: 'assumptions-list' },
      el('li', {}, 'Hardware: one RTX 4090-class GPU — ~22 GH/s raw SHA-256, ~1 TB/s memory bandwidth (published specs).'),
      el('li', {}, 'Average case: attacker finds the password after searching half the keyspace (keyspace ÷ 2).'),
      el('li', {}, 'ASIC advantage: ~5000× for compute-bound PBKDF2 (cheap SHA cores), but only ~5× for memory-bound scrypt/Argon2id — memory bandwidth resists custom silicon.'),
      el('li', {}, 'Farm = 1,000 such GPUs in perfect parallel. Real attacks vary with wordlists, rig efficiency, and price; treat these as ballpark, not guarantees.'),
    ),
  );
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

  const diagram = buildHkdfDiagram();

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
      // Feed the real computed bytes into the two-phase diagram so the animation
      // shows THIS derivation, never a canned value.
      renderHkdfDiagram({ salt: salt || '(none → zero-filled)', ikm, info, prkHex: r.prkHex, blocks: r.blocks });
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
    diagram,
    el('h3', {}, 'Extract Phase'),
    outputBox('hkdf-prk', 'PRK = HMAC-SHA-256(salt, IKM)'),
    el('h3', {}, 'Expand Phase'),
    outputBox('hkdf-okm', 'Output Key Material (OKM)'),
    outputBox('hkdf-blocks', 'Expand Blocks T(i)'),
  );
}

/**
 * Static skeleton for the HKDF extract→expand diagram. It teaches the MECHANISM
 * behind the hex: two boxes labelled in plain words ("condense entropy" /
 * "stretch to length"), an HMAC box in each phase, and an expand loop that shows
 * T(i-1)||info||counter feeding back into HMAC. Filled by renderHkdfDiagram with
 * the real bytes from the last derivation.
 */
function buildHkdfDiagram(): HTMLElement {
  const wrap = el('section', { className: 'hkdf-diagram', 'aria-labelledby': 'hkdf-diagram-h' });
  wrap.append(
    el('h3', { id: 'hkdf-diagram-h', className: 'diagram-h' }, 'How it works: extract, then expand'),
    el('p', { className: 'diagram-lead' },
      'Two phases. ',
      el('strong', {}, 'Extract'),
      ' condenses whatever entropy your inputs have into one fixed-size random-looking seed. ',
      el('strong', {}, 'Expand'),
      ' stretches that seed to any length you asked for, one HMAC block at a time. Derive a key above to watch your bytes flow through.',
    ),
    // Extract phase
    el('div', { className: 'hkdf-phase' },
      el('div', { className: 'hkdf-phase-tag' }, 'PHASE 1 · EXTRACT — condense entropy'),
      el('div', { className: 'hkdf-flow' },
        el('div', { className: 'hkdf-box hkdf-in', id: 'hkdf-d-salt' },
          el('span', { className: 'hkdf-box-k' }, 'salt (the HMAC key)'),
          el('span', { className: 'hkdf-box-v', id: 'hkdf-d-salt-v' }, '—')),
        el('div', { className: 'hkdf-box hkdf-in', id: 'hkdf-d-ikm' },
          el('span', { className: 'hkdf-box-k' }, 'IKM — the secret you start with'),
          el('span', { className: 'hkdf-box-v', id: 'hkdf-d-ikm-v' }, '—')),
        el('div', { className: 'hkdf-op', 'aria-hidden': 'true' }, 'HMAC-SHA-256'),
        el('div', { className: 'hkdf-box hkdf-prk', id: 'hkdf-d-prk' },
          el('span', { className: 'hkdf-box-k' }, 'PRK — a condensed random seed'),
          el('span', { className: 'hkdf-box-v', id: 'hkdf-d-prk-v' }, '—')),
      ),
    ),
    // Expand phase
    el('div', { className: 'hkdf-phase' },
      el('div', { className: 'hkdf-phase-tag' }, 'PHASE 2 · EXPAND — stretch to length'),
      el('p', { className: 'hkdf-expand-formula' },
        'Each block: T(i) = HMAC(PRK, ',
        el('span', { className: 'hkdf-term' }, 'T(i-1)'),
        ' ‖ ',
        el('span', { className: 'hkdf-term' }, 'info'),
        ' ‖ ',
        el('span', { className: 'hkdf-term' }, 'i'),
        '). The previous block feeds the next — that feedback is what makes the output as long as you need.',
      ),
      el('div', { className: 'hkdf-expand-blocks', id: 'hkdf-d-blocks', role: 'list', 'aria-label': 'HKDF expand blocks' },
        el('p', { className: 'hkdf-empty' }, 'Derive a key to see T(1), T(2), … build up.')),
    ),
  );
  return wrap;
}

/** Fill and briefly animate the HKDF diagram with real derivation bytes. */
function renderHkdfDiagram(d: { salt: string; ikm: string; info: string; prkHex: string; blocks: string[] }): void {
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const setV = (id: string, txt: string) => { const e = document.getElementById(id); if (e) e.textContent = txt; };
  setV('hkdf-d-salt-v', d.salt.length > 40 ? `${d.salt.slice(0, 40)}…` : (d.salt || '(empty)'));
  setV('hkdf-d-ikm-v', d.ikm.length > 40 ? `${d.ikm.slice(0, 40)}…` : (d.ikm || '(empty)'));
  setV('hkdf-d-prk-v', shortHex(d.prkHex, 32));

  const box = document.getElementById('hkdf-d-blocks');
  if (!box) return;
  box.innerHTML = '';
  d.blocks.forEach((b, i) => {
    const prev = i === 0 ? 'T(0) = empty' : `T(${i})`;
    const block = el('div', { className: 'hkdf-block', role: 'listitem' },
      el('span', { className: 'hkdf-block-h' }, `T(${i + 1})`),
      el('span', { className: 'hkdf-block-feed' }, `HMAC(PRK, ${prev} ‖ info ‖ ${i + 1})`),
      el('span', { className: 'hkdf-block-v' }, shortHex(b, 32)),
    );
    box.append(block);
    if (!reduce) {
      block.classList.add('hkdf-block-enter');
      setTimeout(() => block.classList.remove('hkdf-block-enter'), 30 + i * 140);
    }
  });
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
    targetSelect('pbkdf2-target'),
  );

  const live = liveRegion('pbkdf2-live');
  const timing = timingDisplay('pbkdf2-timing');
  const chainViz = buildPbkdf2ChainViz();

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
      setOutput('pbkdf2-attack', crackSummary(pbkdf2Attack(iter, 'SHA-256'), readTarget('pbkdf2-target')));
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
    'PBKDF2 is embarrassingly parallel (one guess needs no memory, so a GPU runs thousands at once). ' +
    'OWASP recommends minimum 600,000 iterations for PBKDF2-HMAC-SHA-256. ' +
    'Prefer Argon2id for new systems. Iteration chain: U₁, U₂, … Uₙ XORed together — shown live below.'
  );

  return panel('panel-pbkdf2',
    heading, note, form, derivBtn, benchBtn, live, timing,
    chainViz,
    outputBox('pbkdf2-sha256', 'PBKDF2-HMAC-SHA-256'),
    outputBox('pbkdf2-sha512', 'PBKDF2-HMAC-SHA-512'),
    outputBox('pbkdf2-bench', 'Benchmark Results'),
    attackBox('pbkdf2-attack'),
  );
}

/**
 * Live PBKDF2 iteration-chain visual. A dedicated slider (1…16 iterations, kept
 * small so every link is visible and the XOR is legible) drives a real
 * pbkdf2Chain() computation for output block 1: each U_j link and the running
 * XOR accumulator T_1 are shown, so raising the count visibly adds links and
 * folds more work into the same block. This is the mechanism the panel note has
 * always claimed but never showed.
 */
function buildPbkdf2ChainViz(): HTMLElement {
  const wrap = el('section', { className: 'pb-chain', 'aria-labelledby': 'pb-chain-h' });

  const slider = el('input', {
    id: 'pb-chain-iter', type: 'range', className: 'input-field',
    min: '1', max: '16', value: '4', step: '1', 'aria-label': 'Iterations to visualize',
  });
  const valSpan = el('span', { className: 'range-value', id: 'pb-chain-iter-value', 'aria-live': 'polite' }, '4');
  const ctrl = el('div', { className: 'input-group pb-chain-ctrl' },
    el('label', { 'for': 'pb-chain-iter' }, 'Iterations to visualize (c)'),
    slider, valSpan);

  const links = el('div', { className: 'pb-links', id: 'pb-links', role: 'list', 'aria-label': 'PBKDF2 iteration links' });
  const accBox = el('div', { className: 'pb-acc', id: 'pb-acc' },
    el('span', { className: 'pb-acc-k' }, 'T₁ = U₁ ⊕ U₂ ⊕ … (running XOR — the block PBKDF2 actually outputs)'),
    el('span', { className: 'pb-acc-v', id: 'pb-acc-v' }, '—'));

  const render = async () => {
    const c = parseInt(slider.value, 10) || 1;
    valSpan.textContent = String(c);
    const pw = (document.getElementById('pbkdf2-pw') as HTMLInputElement)?.value ?? 'correct horse battery staple';
    const salt = (document.getElementById('pbkdf2-salt') as HTMLInputElement)?.value ?? 'unique-random-salt';
    const res = await pbkdf2Chain(pw, salt, c, 16);
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    links.innerHTML = '';
    res.steps.forEach((s, i) => {
      const src = s.j === 1 ? 'HMAC(pw, salt ‖ INT(1))' : `HMAC(pw, U${s.j - 1})`;
      const node = el('div', { className: 'pb-link', role: 'listitem' },
        el('span', { className: 'pb-link-h' }, `U${s.j}`),
        el('span', { className: 'pb-link-src' }, src),
        el('span', { className: 'pb-link-v' }, shortHex(s.uHex, 24)),
      );
      links.append(node);
      if (!reduce) {
        node.classList.add('pb-link-enter');
        setTimeout(() => node.classList.remove('pb-link-enter'), 30 + i * 90);
      }
    });
    const accV = document.getElementById('pb-acc-v');
    if (accV) accV.textContent = shortHex(res.finalHex, 32);
    announce('pbkdf2-live',
      `${c} iteration${c === 1 ? '' : 's'}: ${c} link${c === 1 ? '' : 's'} XORed into one output block.`);
  };

  slider.addEventListener('input', () => { void render(); });
  // Render once on load so the panel isn't empty before first interaction.
  queueMicrotask(() => { void render(); });

  wrap.append(
    el('h3', { id: 'pb-chain-h', className: 'diagram-h' }, 'How it works: the iteration chain'),
    el('p', { className: 'diagram-lead' },
      'PBKDF2 makes one guess expensive by hashing in a chain: U₁ = HMAC(password, salt), then each ',
      'U feeds the next — U₂ = HMAC(password, U₁), and so on. All the links are XORed together into the ',
      'output block. More iterations = a longer chain = more work per guess, for you AND the attacker. ',
      'Slide to add links (kept small here so the chain stays readable; real PBKDF2 runs hundreds of thousands).',
    ),
    ctrl,
    el('div', { className: 'pb-chain-body' }, links, accBox),
  );
  return wrap;
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
    targetSelect('scrypt-target'),
  );

  const live = liveRegion('scrypt-live');
  const timing = timingDisplay('scrypt-timing');

  const derivBtn = button('Derive Key', 'Derive scrypt key', async () => {
    const pw = (document.getElementById('scrypt-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('scrypt-salt') as HTMLInputElement).value;
    const N = parseInt((document.getElementById('scrypt-n') as HTMLInputElement).value, 10) || 16384;
    const r = parseInt((document.getElementById('scrypt-r') as HTMLInputElement).value, 10) || 8;
    const p = parseInt((document.getElementById('scrypt-p') as HTMLInputElement).value, 10) || 1;
    const len = parseInt((document.getElementById('scrypt-len') as HTMLInputElement).value, 10) || 32;
    try {
      const res = await deriveScrypt(pw, salt, N, r, p, len);
      setOutput('scrypt-out', res.hex);
      document.getElementById('scrypt-timing')!.textContent =
        `Derived in ${res.timeMs.toFixed(2)} ms | Memory estimate: ${res.memoryEstimateMB.toFixed(2)} MB`;
      setOutput('scrypt-attack', crackSummary(scryptAttack(N, r), readTarget('scrypt-target')));
      announce('scrypt-live', `scrypt derivation complete in ${res.timeMs.toFixed(2)} ms, estimated memory ${res.memoryEstimateMB.toFixed(2)} MB`);
    } catch (err) {
      announce('scrypt-live', `Error: ${(err as Error).message}`);
    }
  });

  const benchBtn = button('Compare N values (2¹⁴ vs 2¹⁷ vs 2²⁰)', 'Benchmark scrypt at different N values', async () => {
    const pw = (document.getElementById('scrypt-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('scrypt-salt') as HTMLInputElement).value;
    const r = parseInt((document.getElementById('scrypt-r') as HTMLInputElement).value, 10) || 8;
    const p = parseInt((document.getElementById('scrypt-p') as HTMLInputElement).value, 10) || 1;
    const len = parseInt((document.getElementById('scrypt-len') as HTMLInputElement).value, 10) || 32;
    announce('scrypt-live', 'Running N-value comparison…');
    try {
      const results: (Awaited<ReturnType<typeof deriveScrypt>> | null)[] = [];
      for (const N of [2 ** 14, 2 ** 17, 2 ** 20]) {
        try { results.push(await deriveScrypt(pw, salt, N, r, p, len)); }
        catch { results.push(null); }
      }
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
    'scrypt fills a big array of pseudorandom blocks, then reads them back in a password-dependent order that a GPU ' +
    'cannot predict or skip (RFC 7914 calls these steps ROMix — the fill-then-shuffle-read loop — and BlockMix — the ' +
    'per-block mixing function). Memory access patterns resist GPU attacks because GPUs have limited on-chip memory per ' +
    'core. Memory estimate: 128 × N × r bytes (RFC 7914 §2).'
  );

  return panel('panel-scrypt',
    heading, note, form, derivBtn, benchBtn, live, timing,
    outputBox('scrypt-out', 'Derived Key'),
    outputBox('scrypt-bench', 'N-value Comparison'),
    attackBox('scrypt-attack'),
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
    targetSelect('argon2-target'),
  );

  const live = liveRegion('argon2-live');
  const timing = timingDisplay('argon2-timing');

  const derivBtn = button('Derive Key', 'Derive Argon2id key', async () => {
    const pw = (document.getElementById('argon2-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('argon2-salt') as HTMLInputElement).value;
    const t = parseInt((document.getElementById('argon2-t') as HTMLInputElement).value, 10) || 2;
    const m = parseInt((document.getElementById('argon2-m') as HTMLInputElement).value, 10) || 19456;
    const p = parseInt((document.getElementById('argon2-p') as HTMLInputElement).value, 10) || 1;
    const dkLen = parseInt((document.getElementById('argon2-len') as HTMLInputElement).value, 10) || 32;
    try {
      const res = await deriveArgon2id(pw, salt, t, m, p, dkLen);
      setOutput('argon2-out', res.hex);
      document.getElementById('argon2-timing')!.textContent =
        `Derived in ${res.timeMs.toFixed(2)} ms | Memory: ${(m / 1024).toFixed(1)} MiB`;
      setOutput('argon2-attack', crackSummary(argon2Attack(t, m), readTarget('argon2-target')));
      announce('argon2-live', `Argon2id derivation complete in ${res.timeMs.toFixed(2)} milliseconds`);
    } catch (err) {
      announce('argon2-live', `Error: ${(err as Error).message}`);
    }
  });

  const note = infoBox(
    'Argon2id combines two memory-access styles: data-dependent (where to read next depends on the secret — harder for ' +
    'GPUs, but the access pattern can leak via side-channels) and data-independent (a fixed, secret-free pattern — ' +
    'side-channel safe, but a bit weaker against GPUs). ' +
    'Argon2id uses the data-independent style for the first pass and the data-dependent style thereafter — the best of both. ' +
    'OWASP recommends: t=2, m=19456 (19 MiB), p=1. Memory cost makes ASIC/GPU attacks economically impractical.'
  );

  return panel('panel-argon2',
    heading, note, form, derivBtn, live, timing,
    outputBox('argon2-out', 'Derived Key (Argon2id)'),
    attackBox('argon2-attack'),
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
    el('legend', {}, '3. Are you in a legacy or FIPS-constrained environment? (FIPS = US government crypto-approval standard; it only blesses older KDFs like PBKDF2)'),
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
/*  Panel 7 — The KDF Chain                                           */
/* ------------------------------------------------------------------ */

function buildChainPanel(): HTMLElement {
  const heading = sectionHeading('The KDF Chain: Stretch then Fan Out', statusChip('RECOMMENDED DEFAULT'), 'RFC 9106 + RFC 5869');
  heading.querySelector('h2')!.id = 'panel-chain-title';

  const form = el('div', { className: 'panel-form' },
    inputGroup('chain-pw', 'Password', 'text', 'correct horse battery staple'),
    inputGroup('chain-salt', 'Salt (min 8 chars)', 'text', 'random-salt-value-16'),
    inputGroup('chain-info1', 'Derived key 1 — info string', 'text', 'encryption key'),
    inputGroup('chain-info2', 'Derived key 2 — info string', 'text', 'MAC key'),
    inputGroup('chain-info3', 'Derived key 3 — info string', 'text', 'vault storage key'),
  );

  const live = liveRegion('chain-live');
  const timing = timingDisplay('chain-timing');
  const flow = el('div', { id: 'chain-flow', className: 'chain-flow', 'aria-live': 'polite' });

  const runBtn = button('Run the Chain', 'Run the KDF chain: Argon2id then HKDF-Expand fan-out', async () => {
    const pw = (document.getElementById('chain-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('chain-salt') as HTMLInputElement).value;
    const infos = ['chain-info1', 'chain-info2', 'chain-info3']
      .map(id => (document.getElementById(id) as HTMLInputElement).value)
      .filter(s => s.trim().length > 0);
    announce('chain-live', 'Running KDF chain…');
    try {
      const r = await deriveChain(pw, salt, infos);
      flow.innerHTML = '';
      flow.append(
        chainNode('step', 'Password', pw || '(empty)', 'low entropy — must be stretched'),
        chainArrow('Argon2id  (t=2, m=19 MiB, p=1)  —  slow & memory-hard'),
        chainNode('root', 'Root key', r.rootHex, `expensive step, done once · ${r.argonTimeMs.toFixed(1)} ms`),
        chainArrow('HKDF-Expand  —  cheap, one call per context (info string)'),
        el('div', { className: 'chain-fanout' },
          ...r.links.map(link =>
            chainNode('leaf', `info = "${link.info}"`, link.keyHex, 'independent, domain-separated'))),
      );
      document.getElementById('chain-timing')!.textContent =
        `Whole chain: ${r.totalTimeMs.toFixed(2)} ms (${r.links.length} keys from one password)`;
      announce('chain-live', `Chain complete. ${r.links.length} independent keys derived in ${r.totalTimeMs.toFixed(0)} milliseconds`);
    } catch (err) {
      announce('chain-live', `Error: ${(err as Error).message}`);
    }
  });

  const note = infoBox(
    'This is the pattern the project is named for, and how TLS 1.3, Signal, and password vaults actually work. ' +
    'Argon2id pays the expensive, memory-hard cost once to turn a weak password into a high-entropy root key. ' +
    'HKDF-Expand then cheaply fans that root out into as many independent keys as you need — one per context — ' +
    'so a leak of the MAC key can never expose the encryption key. Change any info string and that key changes completely.'
  );

  return panel('panel-chain', heading, note, form, runBtn, live, timing, flow);
}

function chainNode(kind: string, label: string, value: string, sub: string): HTMLElement {
  return el('div', { className: `chain-node chain-${kind}` },
    el('span', { className: 'chain-node-label' }, label),
    el('pre', { className: 'chain-node-value', tabindex: '0', 'aria-label': `${label} value` }, value),
    el('span', { className: 'chain-node-sub' }, sub),
  );
}

function chainArrow(text: string): HTMLElement {
  return el('div', { className: 'chain-arrow', 'aria-hidden': 'false' },
    el('span', { className: 'chain-arrow-glyph', 'aria-hidden': 'true' }, '↓'),
    el('span', { className: 'chain-arrow-label' }, text),
  );
}

/* ------------------------------------------------------------------ */
/*  Panel 8 — Cost Comparison (unified run)                           */
/* ------------------------------------------------------------------ */

function buildCostPanel(): HTMLElement {
  const heading = sectionHeading('Cost Comparison: One Password, Every KDF', statusChip('GUIDE'), '');
  heading.querySelector('h2')!.id = 'panel-cost-title';

  const form = el('div', { className: 'panel-form' },
    inputGroup('cost-pw', 'Password', 'text', 'correct horse battery staple'),
    inputGroup('cost-salt', 'Salt', 'text', 'unique-random-salt'),
    targetSelect('cost-target'),
  );

  const live = liveRegion('cost-live');
  const bars = el('div', { id: 'cost-bars', className: 'cost-bars', role: 'list', 'aria-label': 'KDF cost comparison' });

  const runBtn = button('Run All KDFs', 'Run the same password through every password KDF and compare', async () => {
    const pw = (document.getElementById('cost-pw') as HTMLInputElement).value;
    const salt = (document.getElementById('cost-salt') as HTMLInputElement).value;
    const target = readTarget('cost-target');
    announce('cost-live', 'Running every KDF…');
    bars.innerHTML = '';
    try {
      const pb100 = await pbkdf2Sha256(pw, salt, 100_000, 32);
      const pb600 = await pbkdf2Sha256(pw, salt, 600_000, 32);
      const sc = await deriveScrypt(pw, salt, 16384, 8, 1, 32);
      const ar = await deriveArgon2id(pw, salt.padEnd(8, '0'), 2, 19456, 1, 32);

      const rows = [
        { name: 'PBKDF2 (100k)', ms: pb100.timeMs, est: pbkdf2Attack(100_000, 'SHA-256'), warn: true },
        { name: 'PBKDF2 (600k)', ms: pb600.timeMs, est: pbkdf2Attack(600_000, 'SHA-256'), warn: false },
        { name: 'scrypt (N=2¹⁴)', ms: sc.timeMs, est: scryptAttack(16384, 8), warn: false },
        { name: 'Argon2id (19 MiB)', ms: ar.timeMs, est: argon2Attack(2, 19456), warn: false },
      ];
      const maxMs = Math.max(...rows.map(r => r.ms));
      rows.forEach(r => bars.append(costBar(r.name, r.ms, maxMs, crackSummary(r.est, target), r.warn)));
      announce('cost-live', `Comparison complete for ${rows.length} KDFs against ${target.label}`);
    } catch (err) {
      announce('cost-live', `Error: ${(err as Error).message}`);
    }
  });

  const note = infoBox(
    'The same password and salt run through every password KDF. The bar shows YOUR cost (one derivation); ' +
    'the line below shows the ATTACKER’s cost for the selected target. Notice that a small change in your ' +
    'time buys an enormous change in theirs — and that memory-hard KDFs (scrypt, Argon2id) deny the GPU the ' +
    'cheap parallelism that makes PBKDF2 crackable.'
  );

  return panel('panel-cost', heading, note, form, runBtn, live, bars);
}

function costBar(name: string, ms: number, maxMs: number, summary: string, warn: boolean): HTMLElement {
  const pct = Math.max(4, Math.round((ms / maxMs) * 100));
  const row = el('div', { className: 'cost-row', role: 'listitem' });
  const head = el('div', { className: 'cost-row-head' },
    el('span', { className: 'cost-name' }, name),
    el('span', { className: 'cost-ms' }, `${ms.toFixed(1)} ms`),
  );
  const track = el('div', { className: 'cost-track' });
  const fill = el('div', { className: `cost-fill${warn ? ' cost-fill-warn' : ''}` });
  fill.setAttribute('style', `width: ${pct}%`);
  fill.setAttribute('role', 'img');
  fill.setAttribute('aria-label', `${name}: ${ms.toFixed(1)} milliseconds to derive`);
  track.append(fill);
  const attack = el('p', { className: 'cost-attack' }, summary);
  row.append(head, track, attack);
  return row;
}

/* ------------------------------------------------------------------ */
/*  Panel 9 — RFC Known-Answer Tests                                  */
/* ------------------------------------------------------------------ */

function buildVectorsPanel(): HTMLElement {
  const heading = sectionHeading('Proof: RFC Known-Answer Tests', statusChip('GUIDE'), 'RFC 5869 · RFC 7914');
  heading.querySelector('h2')!.id = 'panel-vectors-title';

  const live = liveRegion('vectors-live');
  const results = el('div', { id: 'vectors-results', className: 'vectors-results', 'aria-live': 'polite' });

  const runBtn = button('Run Test Vectors', 'Verify this demo against published RFC test vectors', async () => {
    announce('vectors-live', 'Running RFC test vectors…');
    results.innerHTML = '';
    let allPass = true;
    for (const group of vectors) {
      try {
        const rows = await group.run();
        rows.forEach(r => {
          if (!r.pass) allPass = false;
          results.append(vectorRow(r));
        });
      } catch (err) {
        allPass = false;
        results.append(el('div', { className: 'vector-row vector-fail' },
          el('span', { className: 'vector-badge' }, 'ERROR'),
          el('span', {}, `${group.name}: ${(err as Error).message}`)));
      }
    }
    announce('vectors-live', allPass ? 'All RFC test vectors passed' : 'Some RFC test vectors failed');
  });

  const note = infoBox(
    'Cryptographic standards ship their own test vectors. This panel recomputes published RFC vectors in your ' +
    'browser and checks them byte-for-byte — so you can trust that the HKDF and PBKDF2 here are the real, ' +
    'standards-conformant algorithms, not look-alikes.'
  );

  return panel('panel-vectors', heading, note, runBtn, live, results);
}

function vectorRow(r: { ref: string; field: string; expected: string; got: string; pass: boolean }): HTMLElement {
  const row = el('div', { className: `vector-row ${r.pass ? 'vector-pass' : 'vector-fail'}` });
  const badge = el('span', {
    className: 'vector-badge',
    'aria-label': r.pass ? 'Pass' : 'Fail',
  }, r.pass ? '✅ PASS' : '❌ FAIL');
  const title = el('span', { className: 'vector-title' }, `${r.ref} — ${r.field}`);
  const detail = el('pre', { className: 'vector-detail', tabindex: '0' },
    `expected: ${r.expected}\n   got:  ${r.got}`);
  row.append(el('div', { className: 'vector-row-head' }, badge, title), detail);
  return row;
}

/* ------------------------------------------------------------------ */
/*  Header / Footer / Cross-links                                     */
/* ------------------------------------------------------------------ */

function buildHeader(): HTMLElement {
  // Fleet cl-hero standard: title block on the left, "why it matters" on the right.
  const header = el('header', { className: 'cl-hero' });

  const main = el('div', { className: 'cl-hero-main' });
  const title = el('h1', { className: 'cl-hero-title' }, 'KDF Chain');
  const sub = el('p', { className: 'cl-hero-sub' }, 'HKDF · PBKDF2 · scrypt · Argon2id');
  const desc = el('p', { className: 'cl-hero-desc' },
    'Derive keys with four KDFs side by side — stretch a low-entropy password, expand a high-entropy secret, and fan one root out into many keys, with live timing and RFC test vectors.');
  main.append(title, sub, desc);

  const why = el('aside', { className: 'cl-hero-why', 'aria-label': 'Why it matters' });
  why.append(
    el('span', { className: 'cl-hero-why-label' }, 'WHY IT MATTERS'),
    el('p', { className: 'cl-hero-why-text' },
      'The wrong KDF is why leaked password databases still get cracked. Salt, memory-hardness, and domain separation decide how ruinously expensive an attacker’s offline guessing becomes.'),
  );

  header.append(main, why);
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

function buildGuide(): HTMLElement {
  const sec = el('section', { className: 'guide-section', 'aria-labelledby': 'guide-heading' });
  const steps: [string, string, string][] = [
    ['#panel-hkdf', 'Start with the split', 'Every KDF answers one of two needs: expand a high-entropy secret (HKDF) or stretch a low-entropy password. See HKDF first.'],
    ['#panel-pbkdf2', 'Stretch a password', 'Try PBKDF2, then scrypt and Argon2id. Watch the derivation time — and the attacker-cost line beneath each.'],
    ['#panel-memory', 'See why memory wins', 'Understand why scrypt and Argon2id beat GPUs where PBKDF2 fails: the memory-hardness visual.'],
    ['#panel-chain', 'Build the real thing', 'The KDF chain: stretch a password once with Argon2id, then fan it out into many independent keys with HKDF.'],
    ['#panel-cost', 'Compare the costs', 'Run one password through every KDF and compare your cost against the attacker’s.'],
    ['#panel-vectors', 'Prove it’s real', 'Recompute the RFCs’ own test vectors in your browser, checked byte-for-byte.'],
  ];
  const list = el('ol', { className: 'guide-steps' });
  steps.forEach(([href, title, desc], i) => {
    const link = el('a', { href, className: 'guide-step' },
      el('span', { className: 'guide-num', 'aria-hidden': 'true' }, String(i + 1)),
      el('span', { className: 'guide-step-body' },
        el('span', { className: 'guide-step-title' }, title),
        el('span', { className: 'guide-step-desc' }, desc)),
    );
    list.append(el('li', {}, link));
  });
  sec.append(
    el('h2', { id: 'guide-heading' }, 'Start Here — a Guided Path'),
    el('p', { className: 'guide-intro' }, 'New to KDFs? Follow these six steps in order. Already know your way around? Jump to any panel below.'),
    list,
  );
  return sec;
}

function buildMemoryHardnessPanel(): HTMLElement {
  const heading = sectionHeading('Why Memory Hardness Beats GPUs', statusChip('GUIDE'), '');
  heading.querySelector('h2')!.id = 'panel-memory-title';

  const note = infoBox(
    'A GPU is thousands of tiny, cheap compute cores. PBKDF2 is just hashing, so every core runs a separate ' +
    'password guess in parallel — the attack scales almost for free. scrypt and Argon2id force each guess to ' +
    'read and write a large block of memory in sequence. Memory bandwidth is shared and expensive, so the cores ' +
    'sit idle waiting for the bus. You cannot cheaply buy more bandwidth — which is why memory-hard KDFs resist ' +
    'GPUs and ASICs where PBKDF2 collapses. Turn up the memory cost below and watch the wait get worse.'
  );

  // Memory-cost control. Steps map to real, meaningful memory sizes so the
  // learner is tuning the same knob as scrypt's N and Argon2id's m, and the
  // grid scales to match — the animation now RESPONDS to their input.
  const MEM_STEPS = [
    { label: 'scrypt N=2¹², r=8 · 4 MiB', cells: 16 },
    { label: 'scrypt N=2¹⁴, r=8 · 16 MiB (default)', cells: 36 },
    { label: 'Argon2id m=19 MiB (OWASP)', cells: 49 },
    { label: 'Argon2id m=64 MiB (hardened)', cells: 81 },
    { label: 'scrypt N=2¹⁷, r=8 · 128 MiB', cells: 121 },
  ];
  const memSlider = el('input', {
    id: 'mem-cost', type: 'range', className: 'input-field',
    min: '0', max: String(MEM_STEPS.length - 1), value: '1', step: '1',
    'aria-label': 'Memory cost to visualize',
  });
  const memVal = el('span', { className: 'range-value', id: 'mem-cost-value', 'aria-live': 'polite' }, MEM_STEPS[1].label);
  const memCtrl = el('div', { className: 'input-group mem-cost-ctrl' },
    el('label', { 'for': 'mem-cost' }, 'Memory cost (N for scrypt · m for Argon2id)'),
    memSlider, memVal);

  // Compute-bound illustration: many busy cores, always fully lit.
  const cores = el('div', { className: 'mem-cores', 'aria-hidden': 'true' });
  for (let i = 0; i < 48; i++) cores.append(el('span', { className: 'mem-core' }));
  const computeCard = el('div', { className: 'mem-card' },
    el('h3', {}, 'PBKDF2 — compute-bound'),
    cores,
    el('p', { className: 'mem-caption' }, 'Every GPU core runs its own guess. Cheap to add thousands → embarrassingly parallel.'),
  );

  // Memory-bound illustration: a grid (sized to the chosen cost) that fills
  // sequentially, plus a row of 48 GPU cores that STALL while it fills.
  const grid = el('div', { id: 'mem-grid', className: 'mem-grid', 'aria-hidden': 'true' });
  const stalled = el('div', { className: 'mem-stall', 'aria-hidden': 'true' });
  for (let i = 0; i < 48; i++) stalled.append(el('span', { className: 'mem-core mem-core-stall' }));
  const memCard = el('div', { className: 'mem-card' },
    el('h3', {}, 'scrypt / Argon2id — memory-bound'),
    grid,
    el('p', { className: 'mem-caption', id: 'mem-cap' },
      'Each guess must stream this whole block through one shared memory bus.'),
    el('div', { className: 'mem-stall-wrap' },
      el('span', { className: 'mem-stall-label' }, 'GPU cores waiting on the bus:'),
      stalled),
  );

  // Build the grid for the current step and reset the stall state.
  const buildGrid = (cells: number) => {
    grid.innerHTML = '';
    const cols = Math.round(Math.sqrt(cells));
    grid.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
    for (let i = 0; i < cells; i++) grid.append(el('span', { className: 'mem-cell' }));
    stalled.classList.remove('mem-busy');
  };
  buildGrid(MEM_STEPS[1].cells);

  const live = liveRegion('mem-live');

  let timers: ReturnType<typeof setTimeout>[] = [];
  const runAnimation = () => {
    timers.forEach(clearTimeout);
    timers = [];
    const step = MEM_STEPS[parseInt(memSlider.value, 10) || 0];
    buildGrid(step.cells);
    const cells = Array.from(grid.querySelectorAll('.mem-cell')) as HTMLElement[];
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const cap = document.getElementById('mem-cap');
    if (reduce) {
      cells.forEach(c => c.classList.add('filled'));
      if (cap) cap.textContent =
        `${step.cells} memory cells to stream (${step.label}). Extra cores wait → no cheap parallelism.`;
      announce('mem-live', `Memory block filled — ${step.cells} cells must be touched per guess for ${step.label}.`);
      return;
    }
    // Fill duration scales with the chosen memory cost: bigger block, longer
    // wait, so poking the knob visibly changes the time. Per-cell delay eases
    // down as cells grow so the largest block stays watchable.
    const perCell = Math.max(14, 60 - step.cells * 0.35);
    stalled.classList.add('mem-busy');
    if (cap) cap.textContent =
      `Streaming ${step.cells} cells through one bus (${step.label}). While it fills, the 48 cores below stall.`;
    announce('mem-live', `Filling ${step.cells} memory cells one at a time — ${step.label}. Cores stall until it finishes.`);
    cells.forEach((c, i) => {
      timers.push(setTimeout(() => {
        c.classList.add('filled');
        if (i === cells.length - 1) {
          stalled.classList.remove('mem-busy');
          announce('mem-live', 'Memory block full. One guess done — and it cost the whole bus. Cores resume.');
        }
      }, i * perCell));
    });
  };

  memSlider.addEventListener('input', () => {
    const step = MEM_STEPS[parseInt(memSlider.value, 10) || 0];
    memVal.textContent = step.label;
    buildGrid(step.cells);
  });

  const animateBtn = button('Animate memory access', 'Animate sequential memory access for the selected memory cost', runAnimation);

  const grids = el('div', { className: 'mem-grids' }, computeCard, memCard);

  return panel('panel-memory', heading, note, memCtrl, grids, animateBtn, live);
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
    (() => {
      const related = el('nav', { className: 'cross-links', 'aria-label': 'Related demos' });
      related.append(el('span', { className: 'cross-label' }, 'Related demos:'));
      [
        { href: 'https://systemslibrarian.github.io/crypto-lab-kdf-arena/', label: 'crypto-lab-kdf-arena' },
        { href: 'https://systemslibrarian.github.io/crypto-lab-shadow-vault/', label: 'crypto-lab-shadow-vault' },
        { href: 'https://systemslibrarian.github.io/crypto-lab-ratchet-wire/', label: 'crypto-lab-ratchet-wire' },
        { href: 'https://systemslibrarian.github.io/crypto-lab-mac-race/', label: 'crypto-lab-mac-race' },
        { href: 'https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/', label: 'crypto-lab-bcrypt-forge' },
      ].forEach(l => {
        related.append(el('a', { href: l.href, className: 'cross-link', target: '_blank', rel: 'noopener noreferrer' }, l.label));
      });
      return related;
    })(),
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
    // Hero lives INSIDE <main> so its <header class="cl-hero"> is not a second
    // banner landmark (the shared cl-topbar is the page banner).
    el('main', { role: 'main' },
      buildHeader(),
      buildWhySection(),
      buildGuide(),
      el('div', { className: 'panels' },
        buildHkdfPanel(),
        buildPbkdf2Panel(),
        buildScryptPanel(),
        buildArgon2Panel(),
        buildMemoryHardnessPanel(),
        buildChainPanel(),
        buildCostPanel(),
        buildDecisionPanel(),
        buildSaltPanel(),
        buildVectorsPanel(),
      ),
    ),
    buildCrossLinks(),
    buildFooter(),
  );
}
