import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this replaces
 *     opened with an `addStyleTag` that forced `animation-duration: 0s` and
 *     `transition-duration: 0s` on every element and pseudo-element. That does
 *     not merely hide timing flake — it BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the suite was structurally unable to see a defect in the very code
 *     path a motion-sensitive reader gets. It then called `revealAll()`, which
 *     stripped `[hidden]` and force-added `.open`/`.active` everywhere and
 *     opened every `<details>`: a document no visitor can load.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing — and nine of this lab's ten panels start with their output boxes
 *     holding a literal "—".
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * `mem-stall-pulse` is an `infinite` animation that runs while the memory grid
 * is filling, so this would never settle mid-fill — but under reduced motion
 * the lab fills the whole grid synchronously and never adds `.mem-busy`, which
 * is exactly the state the gate runs in.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This lab has exactly that shape twice: `.hkdf-block-enter` and
 * `.pb-link-enter` both declare `opacity: 0`, and the only thing that removes
 * them is a `setTimeout` the renderer skips when it reads the media query. If
 * either branch of that check inverted, every expand block and every iteration
 * link would render invisible and no other oracle here would notice.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/** `await`-able soft wrapper for the assertions that live inside a helper. */
async function softCall(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String((e as Error).message ?? e));
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The SHIPPED DEFAULTS are asserted here rather than assumed, because half of
 * what this gate measures only exists in one of them: the PBKDF2 chain visual
 * renders four links from a `queueMicrotask` at load, the memory grid ships at
 * slider step 1 (16 cells, not the 4 of step 0), and each attacker readout
 * ships with placeholder prose rather than a number. A gate written from the
 * markup alone would be asserting a page that never reaches the screen.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  // index.html's anti-flash script stamps `data-theme` unconditionally
  // (`saved ?? 'dark'`), reading the same 'theme' key the shared header's
  // toggle writes — so both themes are checkable by attribute here.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  await expect(page.locator('main .panels .panel')).toHaveCount(10);
  await expect(page.locator('.cl-hero-title')).toHaveText('KDF Chain');
  await expect(page.locator('.guide-steps .guide-step')).toHaveCount(6);

  // Shipped defaults, asserted.
  await expect(page.locator('#pb-links .pb-link')).toHaveCount(4);
  await expect(page.locator('#mem-grid .mem-cell')).toHaveCount(16);
  await expect(page.locator('#dt-entropy-low')).toBeChecked();
  await expect(page.locator('#decision-result')).toBeEmpty();
  for (const t of await page.locator('.attack-out').allTextContents()) {
    expect(t.trim(), 'attacker readouts ship as prose, not a number').toBe(
      'Derive a key to estimate attacker cost.'
    );
  }

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 64-character hex keys with no spaces, a
 * seven-column comparison table carrying `min-width: 600px`, and a memory grid
 * that grows to 128 cells.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab does not have
    // that rule today, but the check is kept honest against one being added.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. The
    // comparison table has a 600px minimum inside an `overflow-x: auto`
    // wrapper, so its bounding rect is far wider than the phone viewport while
    // contributing nothing to the document's scroll width — naming it would
    // send you off fixing an element that is already reachable.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab has nine of them: the `.table-scroll` region, seven `.output-hex`
 * panes capped at `max-height: 12rem`, and the three `.attack-out` readouts —
 * every one of which only starts overflowing once a derivation has actually
 * run, which is why this is asserted after each step of the drive and not once
 * at the end.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less `<span>` or `<pre>` hides, a defect
 *    that never reaches the violations array at all and which this lab's
 *    output boxes and status chips were full of.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *
 * WCAG 1.4.11 (non-text contrast) and generated content have NO oracle here;
 * both were measured by hand from screenshot pixels during this sweep and the
 * fixes are in `styles/main.css`.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await softCall(() => expectNotBlank(page, label));
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await softCall(() => expectScrollersReachable(page, label));
  await softCall(() => expectNoHorizontalOverflow(page, label));
  await expectNoNewNonTextFailures(page, label);
}

/**
 * A click whose handler is multi-second in-page crypto.
 *
 * `locator.click()` does not return until the handler's synchronous work
 * yields, so a 600,000-iteration PBKDF2 or a 19 MiB Argon2id blows the default
 * action timeout INSIDE the click and reports as if the selector were broken.
 * The timeout belongs on the action, not on the wait that follows it.
 */
const SLOW = { timeout: 120_000 };

/** Click, then wait for a real completion signal rather than a fixed delay. */
async function run(page: Page, selector: string, done: () => Promise<void>): Promise<void> {
  await page.locator(selector).click(SLOW);
  await done();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Ten panels, each of which paints nothing until its button is pressed, plus
 * three controls whose extremes build states the defaults never show:
 *
 *  - the PBKDF2 chain slider (1..16 links — 16 is what makes `.pb-links` wrap
 *    and pushes the panel widest),
 *  - the memory-cost slider (4..128 cells — 128 is what makes `#mem-grid` a
 *    16-column block on a 380px viewport),
 *  - the three attacker-target `<select>`s, whose last option (95^12) is the
 *    one that produces the longest readout and so the widest `.attack-out`.
 *
 * Every step is scanned. Nothing is force-revealed: the `<details>` notes are
 * opened by clicking their own `<summary>`, and the skip link is reached by
 * pressing Tab, because both have styling that only exists in that state.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  // The skip link is `top: -3rem` until focused. Its focused rendering is the
  // only one a keyboard user ever sees, and it is the first tab stop.
  await page.keyboard.press('Tab');
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await scan(page, `${theme} / skip link focused`);

  /* -- Panel 1: HKDF ------------------------------------------------- */
  await run(page, '#panel-hkdf .btn', async () => {
    await expect(page.locator('#hkdf-prk')).not.toHaveText('—');
    await expect(page.locator('#hkdf-d-blocks .hkdf-block')).not.toHaveCount(0);
  });
  await scan(page, `${theme} / hkdf derived`);

  // Out-of-range length: RFC 5869 caps OKM at 255*HashLen, so the derivation
  // rejects and the panel takes its error branch. The `<input max>` is advisory
  // only — typing past it is a state a visitor reaches. Asserted on the VISIBLE
  // readout as well as the live region, because reporting the failure only into
  // `.sr-only` was itself the defect.
  await page.locator('#hkdf-len').fill('9999');
  await run(page, '#panel-hkdf .btn', async () => {
    await expect(page.locator('#hkdf-live')).toContainText('Error');
    await expect(page.locator('#hkdf-timing')).toHaveClass(/timing-error/);
    await expect(page.locator('#hkdf-timing')).toContainText('RFC 5869');
  });
  await scan(page, `${theme} / hkdf error branch`);
  // ...and cleared again by the next good derivation, so a stale error can
  // never be mistaken for a current one.
  await page.locator('#hkdf-len').fill('32');
  await run(page, '#panel-hkdf .btn', async () => {
    await expect(page.locator('#hkdf-timing')).not.toHaveClass(/timing-error/);
  });
  await scan(page, `${theme} / hkdf recovered from error`);

  /* -- Panel 2: PBKDF2 ----------------------------------------------- */
  // Both extremes of the chain slider: one link (no XOR to show) and sixteen
  // (the wrapping, widest layout).
  for (const c of ['1', '16']) {
    await page.locator('#pb-chain-iter').fill(c);
    await expect(page.locator('#pb-links .pb-link')).toHaveCount(Number(c));
    await scan(page, `${theme} / pbkdf2 chain c=${c}`);
  }

  // Last target option — the 95^12 keyspace produces the longest readout.
  const targets = page.locator('#pbkdf2-target option');
  const lastTarget = String((await targets.count()) - 1);
  for (const sel of ['#pbkdf2-target', '#scrypt-target', '#argon2-target', '#cost-target']) {
    await page.selectOption(sel, lastTarget);
  }

  await run(page, '#panel-pbkdf2 .btn >> nth=0', async () => {
    await expect(page.locator('#pbkdf2-sha256')).not.toHaveText('—');
    await expect(page.locator('#pbkdf2-attack')).toContainText('guesses/sec');
  });
  await scan(page, `${theme} / pbkdf2 derived`);

  // The inline assumptions note. Opened by clicking its own <summary>, never
  // by setting `.open` from script.
  const note = page.locator('#panel-pbkdf2 details.assumptions');
  await note.locator('summary').click();
  await expect(note).toHaveAttribute('open', '');
  await scan(page, `${theme} / pbkdf2 assumptions open`);
  await note.locator('summary').click();
  await expect(note).not.toHaveAttribute('open', '');

  await run(page, '#panel-pbkdf2 .btn >> nth=1', async () => {
    await expect(page.locator('#pbkdf2-bench')).toContainText('1000k iterations');
  });
  await scan(page, `${theme} / pbkdf2 benchmarked`);

  /* -- Panel 3: scrypt ----------------------------------------------- */
  await run(page, '#panel-scrypt .btn >> nth=0', async () => {
    await expect(page.locator('#scrypt-out')).not.toHaveText('—');
    await expect(page.locator('#scrypt-attack')).toContainText('guesses/sec');
  });
  await scan(page, `${theme} / scrypt derived`);

  await run(page, '#panel-scrypt .btn >> nth=1', async () => {
    await expect(page.locator('#scrypt-bench')).toContainText('N=2^');
  });
  await scan(page, `${theme} / scrypt N comparison`);

  /* -- Panel 4: Argon2id --------------------------------------------- */
  await run(page, '#panel-argon2 .btn', async () => {
    await expect(page.locator('#argon2-out')).not.toHaveText('—');
    await expect(page.locator('#argon2-attack')).toContainText('guesses/sec');
  });
  await scan(page, `${theme} / argon2 derived`);

  /* -- Panel 5: memory hardness -------------------------------------- */
  // Both ends of the slider, and the animate button at each — under reduced
  // motion the fill is synchronous, so the "all filled" state is the one a
  // motion-sensitive reader actually gets and it is scanned for real.
  for (const [step, cells] of [
    ['0', 4],
    ['4', 128],
  ] as const) {
    await page.locator('#mem-cost').fill(step);
    await expect(page.locator('#mem-grid .mem-cell')).toHaveCount(cells);
    await scan(page, `${theme} / memory cost step ${step} (${cells} cells)`);
    await run(page, '#panel-memory .btn', async () => {
      await expect(page.locator('#mem-grid .mem-cell.filled')).toHaveCount(cells);
    });
    await scan(page, `${theme} / memory cost step ${step} filled`);
  }
  await page.locator('#mem-cost').fill('1');

  /* -- Panel 6: the chain -------------------------------------------- */
  await run(page, '#panel-chain .btn', async () => {
    await expect(page.locator('#chain-flow .chain-leaf')).toHaveCount(3);
  });
  await scan(page, `${theme} / chain run`);

  // Emptying every info string is the branch that fans out to nothing: the
  // root key is still derived but no leaf is.
  for (const id of ['#chain-info1', '#chain-info2', '#chain-info3']) {
    await page.locator(id).fill('');
  }
  await run(page, '#panel-chain .btn', async () => {
    await expect(page.locator('#chain-flow .chain-leaf')).toHaveCount(0);
    await expect(page.locator('#chain-flow .chain-root')).toHaveCount(1);
  });
  await scan(page, `${theme} / chain with no info strings`);

  /* -- Panel 7: cost comparison -------------------------------------- */
  await run(page, '#panel-cost .btn', async () => {
    await expect(page.locator('#cost-bars .cost-row')).toHaveCount(4);
    await expect(page.locator('#cost-bars .cost-fill-warn')).toHaveCount(1);
  });
  await scan(page, `${theme} / cost comparison run`);

  /* -- Panel 8: decision tree ---------------------------------------- */
  // Every branch of the fork, not just the shipped default. Each reaches a
  // different recommendation and a differently-coloured status chip.
  const branches: [string, string, string, string][] = [
    ['dt-entropy-low', 'dt-multi-no', 'dt-legacy-no', 'Argon2id'],
    ['dt-entropy-low', 'dt-multi-yes', 'dt-legacy-no', 'Argon2id'],
    ['dt-entropy-low', 'dt-multi-no', 'dt-legacy-yes', 'PBKDF2'],
    ['dt-entropy-high', 'dt-multi-yes', 'dt-legacy-no', 'HKDF'],
    ['dt-entropy-high', 'dt-multi-no', 'dt-legacy-no', 'HKDF'],
  ];
  for (const [a, b, c, expected] of branches) {
    for (const id of [a, b, c]) await page.locator(`#${id}`).check();
    await run(page, '#panel-decision .btn', async () => {
      await expect(page.locator('#decision-result .decision-kdf')).toContainText(expected);
    });
    await scan(page, `${theme} / decision ${a}+${b}+${c}`);
  }

  /* -- Panel 9: salt and context binding ----------------------------- */
  const saltOutputs = ['#salt-nosalt', '#salt-withsalt', '#salt-context', '#salt-domain'];
  for (let i = 0; i < saltOutputs.length; i++) {
    await run(page, `#panel-salt .btn >> nth=${i}`, async () => {
      await expect(page.locator(saltOutputs[i]!)).not.toHaveText('—');
    });
    await scan(page, `${theme} / salt demo ${saltOutputs[i]}`);
  }

  /* -- Panel 10: RFC known-answer tests ------------------------------ */
  await run(page, '#panel-vectors .btn', async () => {
    await expect(page.locator('#vectors-results .vector-row')).not.toHaveCount(0);
    await expect(page.locator('#vectors-results .vector-fail')).toHaveCount(0);
  });
  await scan(page, `${theme} / rfc vectors run`);
}
