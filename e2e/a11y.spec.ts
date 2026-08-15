import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate. Deploys are already gated on the RFC known-answer
 * vectors; this gates them on accessibility the same way.
 *
 * The lab is driven along everything it teaches: the arrival state, where all
 * ten panels hold placeholder dashes and the three attacker readouts hold
 * prose; the skip link focused; HKDF derived and then pushed past RFC 5869's
 * 255-block output cap so the panel takes its error branch; the PBKDF2
 * iteration-chain slider at both ends (one link, then sixteen wrapping ones);
 * PBKDF2 derived at 600k and benchmarked to 1M, with the inline assumptions
 * `<details>` opened through its own summary; scrypt derived and compared
 * across N=2^14..2^20 (which includes the "N too large for browser memory"
 * branch); Argon2id derived at 19 MiB; the memory-hardness slider at both
 * extremes — 4 cells and 128 — each then filled, which under reduced motion is
 * the synchronous fill a motion-sensitive reader actually gets; the KDF chain
 * run with three info strings and then with none, which is the only state that
 * renders a root with no leaves; all four KDFs compared in one run, the only
 * state that paints the amber `.cost-fill-warn` bar; every branch of the
 * three-question decision fork; all four salt sub-demos; and the RFC vector
 * run. Each attacker `<select>` is moved to its 95^12 option first, because
 * that is the longest readout and so the widest `.attack-out`. Every one of
 * those states is scanned, in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * force-revealed, why the lab's shipped defaults are asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 *
 * `expectBaselineNotStale` is the non-text baseline's third rule — a listed
 * finding that no longer appears fails, so a fixed entry must be deleted and
 * the file can only shrink. It runs in the LIGHT configurations only, and that
 * restriction is measured rather than stylistic. `nonTextSeen` is module state
 * and `fullyParallel` gives every configuration its own worker, so each
 * ratchets against what it alone drove. Run in isolation, each light
 * configuration reaches all three baselined findings; each dark one reaches
 * two, because `div.hkdf-op::before` is a generated-content failure only
 * against the light surface. Dark's set is a strict subset, so running the
 * rule in light loses no coverage, while running it in dark reported that
 * entry as stale on every run.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_200_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_200_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });
}
