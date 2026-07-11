import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the RFC known-answer
 * vectors; this gates them on accessibility the same way. Scans the full page
 * in both themes, with every collapsible expanded and every interactive panel
 * exercised so dynamically-rendered content (cost bars, chain flow, vector
 * rows, decision result) is present in the accessibility tree when scanned.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Kill animations/transitions/opacity so nothing paints mid-transition. */
async function freeze(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      scroll-behavior:auto!important;
    }`,
  });
}

/** Expand every native <details> and reveal class-toggled / hidden panels. */
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of Array.from(document.querySelectorAll('details'))) {
      (d as HTMLDetailsElement).open = true;
    }
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      el.removeAttribute('hidden');
    }
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>('.accordion,.panel,.tab-panel'),
    )) {
      el.classList.add('open', 'active');
    }
  });
}

/**
 * Click every in-page demo button so async-rendered output (with its own
 * ARIA roles and colored badges/bars) exists in the DOM before we scan.
 * Skips the shared-header theme toggle so the theme stays as configured.
 */
async function exercisePanels(page: Page): Promise<void> {
  const buttons = page.locator('#app button.btn');
  const count = await buttons.count();
  for (let i = 0; i < count; i++) {
    const btn = buttons.nth(i);
    if (await btn.isVisible()) {
      await btn.click().catch(() => {});
    }
  }
  // Select a radio in each decision-tree question, then evaluate, so the
  // decision-result region renders content.
  const radios = page.locator('#app input[type="radio"]');
  const rc = await radios.count();
  for (let i = 0; i < rc; i++) {
    await radios.nth(i).check().catch(() => {});
  }
  // Give the async KDFs (scrypt / Argon2id) time to resolve and paint.
  await page.waitForTimeout(3000);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await freeze(page);
  await revealAll(page);
  await exercisePanels(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await freeze(page);
  await revealAll(page);
  await exercisePanels(page);
  await revealAll(page);
  await scan(page);
});
