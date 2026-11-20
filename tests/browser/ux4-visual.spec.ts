import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openScope(page: Page, role: "author" | "viewer" = "author") {
  const api = new SyntheticPilotApi();
  await api.attach(page, role);
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Documentos del lote" })).toBeVisible();
}

test("keyboard navigation offers a visible skip link and moves focus to main content", async ({ page }) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "viewer");
  await page.goto("/");
  const skip = page.getByRole("link", { name: "Saltar al contenido principal" });
  const initial = await skip.boundingBox();
  expect(initial).not.toBeNull();
  expect(initial!.y + initial!.height).toBeLessThanOrEqual(0);
  await page.keyboard.press("Tab");
  await expect(skip).toBeFocused();
  const focused = await skip.boundingBox();
  expect(focused).not.toBeNull();
  expect(focused!.y).toBeGreaterThanOrEqual(0);
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
  await expect(page).toHaveURL(/#main-content$/);
});

test("visual hierarchy uses design tokens while preserving the semantic task workflow", async ({ page }) => {
  await openScope(page);
  const details = await page.evaluate(() => {
    const get = (selector: string) => {
      const element = document.querySelector(selector);
      if (!(element instanceof HTMLElement)) throw new Error(`Missing ${selector}`);
      return getComputedStyle(element);
    };
    return {
      surface: get(".scope-form").backgroundColor,
      scopeElevation: get(".scope-form").boxShadow,
      navElevation: get(".task-navigation").boxShadow,
      reviewElevation: get(".review-card").boxShadow,
      titleWeight: Number(get(".intro h1").fontWeight),
      introLineHeight: Number.parseFloat(get(".intro p:not(.eyebrow)").lineHeight),
      introFontSize: Number.parseFloat(get(".intro p:not(.eyebrow)").fontSize),
      primaryHeight: Number.parseFloat(get(".scope-form .button").height),
      mobileGrid: get(".workspace").gridTemplateColumns
    };
  });
  expect(details.surface).toBe("rgb(255, 255, 255)");
  expect(details.scopeElevation).not.toBe("none");
  expect(details.navElevation).not.toBe("none");
  expect(details.reviewElevation).not.toBe("none");
  expect(details.titleWeight).toBeGreaterThanOrEqual(700);
  expect(details.introLineHeight / details.introFontSize).toBeGreaterThanOrEqual(1.55);
  expect(details.primaryHeight).toBeGreaterThanOrEqual(44);
  const overflow = await page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    return {
      amount: document.documentElement.scrollWidth - width,
      offenders: Array.from(document.body.querySelectorAll("*")).filter(el =>
        el.getBoundingClientRect().right > width + 1
      ).slice(0, 5).map(el => el.tagName.toLowerCase())
    };
  });
  expect(overflow).toEqual({ amount: 0, offenders: [] });
  const scan = await new AxeBuilder({page}).withTags([
    "wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"
  ]).analyze();
  expect(scan.violations.map(issue => issue.id)).toEqual([]);
});

test("reduced-motion preference removes interactive transitions without losing focus indication", async ({ page }) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "author");
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Abrir lote" })).toBeVisible();
  const transition = await page.locator(".scope-form button").evaluate(element =>
    getComputedStyle(element).transitionDuration
  );
  expect(transition).toMatch(/^0s(?:, 0s)*$/);
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Saltar al contenido principal" });
  await expect(skip).toBeFocused();
  const outline = await skip.evaluate(element => {
    const style = getComputedStyle(element);
    return { style: style.outlineStyle, width: Number.parseFloat(style.outlineWidth) };
  });
  expect(outline.style).toBe("solid");
  expect(outline.width).toBeGreaterThanOrEqual(3);
});
