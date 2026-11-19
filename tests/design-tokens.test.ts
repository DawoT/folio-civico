import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const tokenPath = new URL("../apps/web/src/ui/tokens.css", import.meta.url);
const stylesPath = new URL("../apps/web/src/styles.css", import.meta.url);

function tokens(): Record<string, string> {
  const css = readFileSync(tokenPath, "utf8");
  return Object.fromEntries(
    Array.from(css.matchAll(/(--fc-[a-z0-9-]+):\s*([^;]+);/g), ([, name, value]) => [name, value.trim()])
  );
}

function relativeLuminance(hex: string): number {
  if (!/^#[a-f0-9]{6}$/i.test(hex)) throw new Error("Expected literal hex color");
  const channels = [1, 3, 5].map((start) => {
    const channel = Number.parseInt(hex.slice(start, start + 2), 16) / 255;
    return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return channels[0]! * 0.2126 + channels[1]! * 0.7152 + channels[2]! * 0.0722;
}

function contrast(a: string, b: string): number {
  const [light, dark] = [relativeLuminance(a), relativeLuminance(b)].sort((x, y) => y - x);
  return (light! + 0.05) / (dark! + 0.05);
}

describe("DS-001 semantic design token contracts", () => {
  it("extracts semantic tokens into a dedicated CSS file before the legacy stylesheet", () => {
    expect(existsSync(tokenPath)).toBe(true);
    expect(readFileSync(stylesPath, "utf8").startsWith('@import "./ui/tokens.css";')).toBe(true);
  });

  it("defines text, surfaces, borders, focus, status and motion without inventing a second theme", () => {
    const theme = tokens();
    for (const name of [
      "color-text-primary", "color-text-secondary", "color-surface-base",
      "color-surface-canvas", "color-border-default", "color-border-strong",
      "color-brand-primary", "color-brand-primary-hover", "color-focus",
      "color-status-warning-fg", "color-status-warning-bg",
      "color-status-error-fg", "color-status-error-bg",
      "color-status-success-fg", "color-status-success-bg",
      "color-status-quarantined-fg", "color-status-reviewing-fg",
      "color-status-validated-fg", "space-1", "space-2",
      "space-4", "radius-control", "radius-card", "motion-fast", "font-body"
    ]) expect(theme[`--fc-${name}`], `Missing --fc-${name}`).toBeTruthy();
  });

  it("preserves accessible foreground/background contrast of the core institutional palette", () => {
    const theme = tokens();
    const pairs: Array<[string, string]> = [
      ["color-text-primary", "color-surface-base"],
      ["color-text-secondary", "color-surface-base"],
      ["color-brand-on-primary", "color-brand-primary"],
      ["color-status-warning-fg", "color-status-warning-bg"],
      ["color-status-error-fg", "color-status-error-bg"],
      ["color-status-success-fg", "color-status-success-bg"]
    ];
    for (const [foreground, background] of pairs) {
      const ratio = contrast(theme[`--fc-${foreground}`]!, theme[`--fc-${background}`]!);
      expect(ratio, `${foreground}/${background} has insufficient contrast`).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("adopts theme tokens in key affordances while keeping interactive focus visible", () => {
    const styles = readFileSync(stylesPath, "utf8");
    expect(styles).toMatch(/\.brand-mark\s*\{[^}]*var\(--fc-color-brand-primary\)/);
    expect(styles).toMatch(/\.button\.primary\s*\{[^}]*var\(--fc-color-brand-primary\)/);
    expect(styles).toMatch(/\.message\.error\s*\{[^}]*var\(--fc-color-status-error-bg\)/);
    expect(styles).toMatch(/\.message\.success\s*\{[^}]*var\(--fc-color-status-success-bg\)/);
    expect(styles).toMatch(/:where\(button,\s*input,\s*select,\s*textarea,\s*a\):focus-visible\s*\{[^}]*var\(--fc-color-focus\)/);
  });
});
