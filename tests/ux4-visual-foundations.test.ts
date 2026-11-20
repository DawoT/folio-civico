import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const app = readFileSync(new URL("../apps/web/src/App.tsx", import.meta.url), "utf8");
const styles = readFileSync(new URL("../apps/web/src/styles.css", import.meta.url), "utf8");
const tokens = readFileSync(new URL("../apps/web/src/ui/tokens.css", import.meta.url), "utf8");

describe("UX-4.1 premium visual foundations", () => {
  it("offers an accessible skip link as the first interactive surface and a focusable main target", () => {
    expect(app).toMatch(/<div className="app-shell">\s*<a className="skip-link" href="#main-content">/);
    expect(app).toMatch(/<main[^>]*id="main-content"[^>]*tabIndex=\{-1\}/);
    expect(styles).toMatch(/\.skip-link:focus-visible\s*\{[^}]*transform:\s*translateY\(0\)/);
  });

  it("defines single-source visual polish tokens, including reading measure and elevation", () => {
    for (const token of [
      "--fc-color-surface-wash:", "--fc-shadow-shell:", "--fc-shadow-card:",
      "--fc-reading-measure:", "--fc-type-heading-md:", "--fc-type-heading-sm:",
      "--fc-line-body:", "--fc-motion-medium:"
    ]) expect(tokens, `Missing ${token}`).toContain(token);
  });

  it("consolidates foundational layout typography and interactive focus without altering workflow labels", () => {
    expect(styles).toMatch(/\/\* UX-4\.1:[\s\S]*?\.intro h1\s*\{/);
    expect(styles).toMatch(/\.scope-form\s*\{[^}]*box-shadow:\s*var\(--fc-shadow-card\)/);
    expect(styles).toMatch(/\.document-item:focus-visible\s*\{[^}]*outline:/);
    expect(styles).toMatch(/\.task-navigation-links a:hover\s*\{[^}]*box-shadow:/);
    expect(styles).toMatch(/\.review-card\s*\{[^}]*box-shadow:\s*var\(--fc-shadow-card\)/);
    expect(styles).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{[\s\S]*?scroll-behavior:\s*auto/);
  });

  it("keeps a tokenized mobile layout and wrapped long text without horizontal scroll", () => {
    expect(styles).toMatch(/@media\s*\(max-width:\s*600px\)\s*\{[\s\S]*?\.main-content\s*\{/);
    expect(styles).toMatch(/\.brand\s*\{[^}]*min-width:\s*0/);
    expect(styles).toMatch(/\.intro p:not\(\.eyebrow\)\s*\{[^}]*max-width:\s*var\(--fc-reading-measure\)/);
  });
});
