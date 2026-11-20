import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { measureFrontendBundle, enforceFrontendBudget } from "../scripts/check-frontend-budget.mjs";

const tempRoots = [];
function buildFixture(files) {
  const root = mkdtempSync(join(tmpdir(), "folio-ux-bundle-"));
  tempRoots.push(root);
  mkdirSync(join(root, "assets"));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(root, "assets", name), content);
  }
  return root;
}
afterEach(() => {
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("UX frontend bundle budget", () => {
  it("measures combined gzip bytes for every JS and CSS chunk, not just the biggest", () => {
    const files = {
      "index-a.js": "A".repeat(2048),
      "lazy-b.js": "B".repeat(2048),
      "index-c.css": "body{color:#075c57}".repeat(40),
      "logo.svg": "<svg/>"
    };
    const root = buildFixture(files);
    const report = measureFrontendBundle(root);
    expect(report.js.count).toBe(2);
    expect(report.css.count).toBe(1);
    expect(report.js.gzipBytes).toBe(
      gzipSync(Buffer.from(files["index-a.js"])).byteLength +
      gzipSync(Buffer.from(files["lazy-b.js"])).byteLength
    );
    expect(report.css.gzipBytes).toBe(gzipSync(Buffer.from(files["index-c.css"])).byteLength);
    expect(report.assets.map((asset) => asset.name)).toEqual([
      "index-a.js", "index-c.css", "lazy-b.js"
    ]);
  });

  it("rejects missing or incomplete builds rather than reporting zero weight", () => {
    const empty = buildFixture({});
    expect(() => measureFrontendBundle(empty)).toThrow(/JavaScript|CSS/);
    const jsOnly = buildFixture({ "index.js": "hello" });
    expect(() => measureFrontendBundle(jsOnly)).toThrow(/CSS/);
    const cssOnly = buildFixture({ "index.css": "body{}" });
    expect(() => measureFrontendBundle(cssOnly)).toThrow(/JavaScript/);
    expect(() => measureFrontendBundle(join(empty, "missing"))).toThrow();
  });

  it("fails closed if total JS or CSS exceeds its own gzip budget", () => {
    const root = buildFixture({
      "a.js": "const a = 42",
      "b.js": "const b = 99",
      "c.css": "body { color: blue }"
    });
    const report = measureFrontendBundle(root);
    expect(() => enforceFrontendBudget(root, {
      js: report.js.gzipBytes - 1,
      css: report.css.gzipBytes
    })).toThrow(/JavaScript.*budget/);
    expect(() => enforceFrontendBudget(root, {
      js: report.js.gzipBytes,
      css: report.css.gzipBytes - 1
    })).toThrow(/CSS.*budget/);
    expect(() => enforceFrontendBudget(root, {
      js: report.js.gzipBytes,
      css: report.css.gzipBytes
    })).not.toThrow();
  });

  it("rejects symlinks in the generated assets directory", () => {
    const root = buildFixture({ "a.js": "hello", "c.css": "body{}" });
    symlinkSync(join(root, "assets", "a.js"), join(root, "assets", "linked.js"));
    expect(() => measureFrontendBundle(root)).toThrow(/symlink/i);
  });
});
