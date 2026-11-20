import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadCompiledWeb, compiledResponseForPath,
  validateRealApiSample, summarizeRealApiLab
} from "../scripts/real-api-lab.mjs";

const roots = [];
const baseline = {
  discoveryMs: 120, openScopeMs: 180, sessionApiMs: 12, documentsApiMs: 26,
  subject: "reviewer", authorized: true, productionJs: true, productionCss: true,
  documentReady: true, checklistReady: true, apiErrors: 0,
  externalRequests: 0, mutations: 0, apiReads: 7
};
function fixture(html) {
  const root = mkdtempSync(join(tmpdir(), "folio-built-web-"));
  roots.push(root);
  mkdirSync(join(root, "assets"));
  writeFileSync(join(root, "index.html"), html);
  writeFileSync(join(root, "assets", "index-X1.js"), "console.log('built');");
  writeFileSync(join(root, "assets", "index-X2.css"), "body{color:black}");
  return root;
}
const builtHtml = '<!doctype html><div id="root"></div><script type="module" src="/assets/index-X1.js"></script><link rel="stylesheet" href="/assets/index-X2.css">';
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe("PERF-005 compiled frontend plus real signed local API", () => {
  it("serves the exact built assets and NEVER substitutes any API response", () => {
    const web = loadCompiledWeb(fixture(builtHtml));
    expect(compiledResponseForPath("/", web)?.contentType).toBe("text/html; charset=utf-8");
    expect(compiledResponseForPath("/assets/index-X1.js", web)?.body.toString()).toContain("built");
    expect(compiledResponseForPath("/assets/index-X2.css", web)?.contentType).toBe("text/css; charset=utf-8");
    expect(compiledResponseForPath("/api/session", web)).toBe(null);
    expect(compiledResponseForPath("/api/commissions", web)).toBe(null);
    expect(() => compiledResponseForPath("/assets/not-built.js", web)).toThrow(/not built/);
  });

  it("rejects stale dev output, missing assets, paths outside the build and symlinks", () => {
    expect(() => loadCompiledWeb(fixture('<script src="/src/main.tsx"></script>'))).toThrow();
    const withoutCss = builtHtml.replace('<link rel="stylesheet" href="/assets/index-X2.css">', "");
    expect(() => loadCompiledWeb(fixture(withoutCss))).toThrow(/CSS/);
    const root = fixture(builtHtml);
    symlinkSync(join(root, "assets", "index-X1.js"), join(root, "assets", "linked.js"));
    expect(() => loadCompiledWeb(root)).toThrow(/symlink/i);
    const safe = loadCompiledWeb(fixture(builtHtml));
    expect(() => compiledResponseForPath("/assets/../api/session", safe)).toThrow();
    expect(() => compiledResponseForPath("/assets/external.js", safe)).toThrow();
  });

  it("fails closed on synthetic/mock requests, missing real auth or invalid timings", () => {
    expect(validateRealApiSample(baseline)).toEqual({
      discoveryMs: 120, openScopeMs: 180, sessionApiMs: 12, documentsApiMs: 26
    });
    for (const invalid of [
      { ...baseline, discoveryMs: null }, { ...baseline, documentsApiMs: 0 },
      { ...baseline, openScopeMs: Number.POSITIVE_INFINITY }, { ...baseline, subject: "operator" },
      { ...baseline, authorized: false }, { ...baseline, productionJs: false },
      { ...baseline, productionCss: false }, { ...baseline, documentReady: false },
      { ...baseline, checklistReady: false }, { ...baseline, apiErrors: 1 },
      { ...baseline, externalRequests: 1 }, { ...baseline, mutations: 1 },
      { ...baseline, apiReads: 4 }, { ...baseline, apiReads: 0 }
    ]) expect(() => validateRealApiSample(invalid)).toThrow();
  });

  it("requires three independent browser runs and uses medians without fabricated metrics", () => {
    expect(() => summarizeRealApiLab([baseline, baseline])).toThrow(/three/i);
    expect(summarizeRealApiLab([
      baseline,
      { ...baseline, discoveryMs: 100, openScopeMs: 150, sessionApiMs: 9, documentsApiMs: 20 },
      { ...baseline, discoveryMs: 180, openScopeMs: 250, sessionApiMs: 19, documentsApiMs: 45 }
    ])).toEqual({
      navigations: 3,
      backend: "local-real-handler-jwt-rs256-sqlite",
      median: { discoveryMs: 120, openScopeMs: 180, sessionApiMs: 12, documentsApiMs: 26 }
    });
  });
});
