/**
 * Deterministic, local-only gzip budget for the production Vite frontend.
 * A transfer-size guard is not a Lighthouse, Core Web Vitals or user study.
 */
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

export const FRONTEND_BUDGET = Object.freeze({
  js: 100 * 1024,
  css: 10 * 1024
});

const LABELS = Object.freeze({ js: "JavaScript", css: "CSS" });

export function measureFrontendBundle(distDir) {
  const assetsDir = join(distDir, "assets");
  // A missing or symbolic-link output must never pass with a reported size of 0.
  for (const directory of [distDir, assetsDir]) {
    const state = lstatSync(directory);
    if (!state.isDirectory() || state.isSymbolicLink()) {
      throw new Error("Frontend bundle directory must be a real directory: " + directory);
    }
  }
  const report = {
    js: { count: 0, rawBytes: 0, gzipBytes: 0 },
    css: { count: 0, rawBytes: 0, gzipBytes: 0 },
    assets: []
  };
  function collect(directory) {
    for (const item of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, item.name);
      if (item.isSymbolicLink()) throw new Error("Frontend bundle symlink is forbidden: " + item.name);
      if (item.isDirectory()) {
        collect(path);
        continue;
      }
      if (!item.isFile()) throw new Error("Unsupported frontend bundle file: " + item.name);
      const type = item.name.endsWith(".js") ? "js" : item.name.endsWith(".css") ? "css" : null;
      if (!type) continue;
      const content = readFileSync(path);
      const gzipBytes = gzipSync(content).byteLength;
      report[type].count++;
      report[type].rawBytes += content.byteLength;
      report[type].gzipBytes += gzipBytes;
      report.assets.push({
        name: relative(assetsDir, path).replaceAll("\\", "/"),
        type,
        rawBytes: content.byteLength,
        gzipBytes
      });
    }
  }
  collect(assetsDir);
  report.assets.sort((a, b) => a.name.localeCompare(b.name, "en"));
  if (!report.js.count) throw new Error("Frontend build has no JavaScript assets");
  if (!report.css.count) throw new Error("Frontend build has no CSS assets");
  return report;
}

export function enforceFrontendBudget(distDir, limits = FRONTEND_BUDGET) {
  const report = measureFrontendBundle(distDir);
  for (const type of ["js", "css"]) {
    const max = limits[type];
    if (!Number.isSafeInteger(max) || max < 1) {
      throw new Error("Invalid frontend budget for " + LABELS[type]);
    }
    if (report[type].gzipBytes > max) {
      throw new Error(
        LABELS[type] + " gzip budget exceeded: " +
        report[type].gzipBytes + " bytes > " + max + " bytes"
      );
    }
  }
  return report;
}

const scriptPath = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href;
if (scriptPath === import.meta.url) {
  try {
    const distDir = resolve("apps/web/dist");
    const report = enforceFrontendBudget(distDir);
    for (const type of ["js", "css"]) {
      const item = report[type];
      const limit = FRONTEND_BUDGET[type];
      console.log(
        LABELS[type] + ": " + item.count + " files, " +
        item.rawBytes + " bytes raw, " + item.gzipBytes +
        " bytes gzip / " + limit + " byte budget"
      );
    }
    console.log("Frontend bundle budget PASSED (transfer bytes only, not UX performance approval)");
  } catch (error) {
    console.error("Frontend bundle budget FAILED:", error.message);
    process.exitCode = 1;
  }
}
