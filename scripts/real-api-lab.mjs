/**
 * PERF-005 browser test fixture: only built HTML/CSS/JS may be fulfilled by
 * Playwright. All /api/** requests must reach the signed local handler.
 * No production server or Cloudflare settings are modified.
 */
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const ASSET = /^\/assets\/[A-Za-z0-9_.-]+\.(?:js|css)$/;
const STAGES = ["discoveryMs", "openScopeMs", "sessionApiMs", "documentsApiMs"];

export function loadCompiledWeb(root) {
  if (!lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) {
    throw new Error("Compiled frontend directory invalid");
  }
  const assetDir = join(root, "assets");
  if (!lstatSync(assetDir).isDirectory() || lstatSync(assetDir).isSymbolicLink()) {
    throw new Error("Compiled assets directory invalid");
  }
  const html = readFileSync(join(root, "index.html"), "utf8");
  if (!html.includes('id="root"') || html.includes("/src/main.tsx")) {
    throw new Error("Missing production frontend document");
  }
  const urls = [...html.matchAll(/(?:src|href)="(\/assets\/[^"]+)"/g)]
    .map(m => m[1]);
  if (!urls.some(url => url.endsWith(".js"))) throw new Error("Missing compiled JavaScript");
  if (!urls.some(url => url.endsWith(".css"))) throw new Error("Missing compiled CSS");
  const assets = new Map();
  for (const entry of readdirSync(assetDir, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) throw new Error("Compiled assets symlink forbidden: " + entry.name);
    if (!entry.isFile()) throw new Error("Invalid compiled frontend asset: " + entry.name);
  }
  for (const url of urls) {
    if (!ASSET.test(url)) throw new Error("Invalid or external build reference");
    const path = join(root, url.slice(1));
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error("Built frontend asset is not a real file: " + url);
    }
    const body = readFileSync(path);
    if (!body.length) throw new Error("Built frontend asset is empty: " + url);
    assets.set(url, {
      body,
      contentType: url.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8"
    });
  }
  return Object.freeze({ html, assets });
}

export function compiledResponseForPath(path, web) {
  if (path === "/") return { body: web.html, contentType: "text/html; charset=utf-8" };
  if (!path.startsWith("/assets/")) return null; // includes /api/**: never mocked
  if (!ASSET.test(path) || path.includes("..")) {
    throw new Error("Invalid compiled asset path");
  }
  const response = web.assets.get(path);
  if (!response) throw new Error("Asset was not built: " + path);
  return response;
}

export function validateRealApiSample(sample) {
  if (!sample || typeof sample !== "object" ||
      sample.subject !== "reviewer" || sample.authorized !== true ||
      sample.productionJs !== true || sample.productionCss !== true ||
      sample.documentReady !== true || sample.checklistReady !== true ||
      sample.apiErrors !== 0 || sample.externalRequests !== 0 ||
      sample.mutations !== 0 ||
      !Number.isSafeInteger(sample.apiReads) || sample.apiReads < 5) {
    throw new Error("Missing authorized real-API workflow evidence");
  }
  const durations = {};
  for (const key of STAGES) {
    const value = sample[key];
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      throw new Error("Invalid or missing real-API lab measurement: " + key);
    }
    durations[key] = value;
  }
  return durations;
}
function median(values) {
  const sorted = [...values].sort((a,b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}
export function summarizeRealApiLab(samples) {
  if (!Array.isArray(samples) || samples.length < 3) {
    throw new Error("At least three independent real-API browser runs required");
  }
  const entries = samples.map(validateRealApiSample);
  return {
    navigations: entries.length,
    backend: "local-real-handler-jwt-rs256-sqlite",
    median: Object.fromEntries(STAGES.map(key => [key, median(entries.map(s => s[key]))]))
  };
}
