/**
 * PERF-003: pinned Lighthouse mobile profile over the built frontend, locally.
 * No remote service, no institutional data, no synthetic user-performance claim.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { chromium } from "@playwright/test";
import { enforceFrontendBudget } from "./check-frontend-budget.mjs";
import { runLighthouseCli, localLighthouseInvocation } from "./lighthouse-cli.mjs";
import {
  summarizeLighthouseRuns, validateLighthousePort, hasOwnVitePreviewUrl
} from "./lighthouse-lab-metrics.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const web = join(root, "apps/web");
const port = validateLighthousePort(process.env.FOLIO_LIGHTHOUSE_PORT ?? "4181");
const url = `http://127.0.0.1:${port}/`;
const runs = 3;
const profile = Object.freeze({
  device: "mobile",
  viewport: "390x844 @2x",
  throttling: "simulate",
  rttMs: 150,
  throughputKbps: 1638.4,
  cpuSlowdownMultiplier: 4
});

function startPreview() {
  return new Promise((resolveReady, rejectReady) => {
    // Launch the installed Vite binary directly to own the exact process.
    // --strictPort and a verified own startup marker prevent stale-server reuse.
    const viteBin = join(web, "node_modules/vite/bin/vite.js");
    const child = spawn(process.execPath, [
      viteBin, "preview", "--host", "127.0.0.1", "--port", String(port), "--strictPort"
    ], { cwd: web, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let settled = false;
    const timer = setTimeout(() => finish(new Error("Vite preview startup timed out")), 25_000);
    function finish(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        child.kill("SIGTERM");
        rejectReady(error);
      } else resolveReady(child);
    }
    child.stdout.on("data", data => {
      output = (output + data.toString()).slice(-8000);
      if (hasOwnVitePreviewUrl(output, url)) finish(null);
    });
    child.stderr.on("data", data => {
      output = (output + data.toString()).slice(-8000);
      if (hasOwnVitePreviewUrl(output, url)) finish(null);
    });
    child.once("error", error => finish(error));
    child.once("exit", code => {
      if (!settled) finish(new Error("Vite preview stopped before ready (" + code + "): " + output.slice(-1300)));
    });
  });
}

async function lighthouseRun(output, chromePath) {
  const flags = [
    url,
    "--quiet", "--no-enable-error-reporting",
    "--only-categories=performance",
    "--output=json", "--output-path=" + output,
    "--form-factor=mobile",
    "--screenEmulation.mobile=true",
    "--screenEmulation.width=390",
    "--screenEmulation.height=844",
    "--screenEmulation.deviceScaleFactor=2",
    "--throttling-method=simulate",
    "--throttling.rttMs=150",
    "--throttling.throughputKbps=1638.4",
    "--throttling.cpuSlowdownMultiplier=4",
    "--chrome-flags=--headless=new --no-sandbox --disable-dev-shm-usage --disable-background-networking"
  ];
  return runLighthouseCli({
    ...localLighthouseInvocation(root,flags),outputPath:output,cwd:root,
    env:{ ...process.env, CHROME_PATH:chromePath },timeoutMs:90_000
  });
}

async function main() {
  // No old or missing build can silently turn into a green performance report.
  enforceFrontendBudget(join(web, "dist"));
  const chromePath = chromium.executablePath();
  if (!statSync(chromePath).isFile()) throw new Error("Playwright Chromium binary is missing");

  const temporary = mkdtempSync(join(tmpdir(), "folio-lighthouse-"), { mode: 0o700 });
  let server;
  try {
    server = await startPreview();
    const response = await fetch(url, { redirect: "error" });
    if (response.status !== 200 || !(await response.text()).includes("/assets/")) {
      throw new Error("Lighthouse target is not the built production frontend");
    }
    const reports = [];
    for (let index = 0; index < runs; index++) {
      reports.push(await lighthouseRun(join(temporary, `run-${index + 1}.json`), chromePath));
    }
    const summary = summarizeLighthouseRuns(reports, url);
    console.log("PERF-003 LIGHTHOUSE LOCAL (simulated mobile profile): " +
      JSON.stringify({ lighthouse: reports[0].lighthouseVersion, ...profile, ...summary }));
  } finally {
    if (server && server.exitCode === null) {
      server.kill("SIGTERM");
      await Promise.race([
        new Promise(resolveExit => server.once("exit", resolveExit)),
        delay(1500)
      ]);
    }
    rmSync(temporary, { recursive: true, force: true });
  }
}

main().catch(error => {
  console.error("PERF-003 LIGHTHOUSE FAILED: " + error.message);
  process.exitCode = 1;
});
