/**
 * PERF-003: pinned Lighthouse mobile profile over the built frontend, locally.
 * No remote service, no institutional data, no synthetic user-performance claim.
 */
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { chromium } from "@playwright/test";
import { enforceFrontendBudget } from "./check-frontend-budget.mjs";
import { runLighthouseCli, localLighthouseInvocation } from "./lighthouse-cli.mjs";
import { startLighthousePreview } from "./lighthouse-preview.mjs";
import {
  summarizeLighthouseRuns, validateLighthousePort
} from "./lighthouse-lab-metrics.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const web = join(root, "apps/web");
// With no explicit port, ask Vite/OS for a free loopback port. The exact
// process-owned Local: address is still mandatory before any audit begins.
const requestedPort = process.env.FOLIO_LIGHTHOUSE_PORT === undefined
  ? 0 : validateLighthousePort(process.env.FOLIO_LIGHTHOUSE_PORT);
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
  // Preserve the OS-assigned port / explicit strict port behavior of PERF-003.
  // Only the spawned process' own Vite Local: marker may select the URL.
  const viteBin = join(web, "node_modules/vite/bin/vite.js");
  return startLighthousePreview({
    command:process.execPath,
    args:[viteBin, "preview", "--host", "127.0.0.1",
      "--port", String(requestedPort), "--strictPort"],
    cwd:web,
    expectedUrl:requestedPort===0?undefined:`http://127.0.0.1:${requestedPort}/`,
    timeoutMs:25_000
  });
}

async function lighthouseRun(output, chromePath, url) {
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
    const preview = await startPreview();
    server = preview.child;
    const url = preview.url;
    const response = await fetch(url, { redirect: "error" });
    if (response.status !== 200 || !(await response.text()).includes("/assets/")) {
      throw new Error("Lighthouse target is not the built production frontend");
    }
    const reports = [];
    for (let index = 0; index < runs; index++) {
      reports.push(await lighthouseRun(join(temporary, `run-${index + 1}.json`), chromePath, url));
    }
    const summary = summarizeLighthouseRuns(reports, url);
    console.log("PERF-003 LIGHTHOUSE LOCAL (simulated mobile profile): " +
      JSON.stringify({ lighthouse: reports[0].lighthouseVersion, port: Number(new URL(url).port), ...profile, ...summary }));
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
