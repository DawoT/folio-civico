import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLighthouseCli } from "../scripts/lighthouse-cli.mjs";

const directories=[];
afterEach(()=>{
  for(const path of directories.splice(0))rmSync(path,{recursive:true,force:true});
});
function fixture(script, timeoutMs=1500) {
  const dir=mkdtempSync(join(tmpdir(),"folio-lh-cli-test-"));
  directories.push(dir);
  const outputPath=join(dir,"result.json");
  return runLighthouseCli({
    command:process.execPath,args:["-e",script,outputPath],
    cwd:dir,env:process.env,outputPath,timeoutMs
  });
}

describe("PERF-003 Lighthouse CLI report integrity and safe process diagnostics",()=>{
  it("fails closed when a successful child writes no JSON, retaining safe stdout/stderr markers",async()=>{
    await expect(fixture(
      "console.log('Chromium launch failed: ENOENT API_KEY=stdout-secret');"+
      "console.error('Error: EACCES Bearer stderr-secret'); process.exit(0);"
    )).rejects.toThrow(/exit 0.*missing JSON report.*stdout=.*ENOENT.*stderr=.*EACCES/i);
    try {
      await fixture("console.error('Authorization: Bearer private-jwt');process.exit(0);");
    }catch(error){
      expect(error.message).not.toMatch(/private-jwt|Authorization|Bearer/);
    }
  });

  it("fails on an empty or corrupt JSON report even if the child exits 0",async()=>{
    await expect(fixture(
      "require('node:fs').writeFileSync(process.argv[1],'');process.exit(0)"
    )).rejects.toThrow(/empty JSON report/i);
    await expect(fixture(
      "require('node:fs').writeFileSync(process.argv[1],'{broken');"+
      "console.error('ENOENT client_secret=hush');process.exit(0)"
    )).rejects.toThrow(/invalid JSON report.*stderr=.*ENOENT/i);
  });

  it("fails on a nonzero child exit or abnormal termination without inventing results",async()=>{
    await expect(fixture(
      "console.error('Chrome crash: ECONNREFUSED token=hidden');process.exit(7)"
    )).rejects.toThrow(/exit 7.*stderr=.*ECONNREFUSED/i);
    await expect(fixture(
      "console.error('Chrome crashed');process.kill(process.pid,'SIGTERM')"
    )).rejects.toThrow(/signal SIGTERM/i);
  });

  it("distinguishes timeout from ordinary exit and rejects stalled processes",async()=>{
    await expect(fixture(
      "setInterval(()=>{},1000)",300
    )).rejects.toThrow(/timed out/i);
  });

  it("returns the actual valid JSON when every child requirement was met",async()=>{
    const report={lighthouseVersion:"13.6.0",requestedUrl:"http://127.0.0.1:4181/"};
    const result=await fixture(
      "require('node:fs').writeFileSync(process.argv[1],JSON.stringify("+JSON.stringify(report)+"));"
    );
    expect(result).toEqual(report);
  });
});
