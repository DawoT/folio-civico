import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runLighthouseCli, localLighthouseInvocation } from "../scripts/lighthouse-cli.mjs";

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
  it("launches the locally pinned Lighthouse executable directly with Node, never a pnpm wrapper",()=>{
    const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
    const invocation=localLighthouseInvocation(root,["--version"]);
    expect(invocation.command).toBe(process.execPath);
    expect(invocation.args).toEqual([join(root,"node_modules","lighthouse","cli","index.js"),"--version"]);
    const reported=execFileSync(invocation.command,invocation.args,{
      cwd:root,encoding:"utf8",timeout:15_000
    }).trim();
    expect(reported).toBe("13.6.0");
    const empty=mkdtempSync(join(tmpdir(),"folio-lh-uninstalled-"));
    directories.push(empty);
    expect(()=>localLighthouseInvocation(empty,["--version"]))
      .toThrow(/Pinned Lighthouse CLI unavailable/);
  });
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

  it("replaces arbitrary ERR_ codes with a generic non-identifying marker",async()=>{
    let message="";
    try{
      await fixture(
        "console.error('ERR_PRIVATE_SESSION_TOKEN');process.exit(0);"
      );
    }catch(error){ message=error.message; }
    expect(message).toContain("node-error");
    expect(message).not.toMatch(/PRIVATE_SESSION_TOKEN|ERR_PRIVATE/);
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

  it("does not await inherited stdout pipes after its process timeout",async()=>{
    const started=Date.now();
    await expect(fixture(
      "require('node:child_process').spawn(process.execPath,"+
      "['-e','setTimeout(()=>{},1500)'],"+
      "{stdio:['ignore','inherit','inherit']});process.exit(0);",200
    )).rejects.toThrow(/timed out/i);
    expect(Date.now()-started).toBeLessThan(1200);
  });

  it("returns the actual valid JSON when every child requirement was met",async()=>{
    const report={lighthouseVersion:"13.6.0",requestedUrl:"http://127.0.0.1:4181/"};
    const result=await fixture(
      "require('node:fs').writeFileSync(process.argv[1],JSON.stringify("+JSON.stringify(report)+"));"
    );
    expect(result).toEqual(report);
  });
});
