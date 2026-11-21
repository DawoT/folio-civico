import { execFileSync } from "node:child_process";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";

const readConfiguredPort = (override?:string,cwd=process.cwd()):number => {
  const env={...process.env};
  delete env.FOLIO_E2E_PORT;
  if(override!==undefined)env.FOLIO_E2E_PORT=override;
  const configURL=pathToFileURL(resolve(process.cwd(),"playwright.config.ts")).href;
  const script=`import config from ${JSON.stringify(configURL)}; console.log(JSON.stringify({baseURL:config.use.baseURL,webServerURL:config.webServer.url,command:config.webServer.command}))`;
  const output=execFileSync(process.execPath,[
    "--input-type=module","-e",script
  ],{cwd,env,encoding:"utf8",stdio:["ignore","pipe","pipe"]});
  const settings=JSON.parse(output.trim()) as {
    baseURL:string;webServerURL:string;command:string
  };
  const port=Number(new URL(settings.baseURL).port);
  expect(new URL(settings.webServerURL).port).toBe(String(port));
  expect(settings.command).toContain(`--port ${port} --strictPort`);
  return port;
};

it("selects a nondefault port for standalone E2E when none is configured",()=>{
  const port=readConfiguredPort();
  expect(port).toBeGreaterThan(1023);
  expect(port).toBeLessThanOrEqual(65535);
  expect(port).not.toBe(4175);
});

it("uses the same port in independent Playwright worker processes",()=>{
  const first=readConfiguredPort();
  const second=readConfiguredPort();
  expect(second).toBe(first);
});

it("assigns different default ports to separate worktree paths",()=>{
  const first=readConfiguredPort();
  const second=readConfiguredPort(undefined,join(process.cwd(),"tests"));
  expect(second).not.toBe(first);
});

it("preserves an explicit FOLIO_E2E_PORT override",()=>{
  expect(readConfiguredPort("43187")).toBe(43187);
});

it("rejects unsafe explicit port overrides instead of silently switching",()=>{
  expect(()=>readConfiguredPort("80")).toThrow();
  expect(()=>readConfiguredPort("65536")).toThrow();
});
