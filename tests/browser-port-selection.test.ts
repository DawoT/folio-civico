import { execFileSync } from "node:child_process";
import { createServer } from "node:net";
import { expect, it } from "vitest";

const readConfiguredPort = (override?:string):number => {
  const env={...process.env};
  delete env.FOLIO_E2E_PORT;
  if(override!==undefined)env.FOLIO_E2E_PORT=override;
  const script="import config from './playwright.config.ts'; console.log(JSON.stringify({baseURL:config.use.baseURL,webServerURL:config.webServer.url,command:config.webServer.command}))";
  const output=execFileSync(process.execPath,[
    "--input-type=module","-e",script
  ],{cwd:process.cwd(),env,encoding:"utf8",stdio:["ignore","pipe","pipe"]});
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

it("never chooses a port another local browser suite currently holds",async()=>{
  const first=readConfiguredPort();
  const holder=createServer();
  try{
    await new Promise<void>((resolve,reject)=>{
      holder.once("error",(error:NodeJS.ErrnoException)=>{
        // Another CI may already own the fixed port: that is the RED case.
        if(error.code==="EADDRINUSE")resolve();
        else reject(error);
      });
      holder.listen(first,"127.0.0.1",()=>resolve());
    });
    const second=readConfiguredPort();
    expect(second).not.toBe(first);
  }finally{
    if(holder.listening)await new Promise<void>(resolve=>holder.close(()=>resolve()));
  }
});

it("preserves an explicit FOLIO_E2E_PORT override",()=>{
  expect(readConfiguredPort("43187")).toBe(43187);
});

it("rejects unsafe explicit port overrides instead of silently switching",()=>{
  expect(()=>readConfiguredPort("80")).toThrow();
  expect(()=>readConfiguredPort("65536")).toThrow();
});
