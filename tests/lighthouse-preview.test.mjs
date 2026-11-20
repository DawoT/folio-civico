import { afterEach, describe, expect, it } from "vitest";
import { startLighthousePreview } from "../scripts/lighthouse-preview.mjs";

const running = [];
afterEach(()=>{
  for(const child of running.splice(0)) {
    if(child.exitCode === null) child.kill("SIGKILL");
  }
});

function fixture(script, timeoutMs=1600, expectedUrl="http://127.0.0.1:4181/") {
  return startLighthousePreview({
    command:process.execPath,
    args:["-e",script],
    cwd:process.cwd(),
    expectedUrl,
    timeoutMs
  });
}

describe("PERF-003 Vite preview startup fail-closed diagnostics",()=>{
  it("redacts arbitrary startup stdout/stderr while retaining safe failure markers",async()=>{
    let message="";
    try {
      await fixture(
        "console.log('ENOENT API_KEY=preview-secret URL=https://private.invalid/secret');"+
        "console.error('EACCES sandbox Authorization: Bearer jwt-private');process.exit(9);"
      );
    }catch(error){ message=error.message; }
    expect(message).toMatch(/preview.*exit 9.*stdout=.*ENOENT.*stderr=.*EACCES/i);
    expect(message).not.toMatch(/preview-secret|jwt-private|Authorization|Bearer|private.invalid|\/secret/);
  });

  it("categorizes occupied ports and arbitrary ERR_ codes without logging raw identifiers",async()=>{
    let message="";
    try{
      await fixture(
        "console.error('Error: Port 4181 is already in use; ERR_PRIVATE_AUTH_TOKEN');"+
        "process.exit(1);"
      );
    }catch(error){ message=error.message; }
    expect(message).toMatch(/preview.*exit 1.*port-in-use/i);
    expect(message).toContain("node-error");
    expect(message).not.toMatch(/4181|PRIVATE_AUTH_TOKEN|ERR_PRIVATE/);
  });

  it("does not accept a foreign Vite URL and never leaks it",async()=>{
    await expect(fixture(
      "console.log('  ➜  Local:   http://127.0.0.1:4182/');"+
      "console.log('API_KEY=private-data');process.exit(0);"
    )).rejects.toThrow(/preview returned unexpected loopback port/i);
  });

  it("accepts only its own strict Vite ready marker and returns the live child",async()=>{
    const preview=await fixture(
      "console.log('  ➜  Local:   http://127.0.0.1:4181/');"+
      "setInterval(()=>{},1000);"
    );
    running.push(preview.child);
    expect(preview.url).toBe("http://127.0.0.1:4181/");
    expect(preview.child.exitCode).toBeNull();
    expect(preview.child.pid).toBeGreaterThan(0);
  });

  it("accepts the OS-assigned ephemeral loopback URL from its own Vite marker",async()=>{
    const preview=await fixture(
      "console.log('  ➜  Local:   http://127.0.0.1:48619/');"+
      "setInterval(()=>{},1000);",1600,null
    );
    running.push(preview.child);
    expect(preview.url).toBe("http://127.0.0.1:48619/");
    expect(preview.child.exitCode).toBeNull();
  });

  it("enforces the startup deadline without leaking the child's output",async()=>{
    let message="";
    const started=Date.now();
    try {
      await fixture(
        "console.error('EHOSTUNREACH JWT=secret-timeout');setInterval(()=>{},1000);",
        250
      );
    }catch(error){ message=error.message; }
    expect(message).toMatch(/preview startup timed out.*stderr=EHOSTUNREACH/i);
    expect(message).not.toContain("secret-timeout");
    expect(Date.now()-started).toBeLessThan(1250);
  });
});
