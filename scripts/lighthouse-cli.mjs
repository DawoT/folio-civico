/**
 * Executes one Lighthouse CLI process and accepts an actual JSON artifact
 * only after the child has closed successfully. Errors never print raw child
 * output (which could contain URLs, tokens, or environment secrets).
 */
import { spawn } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * Execute the locked workspace Lighthouse binary with Node directly.
 * Avoid an extra pnpm process whose exit/pipes are not the Lighthouse child.
 * The calling runner still validates every JSON report, timeout and origin.
 */
export function localLighthouseInvocation(root, flags) {
  if (typeof root !== "string" || !root
      || !Array.isArray(flags) || !flags.every(flag => typeof flag === "string")) {
    throw new Error("Invalid local Lighthouse invocation");
  }
  const cli=join(root,"node_modules","lighthouse","cli","index.js");
  try {
    if (!statSync(cli).isFile()) throw new Error("Missing pinned CLI file");
  } catch {
    throw new Error("Pinned Lighthouse CLI unavailable");
  }
  return {command:process.execPath,args:[cli,...flags]};
}

const MAX_OUTPUT_BYTES = 7000;
const MAX_JSON_REPORT_BYTES = 64 * 1024 * 1024;
const ERROR_CODES = /\b(?:ENOENT|EACCES|EPERM|EADDRINUSE|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EHOSTUNREACH|EPIPE)\b/g;

/** A safe diagnostic summary: only allowlisted error codes and failure classes. */
export function diagnosticMarkers(output) {
  const raw=typeof output==="string"?output:"";
  const markers=[...new Set(raw.match(ERROR_CODES)??[])].slice(0,5);
  // Arbitrary ERR_* suffixes may encode secrets; never echo them verbatim.
  if (/\bERR_[A-Z0-9_]{2,36}\b/.test(raw)) markers.push("node-error");
  if (/\bEADDRINUSE\b|port.{0,30}in use/i.test(raw)) markers.push("port-in-use");
  if (/chrom(?:e|ium)|devtools/i.test(raw)) markers.push("chromium");
  if (/sandbox/i.test(raw)) markers.push("sandbox");
  if (/timeout|timed out/i.test(raw)) markers.push("timeout");
  if (/network|fetch|http request/i.test(raw)) markers.push("network");
  return [...new Set(markers)].join(",") || "none";
}

function safeErrorCode(error) {
  const code=error?.code;
  return typeof code==="string" && /^[A-Z][A-Z0-9_]{1,35}$/.test(code)
    ? code : "UNKNOWN";
}

function requireFreshOutputPath(path) {
  // A child that exits 0 without writing must NEVER pass via a report left by
  // an earlier run. The caller also supplies a new private temp directory.
  try {
    lstatSync(path);
  } catch(error) {
    if(error?.code==="ENOENT")return;
    throw new Error("Lighthouse report output path cannot be checked");
  }
  throw new Error("Lighthouse report path is pre-existing before launch");
}

function readReport(path, diagnostics) {
  let contents;
  let fd;
  try {
    // O_NONBLOCK avoids a hang on a substituted FIFO; O_NOFOLLOW refuses a
    // symlink even when it is created after the initial path check.
    fd=openSync(path,constants.O_RDONLY | constants.O_NOFOLLOW |
      constants.O_NONBLOCK | constants.O_CLOEXEC);
    const info=fstatSync(fd);
    if(!info.isFile() || info.nlink!==1){
      throw new Error("non-regular JSON report");
    }
    if(info.size>MAX_JSON_REPORT_BYTES){
      throw new Error("oversized JSON report");
    }
    contents=readFileSync(fd,"utf8");
  }catch(error){
    const reason=error?.message==="non-regular JSON report"
      || error?.message==="oversized JSON report" ? error.message
      : error?.code==="ENOENT" ? "missing JSON report"
      : error?.code==="ELOOP" ? "unsafe JSON report"
      : "unreadable JSON report";
    throw new Error("Lighthouse CLI exit 0: " + reason + " (" + diagnostics + ")");
  }finally{
    if(fd!==undefined)closeSync(fd);
  }
  if(contents.trim().length===0){
    throw new Error("Lighthouse CLI exit 0: empty JSON report (" + diagnostics + ")");
  }
  try {
    return JSON.parse(contents);
  }catch{
    throw new Error("Lighthouse CLI exit 0: invalid JSON report (" + diagnostics + ")");
  }
}

/**
 * @param {{command:string,args:string[],cwd:string,env:NodeJS.ProcessEnv,outputPath:string,timeoutMs?:number}} config
 * @returns {Promise<unknown>}
 */
export async function runLighthouseCli({
  command,args,cwd,env,outputPath,timeoutMs=90_000
}) {
  requireFreshOutputPath(outputPath);
  return new Promise((resolve,reject)=>{
    let stdout="";
    let stderr="";
    let timedOut=false;
    let settled=false;
    const child=spawn(command,args,{cwd,env,stdio:["ignore","pipe","pipe"]});
    const diagnostic=()=> "stdout="+diagnosticMarkers(stdout)+
      "; stderr="+diagnosticMarkers(stderr);
    const finish=(error,report)=>{
      if(settled)return;
      settled=true;
      clearTimeout(timer);
      if(error)reject(error);
      else resolve(report);
    };
    const timer=setTimeout(()=>{
      timedOut=true;
      child.kill("SIGKILL");
      // A descendant may inherit these pipes after pnpm has exited; waiting
      // for 'close' can then exceed the deadline. Stop observing them now.
      child.stdout.destroy();
      child.stderr.destroy();
      finish(new Error("Lighthouse CLI timed out after "+timeoutMs+"ms ("+diagnostic()+")"));
    },timeoutMs);
    child.stdout.on("data",chunk=>{
      stdout=(stdout+chunk.toString()).slice(-MAX_OUTPUT_BYTES);
    });
    child.stderr.on("data",chunk=>{
      stderr=(stderr+chunk.toString()).slice(-MAX_OUTPUT_BYTES);
    });
    child.once("error",error=>{
      finish(new Error("Lighthouse process spawn error ("+safeErrorCode(error)+"): "+diagnostic()));
    });
    child.once("close",(code,signal)=>{
      if(timedOut){
        finish(new Error("Lighthouse CLI timed out after "+timeoutMs+"ms ("+diagnostic()+")"));
      }else if(signal){
        finish(new Error("Lighthouse CLI signal "+signal+" ("+diagnostic()+")"));
      }else if(code!==0){
        finish(new Error("Lighthouse CLI exit "+code+" ("+diagnostic()+")"));
      }else{
        try { finish(null,readReport(outputPath,diagnostic())); }
        catch(error){ finish(error); }
      }
    });
  });
}
