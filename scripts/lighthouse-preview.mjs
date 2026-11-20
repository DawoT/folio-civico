/**
 * Own the Vite preview subprocess for local Lighthouse metrics.
 * The raw child output is used only for an exact loopback startup marker,
 * never interpolated into errors (it may include confidential values).
 */
import { spawn } from "node:child_process";
import { diagnosticMarkers } from "./lighthouse-cli.mjs";
import { extractOwnVitePreviewUrl } from "./lighthouse-lab-metrics.mjs";

const MAX_OUTPUT_BYTES = 8000;

function safeProcessCode(error) {
  return typeof error?.code === "string"
    && /^(?:EACCES|EPERM|ENOENT|EADDRINUSE|EAGAIN|EMFILE|UNKNOWN)$/.test(error.code)
    ? error.code : "UNKNOWN";
}

/**
 * @param {{command:string,args:string[],cwd:string,expectedUrl?:string|null,timeoutMs?:number}} config
 * @returns {Promise<{child:import("node:child_process").ChildProcess,url:string}>}
 */
export function startLighthousePreview({
  command,args,cwd,expectedUrl,timeoutMs=25_000
}) {
  return new Promise((resolveReady,rejectReady)=>{
    const child=spawn(command,args,{cwd,stdio:["ignore","pipe","pipe"]});
    let readyOutput="";
    let stdout="";
    let stderr="";
    let settled=false;
    const diagnostics=()=>"stdout="+diagnosticMarkers(stdout)+
      "; stderr="+diagnosticMarkers(stderr);
    const finish=(error,ownedUrl)=>{
      if(settled)return;
      settled=true;
      clearTimeout(timer);
      if(error){
        child.kill("SIGTERM");
        child.stdout.destroy();
        child.stderr.destroy();
        rejectReady(error);
      }else resolveReady({child,url:ownedUrl});
    };
    const timer=setTimeout(()=>finish(new Error(
      "Vite preview startup timed out ("+diagnostics()+")"
    )),timeoutMs);
    const collect=(chunk,stream)=>{
      const value=chunk.toString();
      readyOutput=(readyOutput+value).slice(-MAX_OUTPUT_BYTES);
      if(stream==="stdout")stdout=(stdout+value).slice(-MAX_OUTPUT_BYTES);
      else stderr=(stderr+value).slice(-MAX_OUTPUT_BYTES);
      const ownedUrl=extractOwnVitePreviewUrl(readyOutput);
      if(!ownedUrl)return;
      if(expectedUrl && ownedUrl!==expectedUrl){
        finish(new Error("Vite preview returned unexpected loopback port ("+
          diagnostics()+")"));
      }else finish(null,ownedUrl);
    };
    child.stdout.on("data",chunk=>collect(chunk,"stdout"));
    child.stderr.on("data",chunk=>collect(chunk,"stderr"));
    child.once("error",error=>finish(new Error(
      "Vite preview spawn error ("+safeProcessCode(error)+"): "+diagnostics()
    )));
    child.once("exit",(code,signal)=>{
      if(!settled)finish(new Error(
        "Vite preview stopped before ready ("+
        (signal?"signal "+signal:"exit "+code)+"; "+diagnostics()+")"
      ));
    });
  });
}
