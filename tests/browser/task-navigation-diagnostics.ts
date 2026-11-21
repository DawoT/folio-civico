import { expect, type Locator, type Page, type TestInfo } from "@playwright/test";
import { writeFile } from "node:fs/promises";

/** Synthetic-only browser telemetry for diagnosing intermittent anchor scroll.
 * Captures geometry and timing, never DOM text, URLs, cookies or request bodies.
 */
interface ScrollSample { atMs:number; scrollY:number }
interface ShiftSample { atMs:number; value:number }
interface GeometrySample {
  atMs:number;
  scrollY:number;
  navTop:number|null;
  anchorTop:number|null;
  anchorBottom:number|null;
  sectionTop:number|null;
}
interface ProbeState {
  scrolls:ScrollSample[];
  shifts:ShiftSample[];
  geometrySamples:GeometrySample[];
  startGeometry?:(id:string)=>void;
  stopGeometry?:()=>void;
}
type ProbeWindow=Window & { __folioTaskNavProbe?:ProbeState };

export interface TaskNavigationVisit {
  id:string;
  elapsedMs:number;
  before:unknown;
  after:unknown;
}

/** Real anchor click with fail-only, sanitized synthetic telemetry.
 * Telemetry must never mask the original Playwright failure.
 */
export async function navigateTaskWithDiagnostics(
  page:Page,nav:Locator,testInfo:TestInfo,step:{label:string;id:string},
  visited:TaskNavigationVisit[]
):Promise<void>{
  const {label,id}=step;
  const before=await snapshotTaskNavigation(page,id,"start");
  const started=Date.now();
  try{
    await nav.getByRole("link",{name:label,exact:true}).click();
    await expect(page).toHaveURL(new RegExp(`#${id}$`));
    await expect(page.locator(`#${id}`)).toBeVisible();
    visited.push({id,elapsedMs:Date.now()-started,before,
      after:await snapshotTaskNavigation(page,id,"stop")});
  }catch(error){
    let after:unknown={unavailable:true};
    try{after=await snapshotTaskNavigation(page,id,"stop");}catch{/* retain original click error */}
    const artifact=testInfo.outputPath("task-anchor-diagnostics.json");
    try{
      await writeFile(artifact,JSON.stringify({
        schemaVersion:1,project:testInfo.project.name,
        currentStep:id,elapsedMs:Date.now()-started,visited,before,after
      },null,2));
      await testInfo.attach("task-anchor-diagnostics",{
        path:artifact,contentType:"application/json"
      });
    }catch{/* never replace the original failure with telemetry errors */}
    throw error;
  }
}

export async function installTaskNavigationProbe(page:Page):Promise<void> {
  await page.evaluate(()=>{
    const target=window as ProbeWindow;
    if(target.__folioTaskNavProbe)return;
    const state:ProbeState={scrolls:[],shifts:[],geometrySamples:[]};
    target.__folioTaskNavProbe=state;
    const limit=64;
    const geometryLimit=32;
    let observedId:string|null=null;
    let frameScheduled=false;
    let lastGeometryAt=-Infinity;
    const sampleGeometry=(atMs:number)=>{
      if(observedId===null || atMs-lastGeometryAt<80)return;
      lastGeometryAt=atMs;
      const nav=document.querySelector('nav[aria-label="Áreas de trabajo"]');
      const anchor=nav?.querySelector<HTMLAnchorElement>(
        'a[href="#'+observedId+'"]'
      );
      const section=document.getElementById(observedId);
      const navBox=nav?.getBoundingClientRect();
      const anchorBox=anchor?.getBoundingClientRect();
      const sectionBox=section?.getBoundingClientRect();
      state.geometrySamples.push({
        atMs:Math.round(atMs),scrollY:Math.round(window.scrollY),
        navTop:navBox?Math.round(navBox.top):null,
        anchorTop:anchorBox?Math.round(anchorBox.top):null,
        anchorBottom:anchorBox?Math.round(anchorBox.bottom):null,
        sectionTop:sectionBox?Math.round(sectionBox.top):null
      });
      if(state.geometrySamples.length>geometryLimit)state.geometrySamples.shift();
    };
    const nextFrame=(atMs:number)=>{
      if(observedId===null){frameScheduled=false;return;}
      sampleGeometry(atMs);
      window.requestAnimationFrame(nextFrame);
    };
    state.startGeometry=(id:string)=>{
      observedId=id;
      state.geometrySamples=[];
      lastGeometryAt=-Infinity;
      // Capture a guaranteed initial point even if Chromium throttles rAF.
      sampleGeometry(performance.now());
      if(!frameScheduled){
        frameScheduled=true;
        window.requestAnimationFrame(nextFrame);
      }
    };
    state.stopGeometry=()=>{observedId=null;};
    window.addEventListener("scroll",()=>{
      state.scrolls.push({
        atMs:Math.round(performance.now()),
        scrollY:Math.round(window.scrollY)
      });
      if(state.scrolls.length>limit) state.scrolls.shift();
    },{passive:true});
    try{
      const observer=new PerformanceObserver(list=>{
        for(const item of list.getEntries()){
          const entry=item as PerformanceEntry & {value?:number};
          if(typeof entry.value!=="number")continue;
          state.shifts.push({atMs:Math.round(entry.startTime),value:entry.value});
          if(state.shifts.length>limit)state.shifts.shift();
        }
      });
      observer.observe({type:"layout-shift",buffered:true});
    }catch{/* Layout Shift observer is optional; scroll coordinates still work. */}
  });
}

export async function snapshotTaskNavigation(
  page:Page,landmarkId:string,sampling:"none"|"start"|"stop"="none"
) {
  return page.evaluate(({id,sampling})=>{
    const probe=(window as ProbeWindow).__folioTaskNavProbe;
    if(sampling==="start")probe?.startGeometry?.(id);
    if(sampling==="stop")probe?.stopGeometry?.();
    const nav=document.querySelector('nav[aria-label="Áreas de trabajo"]');
    const anchor=nav?.querySelector<HTMLAnchorElement>('a[href="#'+id+'"]');
    const section=document.getElementById(id);
    const rect=(element:Element|null|undefined)=>{
      if(!element)return null;
      const box=element.getBoundingClientRect();
      return {
        top:Math.round(box.top),bottom:Math.round(box.bottom),
        left:Math.round(box.left),right:Math.round(box.right),
        width:Math.round(box.width),height:Math.round(box.height)
      };
    };
    return {
      landmarkId:id,
      currentHash:window.location.hash,
      elapsedMs:Math.round(performance.now()),
      viewport:{width:window.innerWidth,height:window.innerHeight},
      page:{scrollY:Math.round(window.scrollY),height:document.documentElement.scrollHeight},
      visibility:document.visibilityState,
      scrollBehavior:getComputedStyle(document.documentElement).scrollBehavior,
      nav:rect(nav),anchor:rect(anchor),section:rect(section),
      animations:document.getAnimations().filter(a=>a.playState==="running").length,
      scrollSamples:(probe?.scrolls??[]).slice(-30),
      shiftSamples:(probe?.shifts??[]).slice(-30),
      geometrySamples:(probe?.geometrySamples??[]).slice(-32)
    };
  },{id:landmarkId,sampling});
}
