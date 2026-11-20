import { expect, type Locator, type Page, type TestInfo } from "@playwright/test";
import { writeFile } from "node:fs/promises";

/** Synthetic-only browser telemetry for diagnosing intermittent anchor scroll.
 * Captures geometry and timing, never DOM text, URLs, cookies or request bodies.
 */
interface ScrollSample { atMs:number; scrollY:number }
interface ShiftSample { atMs:number; value:number }
interface ProbeState { scrolls:ScrollSample[]; shifts:ShiftSample[] }
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
  const before=await snapshotTaskNavigation(page,id);
  const started=Date.now();
  try{
    await nav.getByRole("link",{name:label,exact:true}).click();
    await expect(page).toHaveURL(new RegExp(`#${id}$`));
    await expect(page.locator(`#${id}`)).toBeVisible();
    visited.push({id,elapsedMs:Date.now()-started,before,
      after:await snapshotTaskNavigation(page,id)});
  }catch(error){
    let after:unknown={unavailable:true};
    try{after=await snapshotTaskNavigation(page,id);}catch{/* retain original click error */}
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
    const state:ProbeState={scrolls:[],shifts:[]};
    target.__folioTaskNavProbe=state;
    const limit=64;
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

export async function snapshotTaskNavigation(page:Page,landmarkId:string) {
  return page.evaluate(id=>{
    const probe=(window as ProbeWindow).__folioTaskNavProbe;
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
      shiftSamples:(probe?.shifts??[]).slice(-30)
    };
  },landmarkId);
}
