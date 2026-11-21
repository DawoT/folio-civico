import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { installTaskNavigationProbe, navigateTaskWithDiagnostics, snapshotTaskNavigation, type TaskNavigationVisit } from "./task-navigation-diagnostics";

test("a real blocked anchor click produces sanitized evidence and keeps its original timeout",async ({page},testInfo)=>{
  const marker="PRIVATE_NAV_TEXT_MUST_NOT_LEAK";
  await page.setContent(`
    <nav aria-label="Áreas de trabajo">
      <a style="pointer-events:none" href="#registrar-busqueda">${marker}</a>
    </nav>
    <main style="height:3000px">
      <section id="registrar-busqueda">${marker}</section>
    </main>
  `);
  page.setDefaultTimeout(300);
  await installTaskNavigationProbe(page);
  const visited:TaskNavigationVisit[]=[];
  const nav=page.getByRole("navigation",{name:"Áreas de trabajo"});
  await expect(navigateTaskWithDiagnostics(page,nav,testInfo,{
    label:marker,id:"registrar-busqueda"
  },visited)).rejects.toThrow(/Timeout|timeout/i);
  const report=JSON.parse(await readFile(
    testInfo.outputPath("task-anchor-diagnostics.json"),"utf8"
  ));
  expect(report).toMatchObject({
    schemaVersion:1,project:testInfo.project.name,
    currentStep:"registrar-busqueda",visited:[],
    before:{
      landmarkId:"registrar-busqueda",
      viewport:{width:expect.any(Number),height:expect.any(Number)},
      anchor:expect.objectContaining({width:expect.any(Number)})
    },
    after:{landmarkId:"registrar-busqueda"}
  });
  expect(report.elapsedMs).toBeGreaterThan(0);
  expect(report.after.geometrySamples).toEqual(expect.arrayContaining([
    expect.objectContaining({
      atMs:expect.any(Number),scrollY:expect.any(Number),
      navTop:expect.any(Number),anchorTop:expect.any(Number),
      anchorBottom:expect.any(Number),sectionTop:expect.any(Number)
    })
  ]));
  expect(report.after.geometrySamples.length).toBeLessThanOrEqual(32);
  expect(JSON.stringify(report)).not.toContain(marker);
  expect(testInfo.attachments.some(item=>
    item.name==="task-anchor-diagnostics"&&item.contentType==="application/json"
  )).toBe(true);
});

test("synthetic navigation diagnostic captures geometry and scroll without DOM text or credentials", async ({page})=>{
  await page.setContent(`
    <nav aria-label="Áreas de trabajo"><a href="#registrar-busqueda">PRIVATE_NAV_SENTINEL</a></nav>
    <div style="height:10000px"></div>
    <section id="registrar-busqueda">PRIVATE_SECTION_SENTINEL</section>
  `);
  await installTaskNavigationProbe(page);
  const initial=await snapshotTaskNavigation(page,"registrar-busqueda","start");
  expect(initial).toMatchObject({
    landmarkId:"registrar-busqueda",scrollBehavior:"auto",
    nav:expect.objectContaining({height:expect.any(Number)}),
    anchor:expect.objectContaining({width:expect.any(Number)}),
    section:expect.objectContaining({height:expect.any(Number)})
  });
  expect(JSON.stringify(initial)).not.toMatch(/PRIVATE_NAV_SENTINEL|PRIVATE_SECTION_SENTINEL/);
  await page.evaluate(()=>window.scrollTo(0,400));
  await expect.poll(async()=>{
    const snapshot=await snapshotTaskNavigation(page,"registrar-busqueda");
    return snapshot.scrollSamples.length;
  }).toBeGreaterThan(0);
  await expect.poll(async()=>{
    const snapshot=await snapshotTaskNavigation(page,"registrar-busqueda");
    return snapshot.geometrySamples.length;
  }).toBeGreaterThan(1);
  const shifted=await snapshotTaskNavigation(page,"registrar-busqueda","stop");
  expect(shifted.page.scrollY).toBeGreaterThan(0);
  expect(shifted.scrollSamples.at(-1)?.scrollY).toBeGreaterThan(0);
  expect(shifted.geometrySamples.length).toBeLessThanOrEqual(32);
  expect(shifted.geometrySamples.some(sample=>sample.scrollY>0)).toBe(true);
  expect(JSON.stringify(shifted)).not.toMatch(/PRIVATE_NAV_SENTINEL|PRIVATE_SECTION_SENTINEL/);
});
