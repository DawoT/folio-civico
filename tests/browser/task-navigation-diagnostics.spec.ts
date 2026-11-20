import { expect, test } from "@playwright/test";
import { installTaskNavigationProbe, snapshotTaskNavigation } from "./task-navigation-diagnostics";

test("synthetic navigation diagnostic captures geometry and scroll without DOM text or credentials", async ({page})=>{
  await page.setContent(`
    <nav aria-label="Áreas de trabajo"><a href="#registrar-busqueda">PRIVATE_NAV_SENTINEL</a></nav>
    <div style="height:10000px"></div>
    <section id="registrar-busqueda">PRIVATE_SECTION_SENTINEL</section>
  `);
  await installTaskNavigationProbe(page);
  const initial=await snapshotTaskNavigation(page,"registrar-busqueda");
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
  const shifted=await snapshotTaskNavigation(page,"registrar-busqueda");
  expect(shifted.page.scrollY).toBeGreaterThan(0);
  expect(shifted.scrollSamples.at(-1)?.scrollY).toBeGreaterThan(0);
});
