import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openPage(page: Page, actor: string) {
  const api = new SyntheticPilotApi();
  await api.attach(page, actor);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Mesa de revisión" })).toBeVisible();
  return api;
}

async function openLot(page: Page) {
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Historial de observaciones" })).toBeVisible();
}

async function noHorizontalOverflow(page: Page) {
  const result = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    return {
      scroll: Math.max(document.body.scrollWidth, document.documentElement.scrollWidth) - vw,
      elements: Array.from(document.body.querySelectorAll("*"))
        .filter(el => {
          const rect=el.getBoundingClientRect();
          return rect.width > 0 && rect.right > vw + 1
            && getComputedStyle(el).position !== "fixed";
        })
        .slice(0, 8)
        .map(el => ({ tag:el.tagName, className:String(el.className).slice(0,70) }))
    };
  });
  expect(result).toEqual({scroll:0,elements:[]});
}

async function wcagScan(page: Page) {
  const scan = await new AxeBuilder({page})
    .withTags(["wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"])
    .analyze();
  expect(scan.violations.map(issue => issue.id)).toEqual([]);
}

test("200% root text preference enlarges essential information and remains usable",async({page})=>{
  await openPage(page,"viewer");
  await openLot(page);
  const before=await page.evaluate(() => Object.fromEntries(
    [".intro h1",".intro p:not(.eyebrow)",".scope-form .fc-field-label",
      ".review-card h3",".review-note",".brand strong"].map(selector=>{
      const el=document.querySelector(selector);
      if(!(el instanceof HTMLElement)) throw new Error("Missing "+selector);
      return [selector,Number.parseFloat(getComputedStyle(el).fontSize)];
    })
  ));
  await page.evaluate(() => {document.documentElement.style.fontSize="32px";});
  const after=await page.evaluate(() => Object.fromEntries(
    [".intro h1",".intro p:not(.eyebrow)",".scope-form .fc-field-label",
      ".review-card h3",".review-note",".brand strong"].map(selector=>{
      const el=document.querySelector(selector);
      if(!(el instanceof HTMLElement)) throw new Error("Missing "+selector);
      return [selector,Number.parseFloat(getComputedStyle(el).fontSize)];
    })
  ));
  for(const name of Object.keys(before)){
    expect(after[name],name).toBeGreaterThanOrEqual(before[name]! * 1.9);
  }
  await noHorizontalOverflow(page);
  await expect(page.getByRole("button",{name:"Exportar revisión interna (JSON)"})).toBeVisible();
});


test("document filenames and evidence metadata honor 200% text without exposing quarantine originals",async({page})=>{
  await openPage(page,"author");
  await openLot(page);
  const file=page.getByLabel("Incorporar un expediente PDF");
  await file.setInputFiles({
    name:"expediente-accesibilidad.pdf",mimeType:"application/pdf",
    buffer:Buffer.from("%PDF-1.7\\n1 0 obj\\n<< /Type /Catalog >>\\nendobj\\n%%EOF")
  });
  await page.getByRole("button",{name:"Registrar PDF"}).click();
  await expect(page.getByText("PDF recibido en cuarentena")).toBeVisible();
  await expect(page.locator(".document-details strong").filter({hasText:"expediente-accesibilidad.pdf"})).toBeVisible();

  const selectors=[".document-details strong",".document-details small",
    ".evidence-detail h3",".evidence-detail dt",".evidence-detail dd"];
  const sizes=async()=>page.evaluate((items:string[])=>Object.fromEntries(items.map(sel=>{
    const el=document.querySelector(sel);
    if(!(el instanceof HTMLElement)) throw new Error("Missing "+sel);
    return [sel,Number.parseFloat(getComputedStyle(el).fontSize)];
  })),selectors);
  const before=await sizes();
  await page.evaluate(()=>{document.documentElement.style.fontSize="32px";});
  const after=await sizes();
  for(const selector of selectors) {
    expect(after[selector],selector).toBeGreaterThanOrEqual(before[selector]! * 1.9);
  }
  await noHorizontalOverflow(page);
  expect(await page.locator("iframe, embed, object").count()).toBe(0);
});


test("forced-colors preserves visible selected records, pressed filters and keyboard focus",async({page})=>{
  await page.emulateMedia({forcedColors:"active"});
  await openPage(page,"author");
  await openLot(page);
  const file=page.getByLabel("Incorporar un expediente PDF");
  await file.setInputFiles({
    name:"alto-contraste.pdf",mimeType:"application/pdf",
    buffer:Buffer.from("%PDF-1.7\\n1 0 obj\\n<< /Type /Catalog >>\\nendobj\\n%%EOF")
  });
  await page.getByRole("button",{name:"Registrar PDF"}).click();
  await expect(page.getByText("PDF recibido en cuarentena")).toBeVisible();
  const selected=page.locator(".document-item.selected");
  await expect(selected).toContainText("En cuarentena");
  const selectedStyle=await selected.evaluate(el=>{
    const s=getComputedStyle(el);
    return {width:parseFloat(s.borderInlineStartWidth),style:s.borderInlineStartStyle};
  });
  expect(selectedStyle.style).toBe("solid");
  expect(selectedStyle.width).toBeGreaterThanOrEqual(3);
  const pressed=page.getByRole("group",{name:"Filtrar ítems del checklist"})
    .getByRole("button",{name:/Todos/});
  await expect(pressed).toHaveAttribute("aria-pressed","true");
  const pressedWidth=await pressed.evaluate(el=>parseFloat(getComputedStyle(el).borderTopWidth));
  expect(pressedWidth).toBeGreaterThanOrEqual(2);
  await page.keyboard.press("Tab");
  await noHorizontalOverflow(page);
  await wcagScan(page);
});

test("WCAG 1.4.12 text spacing does not clip controls, hints, or reports",async({page})=>{
  await openPage(page,"president");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByRole("link",{name:"Administración"}).click();
  await page.addStyleTag({content:`
    body :is(p,li,span,label,small,a,button,dt,dd,input,textarea,select) {
      letter-spacing: .12em !important;
      word-spacing: .16em !important;
      line-height: 1.5 !important;
    }
    body p { margin-bottom: 2em !important; }
  `});
  await expect(page.getByRole("heading",{name:"Administración de miembros"})).toBeVisible();
  await expect(page.getByLabel("Identificador de Access (sub)")).toBeVisible();
  await noHorizontalOverflow(page);
  await wcagScan(page);
  const input=page.getByLabel("Identificador de Access (sub)");
  await input.fill("subject_wcag_spacing");
  await page.getByLabel("Rol inicial").selectOption("advisor");
  await page.getByRole("button",{name:"Incorporar miembro"}).click();
  await expect(page.getByRole("status").filter({hasText:"Membresía actualizada"})).toBeVisible();
});

test("long identifiers and native keyboard controls reflow at 320 CSS px",async({page})=>{
  const api=await openPage(page,"president");
  const subject="long_subject_"+"segment_".repeat(20);
  api.commission.members.set(subject,{subject,role:"advisor",active:true,revision:1});
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByRole("link",{name:"Administración"}).click();
  await expect(page.getByText(subject,{exact:true})).toBeVisible();
  await noHorizontalOverflow(page);
  await page.keyboard.press("Tab");
  await expect(page.getByRole("heading",{name:"Administración de miembros"})).toBeVisible();
  await wcagScan(page);
});

test("review forms remain operable with 200% text and long documented scopes",async({page,context})=>{
  const api=new SyntheticPilotApi();
  const author=await context.newPage();
  try {
    await api.attach(author,"author");
    await author.goto("/");
    await openLot(author);
    await author.getByLabel("Ítem esperado",{exact:true}).selectOption("item_a");
    await author.getByLabel("Título del registro").fill("Observación de accesibilidad");
    await author.getByLabel("Alcance de la búsqueda").fill(
      "Se revisaron los registros sintéticos del lote y se adjuntaron referencias documentales. ".repeat(10)
    );
    await author.getByRole("checkbox",{name:/Confirmo que realicé esta búsqueda/}).check();
    await author.getByRole("button",{name:"Guardar borrador"}).click();
    await author.getByRole("button",{name:"Enviar a revisión"}).click();
    await expect(author.getByText("Borrador enviado a revisión")).toBeVisible();
  }finally{await author.close();}
  await api.attach(page,"reviewer");
  await page.goto("/");
  await openLot(page);
  await page.getByRole("button",{name:"Revisar registro"}).click();
  await page.evaluate(() => {document.documentElement.style.fontSize="32px";});
  const note=page.getByLabel("Justificación de la decisión humana");
  await expect(note).toBeVisible();
  await note.fill("Se realizó una revisión documental independiente del registro sintético.");
  await page.getByRole("checkbox",{name:/Confirmo que revisé la evidencia/}).check();
  await noHorizontalOverflow(page);
  await wcagScan(page);
  await page.getByRole("button",{name:"Validar internamente"}).click();
  await expect(page.getByText("Registro validado por un segundo revisor")).toBeVisible();
});
