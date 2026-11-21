import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFile } from "node:fs/promises";
import { SyntheticPilotApi } from "./synthetic-api";

// Playwright 1.65.1 reproducibly loses a retained trace in this Axe pilot flow.
// Record the entire pilot spec instead of disabling tracing or a11y assertions.
test.use({ trace: "on" });

async function selectPilot(page: import("@playwright/test").Page) {
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button",{name:"Abrir lote"}).click();
  await expect(page.getByRole("heading",{name:"Checklist de constatación"})).toBeVisible();
  await expect(page.getByText("Expediente de obra").first()).toBeVisible();
}

async function expectA11y(page:import("@playwright/test").Page) {
  const scan=await new AxeBuilder({page}).withTags([
    "wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"
  ]).analyze();
  expect(scan.violations.map(item=>({
    rule:item.id,impact:item.impact,
    elements:item.nodes.map(node=>node.target.join(" "))
  }))).toEqual([]);
  const overflow=await page.evaluate(()=>{
    const width=document.documentElement.clientWidth;
    return Array.from(document.body.querySelectorAll("*")).filter(el=>{
      const rect=el.getBoundingClientRect();
      return rect.width>0 && rect.right>width+1;
    }).slice(0,12).map(el=>{
      const rect=el.getBoundingClientRect();
      return {element:el.tagName.toLowerCase(),className:String(el.className).slice(0,90),
        right:Math.round(rect.right),width:Math.round(rect.width)};
    });
  });
  expect(overflow).toEqual([]);
}

test("a11y: initial, empty, and president administration screens",async({page})=>{
  const api=new SyntheticPilotApi();
  await api.attach(page,"president");
  await page.goto("/");
  await expect(page.getByRole("heading",{name:"Mesa de revisión"})).toBeVisible();
  await expect(page.getByText("No constituye el acta oficial")).toBeVisible();
  await expectA11y(page);
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await expect(page.getByRole("heading",{name:"Administración de miembros"})).toBeHidden();
  await page.getByRole("link", {name:"Administración"}).click();
  await expect(page.getByRole("heading",{name:"Administración de miembros"})).toBeVisible();
  await expectA11y(page);

  const memberInput=page.getByLabel("Identificador de Access (sub)");
  await memberInput.fill("pilot_new_member");
  await page.getByLabel("Rol inicial").selectOption("advisor");
  await page.getByRole("button",{name:"Incorporar miembro"}).click();
  await expect(page.getByText("pilot_new_member",{exact:true})).toBeVisible();
  expect(api.commission.members.get("pilot_new_member")).toMatchObject({
    role:"advisor",active:true,revision:1
  });
  const add=api.calls.find(c=>c.path.endsWith("/members")&&c.method==="POST");
  expect(add?.idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);

  const createBatch=page.getByLabel("Nuevo lote de expedientes");
  await createBatch.fill("Lote nuevo accesible");
  await page.getByRole("button",{name:"Crear lote"}).click();
  await expect(page.getByRole("status").filter({hasText:"Lote creado"})).toBeVisible();
  await expectA11y(page);
});

test("a11y: two real browser pages complete manual review and SHA-256 download",async({page,context})=>{
  const api=new SyntheticPilotApi();
  await api.attach(page,"author");
  await page.goto("/");
  await selectPilot(page);

  await page.getByLabel("Ítem esperado",{exact:true}).selectOption("item_a");
  await page.getByLabel("Título del registro").fill("Expediente no ubicado en el lote");
  await page.getByLabel("Alcance de la búsqueda")
    .fill("Se revisaron las versiones del lote, el registro y los antecedentes sintéticos.");
  await page.getByRole("checkbox",{name:/Confirmo que realicé esta búsqueda/}).check();
  await page.getByRole("button",{name:"Guardar borrador"}).click();
  await expect(page.getByText("Se registró un borrador de búsqueda")).toBeVisible();
  await expect(page.getByRole("button",{name:"Enviar a revisión"})).toBeVisible();
  await page.getByRole("button",{name:"Enviar a revisión"}).click();
  await expect(page.getByText("Borrador enviado a revisión")).toBeVisible();
  await expect(page.getByRole("button",{name:"Revisar registro"})).toHaveCount(0);
  expect(api.observations[0]?.status).toBe("in_review");

  const reviewer=await context.newPage();
  try{
    await api.attach(reviewer,"reviewer");
    await reviewer.goto("/");
    await selectPilot(reviewer);
    await expect(reviewer.getByRole("button",{name:"Revisar registro"})).toBeVisible();
    await reviewer.getByRole("button",{name:"Revisar registro"}).click();
    await reviewer.getByLabel("Justificación de la decisión humana")
      .fill("Verifiqué independientemente el alcance documental de la búsqueda sintética.");
    await reviewer.getByRole("checkbox",{name:/Confirmo que revisé la evidencia/}).check();
    await reviewer.getByRole("button",{name:"Validar internamente"}).click();
    await expect(reviewer.getByText("Registro validado por un segundo revisor")).toBeVisible();
    await expect(reviewer.getByText("No ubicado · validación interna",{exact:true})).toBeVisible();
    expect(api.observations[0]).toMatchObject({
      status:"validated",reviewedBy:"reviewer",validatedBy:"reviewer"
    });

    await reviewer.getByRole("button",{name:"Ver validación"}).click();
    await expect(reviewer.getByRole("heading",{name:"Detalle de la observación"})).toBeVisible();
    await expect(reviewer.getByText("Verifiqué independientemente el alcance documental de la búsqueda sintética.",{exact:true})).toBeVisible();
    await expectA11y(reviewer);

    const downloadEvent=reviewer.waitForEvent("download");
    await reviewer.getByRole("button",{name:"Exportar revisión interna (JSON)"}).click();
    const download=await downloadEvent;
    expect(download.suggestedFilename()).toBe("folio-civico-c_a-revision-interna.json");
    const raw=JSON.parse(await readFile(await download.path()!,"utf8")) as {
      sha256:string;payload:string;
    };
    expect(raw.sha256).toMatch(/^[a-f0-9]{64}$/);
    const contents=JSON.parse(raw.payload) as {observations:Array<{status:string}>};
    expect(contents.observations).toHaveLength(1);
    expect(contents.observations[0]?.status).toBe("validated");
    await expect(reviewer.getByText("Integridad verificada. SHA-256:")).toBeVisible();
  }finally{await reviewer.close();}
});

test("a11y: observer history over 25 records, opening exact detail, no mutation actions",async({page})=>{
  const api=new SyntheticPilotApi();
  api.addHistory(31);
  await api.attach(page,"viewer");
  await page.goto("/");
  await selectPilot(page);
  await expect(page.getByText("Histórico 030")).toBeVisible();
  await expect(page.getByText("Histórico 000")).toHaveCount(0);
  await page.getByRole("button",{name:"Cargar observaciones anteriores"}).click();
  await expect(page.getByText("Histórico 000")).toBeVisible();
  await expect(page.getByText("Histórico 030")).toBeVisible();
  await expect(page.getByRole("button",{name:"Cargar observaciones anteriores"})).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Enviar a revisión"})).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Revisar registro"})).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Crear lote"})).toHaveCount(0);
  await expect(page.getByRole("heading",{name:"Administración de miembros"})).toHaveCount(0);
  const row=page.locator(".observations-card li").filter({hasText:"Histórico 000"});
  await row.getByRole("button",{name:"Ver detalle"}).click();
  await expect(page.getByRole("heading",{name:"Detalle de la observación"})).toBeVisible();
  await expect(page.locator(".linked-observation-id")).toHaveText("old_000");
  await expectA11y(page);
});

test("keyboard-only commission and batch opening, with visible focus",async({page})=>{
  const api=new SyntheticPilotApi();
  await api.attach(page,"author");
  await page.goto("/");
  await expect(page.getByLabel("Identificador de comisión")).toBeEnabled();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link",{name:"Saltar al contenido principal"})).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Identificador de comisión")).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByLabel("Identificador de comisión")).toHaveValue("c_a");
  await expect(page.getByLabel("Identificador de lote").locator('option[value="b_a"]')).toHaveCount(1);
  await expect(page.getByLabel("Identificador de lote")).toBeEnabled();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Identificador de lote")).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByLabel("Identificador de lote")).toHaveValue("b_a");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button",{name:"Abrir lote"})).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading",{name:"Historial de observaciones"})).toBeVisible();
  await expectA11y(page);
});

test("only PDF files reach quarantine, never a browser preview of the original",async({page})=>{
  const api=new SyntheticPilotApi();
  await api.attach(page,"author");
  await page.goto("/");
  await selectPilot(page);
  const input=page.getByLabel("Incorporar un expediente PDF");
  await input.setInputFiles({
    name:"not-a-pdf.txt",mimeType:"text/plain",buffer:Buffer.from("not a PDF")
  });
  await page.getByRole("button",{name:"Registrar PDF"}).click();
  await expect(page.getByRole("alert").filter({hasText:"Solo se admiten archivos PDF"})).toBeVisible();
  expect(api.documents).toHaveLength(0);
  await input.setInputFiles({
    name:"synthetic.pdf",mimeType:"application/pdf",
    buffer:Buffer.from("%PDF-1.7\\n1 0 obj\\n<< /Type /Catalog >>\\nendobj\\n%%EOF")
  });
  await page.getByRole("button",{name:"Registrar PDF"}).click();
  await expect(page.getByText("PDF recibido en cuarentena")).toBeVisible();
  await expect(page.getByRole("button",{name:"synthetic.pdf En cuarentena"})).toBeVisible();
  expect(api.documents).toHaveLength(1);
  expect(api.calls.filter(c=>c.method==="POST"&&c.path.endsWith("/documents"))).toHaveLength(1);
  expect(await page.locator("iframe,embed,object").count()).toBe(0);
  await expectA11y(page);
});

test("a11y: corrupt export never downloads and visibly reports the integrity failure",async({page})=>{
  const api=new SyntheticPilotApi();
  api.addHistory(1);
  api.corruptExport=true;
  await api.attach(page,"reviewer");
  await page.goto("/");
  await selectPilot(page);
  const downloads:string[]=[];
  page.on("download",download=>downloads.push(download.suggestedFilename()));
  await page.getByRole("button",{name:"Exportar revisión interna (JSON)"}).click();
  await expect(page.getByRole("alert").filter({hasText:"huella SHA-256"})).toBeVisible();
  expect(downloads).toHaveLength(0);
  await expectA11y(page);
});
