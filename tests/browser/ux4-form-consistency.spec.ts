import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function inspectAccessibility(page: Page) {
  const result = await new AxeBuilder({ page }).withTags([
    "wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"
  ]).analyze();
  expect(result.violations.map(issue => issue.id)).toEqual([]);
  const horizontal = await page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    return Array.from(document.querySelectorAll("*")).filter(el => {
      const bounds=el.getBoundingClientRect();
      return bounds.width > 0 && bounds.right > width + 1;
    }).slice(0,8).map(el => ({ name: el.tagName, className: String(el.className).slice(0,80) }));
  });
  expect(horizontal).toEqual([]);
}

async function openLot(page: Page) {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading",{name:"Historial de observaciones"})).toBeVisible();
}

test("presidency administers real Access subjects with linked hints and consistent feedback",async({page})=>{
  const api=new SyntheticPilotApi();
  await api.attach(page,"president");
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByRole("link",{name:"Administración"}).click();
  const panel=page.getByRole("region",{name:"Administración de miembros"});
  await expect(panel).toBeVisible();
  const identity=page.getByLabel("Identificador de Access (sub)");
  await expect(identity).toBeVisible();
  const hintId=await identity.getAttribute("aria-describedby");
  expect(hintId).toContain("new-member-subject-hint");
  await expect(page.locator("#new-member-subject-hint")).toContainText("Identificador exacto de Access");
  expect(await identity.getAttribute("autocomplete")).toBe("off");
  const role=page.getByLabel("Rol inicial");
  expect(await role.getAttribute("aria-describedby")).toContain("new-member-role-hint");
  await identity.fill("member_synthetic_ux4");
  await role.selectOption("advisor");
  await page.getByRole("button",{name:"Incorporar miembro"}).click();
  await expect(page.getByRole("status").filter({hasText:"Membresía actualizada"})).toBeVisible();
  expect(api.commission.members.get("member_synthetic_ux4")).toMatchObject({
    role:"advisor",active:true,revision:1
  });
  const memberRole=page.getByRole("combobox",{name:"Rol de member_synthetic_ux4"});
  await expect(memberRole).toBeVisible();
  await memberRole.selectOption("observer");
  await page.getByRole("button",{name:"Actualizar rol de member_synthetic_ux4"}).click();
  await expect(page.getByRole("status").filter({hasText:"Membresía actualizada"})).toBeVisible();
  expect(api.commission.members.get("member_synthetic_ux4")).toMatchObject({
    role:"observer",active:true,revision:2
  });
  await expect(page.getByRole("button",{name:"Revocar acceso de president"})).toHaveCount(0);
  await inspectAccessibility(page);
});

test("review decisions explain missing independent justification without bypassing server permission",async({page,context})=>{
  const api=new SyntheticPilotApi();
  const author=await context.newPage();
  try {
    await api.attach(author,"author");
    await openLot(author);
    await author.getByLabel("Ítem esperado",{exact:true}).selectOption("item_a");
    await author.getByLabel("Título del registro").fill("Solicitud de revisión de prueba");
    await author.getByLabel("Alcance de la búsqueda")
      .fill("Se recorrieron documentos sintéticos de comisión y el expediente no se encontró en el lote.");
    await author.getByRole("checkbox",{name:/Confirmo que realicé esta búsqueda/}).check();
    await author.getByRole("button",{name:"Guardar borrador"}).click();
    await author.getByRole("button",{name:"Enviar a revisión"}).click();
    await expect(author.getByText("Borrador enviado a revisión")).toBeVisible();
    await expect(author.getByRole("button",{name:"Revisar registro"})).toHaveCount(0);
  } finally {await author.close();}

  await api.attach(page,"reviewer");
  await openLot(page);
  await page.getByRole("button",{name:"Revisar registro"}).click();
  const note=page.getByLabel("Justificación de la decisión humana");
  const desc=(await note.getAttribute("aria-describedby"))??"";
  expect(desc).toContain("review-decision-guidance-");
  const guidance=page.locator(".fc-decision-guidance");
  await expect(guidance).toContainText("Faltan 15 caracteres");
  const approve=page.getByRole("button",{name:"Validar internamente"});
  await expect(approve).toBeDisabled();
  await note.fill("corta");
  await expect(guidance).toContainText("Faltan 10 caracteres");
  await note.fill("Justificación suficiente");
  await expect(guidance).toContainText("Justificación con la extensión mínima");
  await expect(approve).toBeDisabled();
  await page.getByRole("checkbox",{name:/Confirmo que revisé la evidencia/}).check();
  await expect(guidance).toContainText("Requisitos de formulario completos");
  await expect(guidance).toContainText("verificada por el servidor");
  await expect(approve).toBeEnabled();
  await inspectAccessibility(page);
  await approve.click();
  await expect(page.getByText("Registro validado por un segundo revisor")).toBeVisible();
  expect(api.observations[0]).toMatchObject({status:"validated",validatedBy:"reviewer"});
});

test("read-only users never receive administrative or decision controls after the form migration",async({page})=>{
  const api=new SyntheticPilotApi();
  api.addHistory(2);
  await api.attach(page,"viewer");
  await openLot(page);
  await expect(page.getByRole("region",{name:"Administración de miembros"})).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Revisar registro"})).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Incorporar miembro"})).toHaveCount(0);
  await inspectAccessibility(page);
});
