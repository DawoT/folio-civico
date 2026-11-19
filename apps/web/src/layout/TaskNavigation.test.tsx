import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { TaskNavigation } from "./TaskNavigation";

describe("IA-001 task navigation", () => {
  it("provides an accessible local navigation without inventing workflow totals or routes", () => {
    const html = renderToStaticMarkup(
      <TaskNavigation hasScope canDraft canAdmin commissionName="Comisión de prueba"
        batchLabel="Obras · 2026" onOpenAdministration={() => {}} />
    );
    expect(html).toContain('aria-label="Áreas de trabajo"');
    for (const target of ["#expedientes", "#checklist", "#registrar-busqueda", "#observaciones", "#informes", "#administracion"]) {
      expect(html).toContain(`href="${target}"`);
    }
    expect(html).toContain("Comisión de prueba");
    expect(html).toContain("Obras · 2026");
    expect(html).not.toMatch(/\b(?:100|99)%\s*(?:completo|revisado)/);
  });

  it("hides drafting and administration actions from read-only users", () => {
    const html = renderToStaticMarkup(
      <TaskNavigation hasScope canDraft={false} canAdmin={false} commissionName="Comisión X" />
    );
    expect(html).toContain('href="#checklist"');
    expect(html).toContain('href="#observaciones"');
    expect(html).not.toContain('href="#registrar-busqueda"');
    expect(html).not.toContain('href="#administracion"');
  });

  it("allows presidency to discover administration before a batch is opened", () => {
    const html = renderToStaticMarkup(
      <TaskNavigation hasScope={false} canDraft={false} canAdmin commissionName="Comisión X" />
    );
    expect(html).toContain('href="#administracion"');
    expect(html).not.toContain('href="#expedientes"');
    expect(html).not.toContain('href="#informes"');
  });

  it("does not display a redundant navigation when the user has no current scope or permissions", () => {
    const html = renderToStaticMarkup(
      <TaskNavigation hasScope={false} canDraft={false} canAdmin={false} />
    );
    expect(html).toBe("");
  });
});
