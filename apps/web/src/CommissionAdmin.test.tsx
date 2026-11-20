import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { BootstrapCommissionPanel, CommissionAdminPanel } from "./CommissionAdmin";

describe("UX-4.2 commission administration forms", () => {
  it("uses linked native controls and contextual instructions for a new member's Access identity", () => {
    const html=renderToStaticMarkup(
      <CommissionAdminPanel commissionId="c_a" currentSubject="president"/>
    );
    expect(html).toContain('class="fc-field"');
    expect(html).toContain('for="new-member-subject"');
    expect(html).toContain('id="new-member-subject"');
    expect(html).toContain('id="new-member-subject-hint"');
    expect(html).toMatch(/id="new-member-subject"[^>]*aria-describedby="new-member-subject-hint"/);
    expect(html).toContain("Identificador exacto de Access");
    expect(html).toContain('autoComplete="off"');
    expect(html).toContain('for="new-member-role"');
    expect(html).toContain('id="new-member-role-hint"');
    expect(html).toContain("No uses una dirección de correo supuesta");
    expect(html).toContain('type="submit"');
    expect(html).toContain("Incorporar miembro");
  });

  it("keeps creation disabled without explicit identity confirmation and links form hints", () => {
    const html=renderToStaticMarkup(
      <BootstrapCommissionPanel onCreated={()=>{}}/>
    );
    expect(html).toContain('for="bootstrap-name"');
    expect(html).toContain('for="bootstrap-president"');
    expect(html).toContain('id="bootstrap-president-hint"');
    expect(html).toContain('aria-describedby="bootstrap-president-hint"');
    expect(html).toContain("Identidad Access previamente verificada");
    expect(html).toContain('type="checkbox"');
    expect(html).toContain('disabled=""');
    expect(html).toContain("Crear comisión");
  });
});
