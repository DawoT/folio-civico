import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { reviewDecisionProgress, ReviewDecisionGuidance } from "./ReviewDecisionGuidance";

describe("UX-4.2 independent review form progress", () => {
  it("counts trimmed characters consistently with the actual human review gate", () => {
    expect(reviewDecisionProgress("  abc  ",false)).toEqual({
      length:3, remaining:12, enough:false, confirmed:false
    });
    expect(reviewDecisionProgress(" ".repeat(15),true).enough).toBe(false);
    expect(reviewDecisionProgress("x".repeat(15),true).enough).toBe(true);
    expect(reviewDecisionProgress("x".repeat(1001),true).enough).toBe(false);
    expect(reviewDecisionProgress("x".repeat(1001),true).remaining).toBe(0);
  });

  it("never labels a filled form as officially verified, and tells users what remains", () => {
    const pending=renderToStaticMarkup(
      <ReviewDecisionGuidance id="decision-guidance-test" note="corta" confirmed={false}/>
    );
    expect(pending).toContain('id="decision-guidance-test"');
    expect(pending).toContain("Faltan 10 caracteres");
    expect(pending).toContain("Confirma que la revisión fue independiente");
    expect(pending).not.toContain("Aprobada");

    const ready=renderToStaticMarkup(
      <ReviewDecisionGuidance id="decision-guidance-test" note={"x".repeat(15)} confirmed/>
    );
    expect(ready).toContain("Requisitos de formulario completos");
    expect(ready).toContain("La decisión será verificada por el servidor");
    expect(ready).not.toContain("Aprobada");
  });

  it("informs about exceeding the limit, without promising submit eligibility", () => {
    const html=renderToStaticMarkup(
      <ReviewDecisionGuidance id="decision-guidance-test" note={"x".repeat(1001)} confirmed/>
    );
    expect(html).toContain("Supera el límite de 1000 caracteres");
    expect(html).not.toContain("Requisitos de formulario completos");
  });
});
