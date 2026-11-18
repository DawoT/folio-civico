import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { App } from "./App";

describe("mesa documental accessibility", () => {
  it("identifies the product, non-official output and evidence workspace", () => {
    const html=renderToStaticMarkup(<App />);
    expect(html).toContain("Folio Cívico");
    expect(html).toContain("Mesa de revisión");
    expect(html).toContain("No constituye el acta oficial");
    expect(html).toContain('aria-label="Identificador de comisión"');
    expect(html).toContain('aria-label="Identificador de lote"');
  });
});
