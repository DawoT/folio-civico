import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ChecklistRow } from "../api";
import {
  ChecklistFilters, countChecklistByStatus, filterChecklistRows, isInternallyValidated
} from "./ChecklistFilters";

const entry = (overrides: Partial<ChecklistRow>): ChecklistRow => ({
  id: "item_1", area: "works", expectedDocument: "Expediente",
  status: "pending", statusSource: "stored",
  validatedSearchObservationId: null, reviewedBy: null, reviewedAt: null, ...overrides
});
const rows = [
  entry({id:"pending-works"}),
  entry({id:"pending-proc",area:"procurement"}),
  entry({id:"reviewed",status:"not_located",statusSource:"validated_search",
    validatedSearchObservationId:"obs_1",reviewedBy:"reviewer"}),
  entry({id:"not-located",status:"not_located"}),
  entry({id:"found",status:"located"}),
  entry({id:"observed",status:"observed",area:"procurement"})
];

describe("UX-3.3 contextual checklist filters", () => {
  it("distinguishes human validation from a merely stored not-located state", () => {
    expect(isInternallyValidated(rows[2]!)).toBe(true);
    expect(isInternallyValidated(rows[3]!)).toBe(false);
    expect(isInternallyValidated(entry({statusSource:"validated_search",
      validatedSearchObservationId:null}))).toBe(false);
    expect(filterChecklistRows(rows,"validated","all").map(row=>row.id)).toEqual(["reviewed"]);
    expect(filterChecklistRows(rows,"other","all").map(row=>row.id)).toEqual(["not-located","observed"]);
  });

  it("counts the authorized loaded subset by area and status without changing order", () => {
    expect(countChecklistByStatus(rows,"all")).toEqual({
      all:6,pending:2,validated:1,located:1,other:2
    });
    expect(countChecklistByStatus(rows,"procurement")).toEqual({
      all:2,pending:1,validated:0,located:0,other:1
    });
    expect(filterChecklistRows(rows,"all","procurement").map(row=>row.id))
      .toEqual(["pending-proc","observed"]);
    expect(filterChecklistRows(rows,"pending","works").map(row=>row.id))
      .toEqual(["pending-works"]);
  });

  it("provides an accessible area select and native pressed buttons with explicit loaded scope", () => {
    const html=renderToStaticMarkup(<ChecklistFilters selectedStatus="validated"
      selectedArea="works" counts={countChecklistByStatus(rows,"works")}
      onStatusChange={()=>{}} onAreaChange={()=>{}} />);
    expect(html).toContain('role="group"');
    expect(html).toContain('aria-label="Filtrar ítems del checklist"');
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain("Validación interna");
    expect(html).toContain("Área del checklist para filtrar");
    expect(html).toContain("Solo ítems cargados de la comisión");
    expect(html).toContain('type="button"');
    expect(html).not.toContain("Total institucional");
  });

  it("does not manufacture a validation or a zero when there are no loaded items", () => {
    expect(countChecklistByStatus([], "all")).toEqual({
      all:0,pending:0,validated:0,located:0,other:0
    });
    expect(filterChecklistRows([], "validated","works")).toEqual([]);
  });
});
