import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  filterLoadedObservations, countLoadedObservations, ObservationInboxFilters
} from "./ObservationInbox";

const rows = [
  { id: "pending-other", status: "in_review", canReview: true, canSubmit: false },
  { id: "self", status: "in_review", canReview: false, canSubmit: false },
  { id: "own-draft", status: "draft", canReview: false, canSubmit: true },
  { id: "other-draft", status: "draft", canReview: false, canSubmit: false },
  { id: "validated", status: "validated", canReview: false, canSubmit: false },
  { id: "dismissed", status: "dismissed", canReview: false, canSubmit: false }
] as const;

describe("UX-3.1 filtered observation inbox", () => {
  it("only counts records the API explicitly allows the current actor to review", () => {
    expect(countLoadedObservations(rows)).toEqual({
      all: 6, for_review: 1, my_drafts: 1, decided: 2
    });
    expect(filterLoadedObservations(rows, "for_review").map(row => row.id))
      .toEqual(["pending-other"]);
    expect(filterLoadedObservations(rows, "my_drafts").map(row => row.id))
      .toEqual(["own-draft"]);
  });

  it("filters only loaded records, preserves server ordering, and never claims a global total", () => {
    expect(filterLoadedObservations(rows, "all")).toEqual(rows);
    expect(filterLoadedObservations(rows, "decided").map(row => row.id))
      .toEqual(["validated", "dismissed"]);
    const empty: typeof rows[number][] = [];
    expect(countLoadedObservations(empty)).toEqual({
      all: 0, for_review: 0, my_drafts: 0, decided: 0
    });
  });

  it("renders accessible, keyboard-native pressed filters and explains the pagination limit", () => {
    const html = renderToStaticMarkup(
      <ObservationInboxFilters counts={countLoadedObservations(rows)}
        selected="for_review" canDraft hasOlderRecords
        onSelect={() => {}} />
    );
    expect(html).toContain('role="group"');
    expect(html).toContain('aria-label="Filtrar observaciones cargadas"');
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain("Para revisar");
    expect(html).toContain("Mis borradores");
    expect(html).toContain("Cargados: 6");
    expect(html).toContain("Hay más páginas sin cargar");
    expect(html).not.toContain("Total de observaciones");
    expect(html).toContain('type="button"');
  });

  it("hides action-focused filters from read-only users while retaining history and decisions", () => {
    const html = renderToStaticMarkup(
      <ObservationInboxFilters counts={countLoadedObservations(rows)}
        selected="all" canDraft={false} hasOlderRecords={false}
        onSelect={() => {}} />
    );
    expect(html).toContain("Todas");
    expect(html).toContain("Decisiones");
    expect(html).not.toContain("Para revisar");
    expect(html).not.toContain("Mis borradores");
  });
});
