import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { ObservationRow } from "../api";
import { ReviewEvidenceContext, canPrepareReviewDecision } from "./ReviewEvidenceContext";

const sample = (overrides: Partial<ObservationRow> = {}): ObservationRow => ({
  id: "obs_1",
  commissionId: "c_a",
  authorSubject: "author",
  title: "Búsqueda documentada",
  description: "Búsqueda delimitada al expediente del lote.",
  status: "in_review",
  validatedBy: null,
  createdAt: "2026-11-19T18:00:00.000Z",
  canReview: true,
  evidence: [
    { type: "SEARCH_SCOPE", commissionId: "c_a", batchId: "b_a",
      checklistItemId: "item_a", searchedAt: "2026-11-19T18:00:00.000Z" },
    { type: "DOCUMENT_PAGE", commissionId: "c_a",
      documentVersionId: "version_1", page: 3, sha256: "a".repeat(64) },
    { type: "OFFICIAL_SOURCE", commissionId: "c_a", source: "Registro declarado" }
  ],
  ...overrides
});

describe("UX-3.2 documented evidence context", () => {
  it("presents author, scoped search and page reference as evidence registered, not authenticated", () => {
    const html = renderToStaticMarkup(<ReviewEvidenceContext record={sample()}/>);
    expect(html).toContain('aria-labelledby="review-evidence-obs_1"');
    expect(html).toContain("Evidencia antes de decidir");
    expect(html).toContain("author");
    expect(html).toContain("Búsqueda delimitada al expediente del lote.");
    expect(html).toContain("Lote b_a");
    expect(html).toContain("Ítem item_a");
    expect(html).toContain("Versión version_1");
    expect(html).toContain("Página 3");
    expect(html).toContain("SHA-256 declarado");
    expect(html).toContain("Fuente registrada");
    expect(html).toContain("Registro declarado");
    expect(html).toContain("no acredita por sí sola");
    expect(html).not.toMatch(/href=|<iframe|<embed|<object/i);
  });

  it("does not fabricate references or imply an inspected original with no evidence", () => {
    const html = renderToStaticMarkup(<ReviewEvidenceContext record={sample({evidence: []})}/>);
    expect(html).toContain("No hay referencias de evidencia registradas");
    expect(html).toContain("revisión independiente");
    expect(html).not.toContain("Página verificada");
    expect(html).not.toContain("Original inspeccionado");
  });

  it("handles incomplete and malformed evidence without an unsafe URL or fabricated hash", () => {
    const html = renderToStaticMarkup(<ReviewEvidenceContext record={sample({ evidence: [
      { type: "DOCUMENT_PAGE", commissionId: "c_a", page: -5, sha256: "bad" },
      { type: "OFFICIAL_SOURCE", commissionId: "c_a", source: "https://example.org/?x=<script>" },
      { type: "SEARCH_SCOPE", commissionId: "c_a" }
    ]})}/>);
    expect(html).toContain("Referencia incompleta");
    expect(html).toContain("No declarado");
    expect(html).not.toContain("SHA-256 declarado");
    expect(html).not.toMatch(/href=|<iframe|<embed|<object/i);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("rejects action preparation without the exact active record, real permission and confirmation", () => {
    const record = sample();
    expect(canPrepareReviewDecision(record, "obs_1", "Comprobación independiente completa", true, false)).toBe(true);
    expect(canPrepareReviewDecision(record, "another", "Comprobación independiente completa", true, false)).toBe(false);
    expect(canPrepareReviewDecision(sample({canReview:false}), "obs_1", "Comprobación independiente completa", true, false)).toBe(false);
    expect(canPrepareReviewDecision(sample({status:"validated"}), "obs_1", "Comprobación independiente completa", true, false)).toBe(false);
    expect(canPrepareReviewDecision(record, "obs_1", "corta", true, false)).toBe(false);
    expect(canPrepareReviewDecision(record, "obs_1", "Comprobación independiente completa", false, false)).toBe(false);
    expect(canPrepareReviewDecision(record, "obs_1", "Comprobación independiente completa", true, true)).toBe(false);
  });
});
