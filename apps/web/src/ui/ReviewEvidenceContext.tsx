import type { ObservationEvidence, ObservationRow } from "../api";

function declared(value: unknown): string {
  return typeof value === "string" && value.trim() ? value : "No declarado";
}

function EvidenceReference({ proof }: { proof: ObservationEvidence }) {
  if (proof.type === "SEARCH_SCOPE") {
    return (
      <li>
        <strong>Búsqueda documentada</strong>
        <p>Lote {declared(proof.batchId)} · Ítem {declared(proof.checklistItemId)}</p>
        <p>Fecha registrada: {declared(proof.searchedAt)}</p>
      </li>
    );
  }
  if (proof.type === "DOCUMENT_PAGE") {
    const version = typeof proof.documentVersionId === "string"
      && /^[A-Za-z0-9_-]{1,64}$/.test(proof.documentVersionId)
      ? proof.documentVersionId : null;
    const page = typeof proof.page === "number"
      && Number.isSafeInteger(proof.page) && proof.page >= 1 && proof.page <= 100
      ? proof.page : null;
    const hash = typeof proof.sha256 === "string" && /^[a-f0-9]{64}$/.test(proof.sha256)
      ? proof.sha256 : null;
    return (
      <li>
        <strong>Referencia a página documental</strong>
        {version !== null && page !== null ? (
          <p>Versión {version} · Página {page}</p>
        ) : <p>Referencia incompleta: no se puede identificar una página segura.</p>}
        {hash !== null && <p>SHA-256 declarado: <code>{hash}</code></p>}
      </li>
    );
  }
  if (proof.type === "OFFICIAL_SOURCE") {
    return (
      <li>
        <strong>Fuente registrada</strong>
        <p>{declared(proof.source)}</p>
        <p>Su procedencia requiere comprobación independiente.</p>
      </li>
    );
  }
  return <li><strong>Referencia no identificada</strong><p>Requiere comprobación independiente.</p></li>;
}

/**
 * The submitted reference is not inspection evidence and does not automatically
 * validate a finding. Render as text only; NEVER resolve an external URL or
 * expose quarantined PDF bytes.
 */
export function ReviewEvidenceContext({ record }: { record: ObservationRow }) {
  return (
    <section className="review-evidence-context"
      aria-labelledby={`review-evidence-${record.id}`}>
      <h4 id={`review-evidence-${record.id}`}>Evidencia antes de decidir</h4>
      <p className="review-evidence-disclaimer">
        La documentación registrada no acredita por sí sola una irregularidad.
        Corresponde realizar una revisión independiente antes de validar o descartar.
        No se accede al PDF original en cuarentena.
      </p>
      <dl className="review-evidence-metadata">
        <div><dt>Autor</dt><dd>{declared(record.authorSubject)}</dd></div>
        <div><dt>Registro</dt><dd>{declared(record.createdAt)}</dd></div>
        <div><dt>Título</dt><dd>{record.title}</dd></div>
        <div><dt>Alcance declarado</dt><dd>{record.description}</dd></div>
      </dl>
      <h5>Referencias registradas ({record.evidence.length})</h5>
      {record.evidence.length === 0 ? (
        <p className="review-evidence-empty">
          No hay referencias de evidencia registradas. Confirma el alcance de la búsqueda
          y efectúa la revisión independiente antes de decidir.
        </p>
      ) : (
        <ul className="review-evidence-list">
          {record.evidence.map((proof, index) => (
            <EvidenceReference key={index} proof={proof}/>
          ))}
        </ul>
      )}
    </section>
  );
}

/** Defensive UI gate. The API remains the final authority for decisions. */
export function canPrepareReviewDecision(
  record: ObservationRow, activeReviewId: string | null,
  note: string, confirmed: boolean, busy: boolean
): boolean {
  return !busy
    && record.status === "in_review"
    && record.canReview === true
    && activeReviewId === record.id
    && confirmed
    && note.trim().length >= 15
    && note.trim().length <= 1000;
}
