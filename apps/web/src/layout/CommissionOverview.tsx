import type { ChecklistRow, DocumentRow, ObservationRow, Scope } from "../api";

export interface ReviewSummary {
  scopeKey: string;
  checklistTotal: number;
  checklistPending: number;
  internallyValidated: number;
  /** First keyset history page only; NEVER a commission-wide total. */
  reviewableRecent: number;
  recentRecordCount: number;
  hasOlderRecords: boolean;
}

export function summaryScopeKey(scope: Scope): string {
  return `${scope.commissionId}:${scope.batchId}`;
}

/**
 * Reuses the authorized checklist and initial history page that ReviewWorkspace
 * already fetched. In particular, "reviewable" relies on server-supplied
 * canReview permissions and does NOT represent the complete paginated history.
 */
export function makeReviewSummary(
  scope: Scope,
  checklist: ReadonlyArray<Pick<ChecklistRow, "status" | "statusSource">>,
  history: ReadonlyArray<Pick<ObservationRow, "status" | "canReview">>,
  hasOlderRecords: boolean
): ReviewSummary {
  return {
    scopeKey: summaryScopeKey(scope),
    checklistTotal: checklist.length,
    checklistPending: checklist.filter(item => item.status === "pending").length,
    internallyValidated: checklist.filter(item => item.statusSource === "validated_search").length,
    reviewableRecent: history.filter(item =>
      item.status === "in_review" && item.canReview === true
    ).length,
    recentRecordCount: history.length,
    hasOlderRecords
  };
}

export interface CommissionOverviewProps {
  scope: Scope;
  commissionName?: string;
  batchLabel?: string;
  /** Null when not yet loaded, not authorized, or stale. Never interpret as zero. */
  documents: ReadonlyArray<DocumentRow> | null;
  documentsFailed: boolean;
  review: ReviewSummary | null;
  canDraft: boolean;
}

export function CommissionOverview({
  scope, commissionName, batchLabel, documents, documentsFailed, review, canDraft
}: CommissionOverviewProps) {
  const current = review?.scopeKey === summaryScopeKey(scope) ? review : null;
  const readableDocuments = documentsFailed ? null : documents;
  const documentCount = readableDocuments?.length;
  const pendingProcessing = readableDocuments?.filter(
    item => item.extractionStatus === "pending"
  ).length;
  const hasUnavailable = documentsFailed || current === null;
  const action =
    canDraft && current && current.reviewableRecent > 0
      ? { href: "#observaciones", label: "Revisar solicitudes" }
      : !canDraft
        ? { href: "#checklist", label: "Consultar checklist" }
        : current && current.checklistPending > 0
          ? { href: "#registrar-busqueda", label: "Registrar búsqueda" }
          : { href: "#expedientes", label: "Explorar expedientes" };

  function metric(value: number | undefined | null) {
    return value === undefined || value === null ? "—" : String(value);
  }

  return (
    <section id="resumen" className="commission-overview"
      aria-labelledby="commission-overview-title">
      <header className="overview-heading">
        <div>
          <p className="eyebrow">VISTA DEL LOTE AUTORIZADO</p>
          <h2 id="commission-overview-title">Resumen de comisión</h2>
          <p className="overview-context">
            {commissionName ?? "Comisión seleccionada"}
            {" · "}
            {batchLabel ?? "Lote seleccionado"}
          </p>
        </div>
        <a className="overview-primary-action" href={action.href}>{action.label}</a>
      </header>

      <dl className="overview-metrics">
        <div className="overview-metric">
          <dt>Documentos del lote</dt>
          <dd>{documentsFailed ? "No disponible" : metric(documentCount)}
            <small>Solo documentos de este lote</small>
          </dd>
        </div>
        <div className="overview-metric">
          <dt>Pendientes de procesamiento</dt>
          <dd>{documentsFailed ? "No disponible" : metric(pendingProcessing)}
            <small>Sin extracción iniciada. Los PDF originales permanecen en cuarentena en todos los estados.</small>
          </dd>
        </div>
        <div className="overview-metric">
          <dt>Checklist pendiente</dt>
          <dd>{metric(current?.checklistPending)}
            <small>
              De {metric(current?.checklistTotal)} ítems de la comisión
              {" · "}
              {metric(current?.internallyValidated)} con Validación interna
            </small>
          </dd>
        </div>
        <div className="overview-metric">
          <dt>Para tu revisión</dt>
          <dd>{metric(current?.reviewableRecent)}
            <small>Solo en los últimos {metric(current?.recentRecordCount)} registros visibles (máximo 25)</small>
          </dd>
        </div>
      </dl>

      <p className="overview-disclaimer">
        No es un total de la comisión: las observaciones se consultan por páginas de hasta 25.
        {current?.hasOlderRecords ? " Hay más registros anteriores por consultar." : ""}
        {" "}La validación interna no equivale a un acta oficial.
      </p>
      {hasUnavailable && (
        <p className="overview-unavailable" role="status">
          {documentsFailed ? "Datos no disponibles para documentos. " : ""}
          {current === null ? "Checklist e historial aún no disponibles. " : ""}
          Los guiones indican información no confirmada, no cero.
        </p>
      )}
    </section>
  );
}
