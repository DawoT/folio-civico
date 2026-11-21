import type { ChecklistRow, DocumentRow, ObservationRow, Scope } from "../api";

export interface ReviewSummary {
  scopeKey: string;
  checklistTotal: number;
  checklistPending: number;
  internallyValidated: number;
  /** First keyset history page only; NEVER a commission-wide total. */
  reviewableRecent: number;
  /** Verified via authorized endpoint, null when missing/denied/unavailable. */
  reviewableTotal: number | null;
  reviewableTotalLoading: boolean;
  /** Fail-closed reason for unavailable aggregate, distinct from an in-flight query. */
  reviewableTotalError: "access-denied" | "unavailable" | null;
  recentRecordCount: number;
  hasOlderRecords: boolean;
}

export function summaryScopeKey(scope: Scope): string {
  return `${scope.commissionId}:${scope.batchId}`;
}

/**
 * Reuses the authorized checklist and first history page. The optional
 * commission-wide aggregate is obtained separately from the authorized API.
 * reviewableRecent is always page-bound; reviewableTotal is never inferred.
 */
export function makeReviewSummary(
  scope: Scope,
  checklist: ReadonlyArray<Pick<ChecklistRow, "status" | "statusSource">>,
  history: ReadonlyArray<Pick<ObservationRow, "status" | "canReview">>,
  hasOlderRecords: boolean,
  reviewableTotal: number | null = null,
  reviewableTotalLoading = false,
  reviewableTotalError: ReviewSummary["reviewableTotalError"] = null
): ReviewSummary {
  return {
    scopeKey: summaryScopeKey(scope),
    checklistTotal: checklist.length,
    checklistPending: checklist.filter(item => item.status === "pending").length,
    internallyValidated: checklist.filter(item => item.statusSource === "validated_search").length,
    reviewableRecent: history.filter(item =>
      item.status === "in_review" && item.canReview === true
    ).length,
    reviewableTotal,
    reviewableTotalLoading,
    reviewableTotalError,
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
  const authorizedTotal = current?.reviewableTotal ?? null;
  const countLoading = current?.reviewableTotalLoading === true;
  const countDenied = current?.reviewableTotalError === "access-denied";
  const hasUnavailable = documentsFailed || current === null
    || (authorizedTotal === null && !countLoading);
  const action =
    canDraft && current && (authorizedTotal === null
      ? current.reviewableRecent > 0 : authorizedTotal > 0)
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
          <dd>{authorizedTotal === null ? "—" : metric(authorizedTotal)}
            <small>{authorizedTotal === null
              ? countLoading
                ? "Consultando total autorizado de la comisión…"
                : countDenied
                  ? "Acceso no concedido para consultar el total de la comisión."
                  : "Total de la comisión no disponible; no equivale a cero."
              : "Total autorizado de la comisión."}</small>
            <small>Solo en los últimos {metric(current?.recentRecordCount)} registros visibles (máximo 25): {metric(current?.reviewableRecent)} elegibles.</small>
          </dd>
        </div>
      </dl>

      <p className="overview-disclaimer">
        {authorizedTotal === null
          ? countLoading
            ? "No es un total de la comisión: la consulta del agregado está en curso y el historial se carga en páginas de hasta 25."
            : countDenied
              ? "No es un total de la comisión: la consulta del agregado no está autorizada."
              : "No es un total de la comisión: la página histórica se consulta por partes de hasta 25 y el total autorizado aún no está disponible."
          : "El total de revisiones corresponde a la comisión autorizada, no al lote abierto. La bandeja consulta páginas de hasta 25."}
        {current?.hasOlderRecords ? " Hay más registros anteriores por consultar." : ""}
        {" "}La validación interna no equivale a un acta oficial.
      </p>
      {hasUnavailable && (
        <p className="overview-unavailable" role="status">
          {documentsFailed ? "Datos no disponibles para documentos. " : ""}
          {current === null ? "Checklist e historial aún no disponibles. " : ""}
          {authorizedTotal === null && !countLoading
            ? countDenied
              ? "Acceso al contador no concedido. "
              : "Total autorizado de revisión no disponible. "
            : ""}
          Los guiones indican información no confirmada, no cero.
        </p>
      )}
    </section>
  );
}
