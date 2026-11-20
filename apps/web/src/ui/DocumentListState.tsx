import { LoadingState } from "./FeedbackStates";

export type DocumentListPhase = "unselected" | "loading" | "failed" | "empty";

export interface DocumentListStateProps {
  phase: DocumentListPhase;
  canUpload: boolean;
  onRetry: () => void;
}

/**
 * Only an authorized, successful document-list response may represent a genuinely
 * empty lot. Failed requests must never be presented as documented absence.
 */
export function DocumentListState({ phase, canUpload, onRetry }: DocumentListStateProps) {
  if (phase === "loading") {
    return <LoadingState className="document-collection-loading">Consultando documentos…</LoadingState>;
  }

  return (
    <div className="document-collection-state" role="group" aria-label="Estado del listado de documentos">
      {phase === "unselected" && (
        <>
          <h3>Primero selecciona un lote</h3>
          <p>Selecciona una comisión y un lote autorizados para consultar sus documentos.</p>
          <a className="document-state-action" href="#scope-commission">Elegir comisión y lote</a>
        </>
      )}
      {phase === "failed" && (
        <>
          <h3>Listado no disponible</h3>
          <p>No se pudo consultar el listado de documentos. Esto no significa que el lote esté vacío.</p>
          <button type="button" className="button secondary document-state-action" onClick={onRetry}>
            Reintentar consulta
          </button>
        </>
      )}
      {phase === "empty" && (
        <>
          <h3>Lote sin documentos registrados</h3>
          <p>No hay documentos registrados en este lote según la consulta completada.</p>
          {canUpload
            ? <a className="document-state-action" href="#upload-pdf">Seleccionar PDF para registrar</a>
            : <p>No tienes permiso para incorporar archivos en esta comisión. Puedes consultar los registros disponibles.</p>}
        </>
      )}
    </div>
  );
}
