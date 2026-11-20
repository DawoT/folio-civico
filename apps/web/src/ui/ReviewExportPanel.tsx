import { useEffect, useState } from "react";
import { StatusBadge } from "./StatusBadge";

export type ReportExportStatus =
  | { phase: "idle" }
  | { phase: "verifying" }
  | { phase: "verified"; sha256: string; count: number; filename: string }
  | { phase: "error"; message: string };

export interface ReviewExportPanelProps {
  status: ReportExportStatus;
  onExport: () => void;
}

/**
 * This receipt confirms integrity of the embedded report payload against the
 * server-provided digest. It is neither a signature nor confirmation that the
 * browser saved the JSON envelope.
 */
export function ReviewExportPanel({ status, onExport }: ReviewExportPanelProps) {
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "error">("idle");
  const digest = status.phase === "verified" ? status.sha256 : null;

  useEffect(() => { setCopyStatus("idle"); }, [digest]);

  async function copyDigest() {
    if (status.phase !== "verified") return;
    try {
      await navigator.clipboard.writeText(status.sha256);
      setCopyStatus("copied");
    } catch {
      setCopyStatus("error");
    }
  }

  return (
    <section className="review-export" id="informes"
      aria-labelledby="review-export-title"
      aria-describedby="review-export-description"
      aria-busy={status.phase === "verifying"}>
      <div className="review-export-heading">
        <h3 id="review-export-title">Informe de revisión interna</h3>
        <StatusBadge status="neutral">JSON · uso interno</StatusBadge>
      </div>
      <p className="review-note" id="review-export-description">
        Incluye decisiones internas validadas y descartadas, sus evidencias, autores y revisores.
        No incluye borradores ni archivos PDF. No constituye un acta oficial.
      </p>
      <button type="button" className="button secondary"
        onClick={onExport} disabled={status.phase === "verifying"}>
        {status.phase === "verifying" ? "Preparando informe…" :
          status.phase === "error" ? "Reintentar exportación" : "Exportar revisión interna (JSON)"}
      </button>
      {status.phase === "verifying" && (
        <p role="status" className="review-export-progress">
          Verificando contenido y huella SHA-256 antes de iniciar la descarga…
        </p>
      )}
      {status.phase === "error" && (
        <div className="review-export-error" role="alert">
          <strong>No se inició ninguna descarga verificada.</strong>
          <p>{status.message}</p>
          <p>Comprueba la conexión o solicita revisar la integridad del informe antes de reintentar.</p>
        </div>
      )}
      {status.phase === "verified" && (
        <div className="review-export-receipt">
          <p role="status" className="review-export-verified">
            Integridad verificada. SHA-256: <code className="report-digest">{status.sha256}</code>.
          </p>
          <dl className="review-export-metadata">
            <div><dt>Contenido</dt><dd>{status.count} {status.count === 1 ? "decisión interna" : "decisiones internas"}</dd></div>
            <div><dt>Archivo solicitado</dt><dd><code>{status.filename}</code></dd></div>
            <div><dt>Estado</dt><dd>La descarga se inició. Comprueba que el navegador guardó el archivo.</dd></div>
          </dl>
          <p className="review-export-caveat">
            Esta huella identifica el contenido del informe, no del archivo contenedor JSON;
            no es una firma digital ni acredita aprobación institucional.
            Conserva la huella por separado del archivo.
          </p>
          <button type="button" className="button secondary review-export-copy"
            onClick={() => void copyDigest()}>Copiar SHA-256</button>
          {copyStatus === "copied" && (
            <p role="status" className="review-export-copy-feedback">Huella copiada al portapapeles.</p>
          )}
          {copyStatus === "error" && (
            <p role="alert" className="review-export-copy-feedback">
              No se pudo copiar automáticamente. Selecciona la huella mostrada para copiarla.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
