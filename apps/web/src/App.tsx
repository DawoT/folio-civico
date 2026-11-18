import { useEffect, useRef, useState, type FormEvent } from "react";
import { ApiError, loadDocuments, makeDocumentsPath, uploadPdf, type DocumentRow, type Scope } from "./api";
import "./styles.css";

const statusText: Record<DocumentRow["extractionStatus"], string> = {
  pending: "En cuarentena", processing: "Procesando", ready: "Texto disponible",
  needs_review: "Revisión manual", failed: "Extracción fallida"
};

function initialScope(): Scope | null {
  if (typeof window === "undefined") return null;
  const params = new URLSearchParams(window.location.search);
  const commissionId = params.get("commission") ?? "";
  const batchId = params.get("batch") ?? "";
  try {
    makeDocumentsPath(commissionId, batchId);
    return { commissionId, batchId };
  } catch {
    return null;
  }
}

export function App() {
  const initial = initialScope();
  const [commissionId, setCommissionId] = useState(initial?.commissionId ?? "");
  const [batchId, setBatchId] = useState(initial?.batchId ?? "");
  const [scope, setScope] = useState<Scope | null>(initial);
  const [documents, setDocuments] = useState<DocumentRow[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  // Preserve the same key on a retry after network failure, while the File remains selected.
  const pendingUpload = useRef<{ file: File; key: string } | null>(null);

  useEffect(() => {
    if (!scope) return;
    let alive = true;
    setLoading(true);
    setError("");
    loadDocuments(scope).then((rows) => {
      if (alive) {
        setDocuments(rows);
        setSelectedId((id) => id && rows.some((row) => row.id === id) ? id : (rows[0]?.id ?? null));
      }
    }).catch((problem: unknown) => {
      if (alive) {
        setDocuments([]);
        setSelectedId(null);
        setError(problem instanceof Error ? problem.message : "No se pudo cargar el lote.");
      }
    }).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scope, refresh]);

  const selected = documents.find((document) => document.id === selectedId) ?? null;

  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      makeDocumentsPath(commissionId.trim(), batchId.trim());
      const nextScope = { commissionId: commissionId.trim(), batchId: batchId.trim() };
      setScope(nextScope);
      setNotice("");
      setError("");
      if (typeof window !== "undefined") {
        const url = new URL(window.location.href);
        url.searchParams.set("commission", nextScope.commissionId);
        url.searchParams.set("batch", nextScope.batchId);
        window.history.replaceState(null, "", url);
      }
      setRefresh((value) => value + 1);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "Identificadores no válidos.");
    }
  }

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const file = fileInput.current?.files?.[0];
    if (!scope || !file) return;
    setUploading(true);
    setNotice("");
    setError("");
    try {
      const key = pendingUpload.current?.file === file
        ? pendingUpload.current.key : crypto.randomUUID();
      pendingUpload.current = { file, key };
      const result = await uploadPdf(scope, file, fetch, () => key);
      pendingUpload.current = null;
      setNotice(result.repeated
        ? "Este documento ya estaba registrado. Se conservó la versión original."
        : "PDF recibido en cuarentena. Todavía no está verificado ni procesado.");
      if (fileInput.current) fileInput.current.value = "";
      setSelectedId(result.documentId);
      setRefresh((value) => value + 1);
    } catch (problem) {
      setError(problem instanceof ApiError ? problem.message : "No se pudo cargar el PDF.");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand" aria-label="Folio Cívico">
          <span className="brand-mark" aria-hidden="true">F</span>
          <div><strong>Folio Cívico</strong><span>Evidencia para una transferencia ordenada.</span></div>
        </div>
        <span className="environment-tag">MESA DOCUMENTAL · PILOTO</span>
      </header>

      <div className="disclaimer" role="note">
        <strong>Insumo de trabajo.</strong> No constituye el acta oficial de transferencia.
      </div>

      <main className="main-content">
        <section className="intro" aria-labelledby="page-title">
          <div>
            <p className="eyebrow">TRANSFERENCIA DE GESTIÓN · OBRAS Y CONTRATACIONES</p>
            <h1 id="page-title">Mesa de revisión</h1>
            <p>Recibe expedientes, conserva sus versiones y prepara evidencia para revisión humana.</p>
          </div>
          <span className="status-label">Sin validación automática</span>
        </section>

        <form className="scope-form" onSubmit={connect} aria-label="Conectar comisión y lote">
          <label>
            <span>Comisión</span>
            <input aria-label="Identificador de comisión" value={commissionId}
              onChange={(event) => setCommissionId(event.target.value)} placeholder="comision_001"
              autoComplete="off" required/>
          </label>
          <label>
            <span>Lote de expedientes</span>
            <input aria-label="Identificador de lote" value={batchId}
              onChange={(event) => setBatchId(event.target.value)} placeholder="lote_001"
              autoComplete="off" required/>
          </label>
          <button className="button primary" type="submit">Abrir lote</button>
        </form>

        {(error || notice) && (
          <div className={error ? "message error" : "message success"} role={error ? "alert" : "status"} aria-live="polite">
            {error || notice}
          </div>
        )}

        <div className="workspace">
          <section className="documents-panel" aria-labelledby="documents-title">
            <div className="panel-header">
              <div>
                <p className="eyebrow">01 · DOCUMENTACIÓN</p>
                <h2 id="documents-title">Documentos del lote</h2>
              </div>
              <span className="count">{documents.length}</span>
            </div>

            <form className="upload-form" onSubmit={upload}>
              <label htmlFor="upload-pdf">Incorporar un expediente PDF</label>
              <input id="upload-pdf" ref={fileInput} type="file" accept=".pdf,application/pdf"
                disabled={!scope || uploading} required/>
              <p>Máximo 8 MiB. Se conservará en cuarentena, sin lectura automática.</p>
              <button className="button primary upload-button" type="submit" disabled={!scope || uploading}>
                {uploading ? "Registrando…" : "Registrar PDF"}
              </button>
            </form>

            <div className="document-list" aria-live="polite">
              {!scope && <p className="empty">Indica una comisión y un lote para consultar los documentos autorizados.</p>}
              {scope && loading && <p className="empty">Consultando documentos…</p>}
              {scope && !loading && documents.length === 0 && <p className="empty">No hay documentos disponibles para este lote.</p>}
              {!loading && documents.map((document) => (
                <button className={document.id === selectedId ? "document-item selected" : "document-item"}
                  key={document.id} type="button" onClick={() => setSelectedId(document.id)}
                  aria-pressed={document.id === selectedId}>
                  <span className="pdf-icon" aria-hidden="true">PDF</span>
                  <span className="document-details">
                    <strong>{document.filename}</strong>
                    <small>{statusText[document.extractionStatus]}</small>
                  </span>
                  <span aria-hidden="true" className="chevron">›</span>
                </button>
              ))}
            </div>
          </section>

          <section className="evidence-panel" aria-labelledby="evidence-title">
            <div className="panel-header">
              <div>
                <p className="eyebrow">02 · EVIDENCIA</p>
                <h2 id="evidence-title">Detalle verificable</h2>
              </div>
              <span className="read-only">Solo consulta</span>
            </div>
            {selected ? (
              <div className="evidence-detail">
                <p className="doc-label">DOCUMENTO SELECCIONADO</p>
                <h3>{selected.filename}</h3>
                <dl>
                  <div><dt>Estado</dt><dd>{statusText[selected.extractionStatus]}</dd></div>
                  <div><dt>Versión</dt><dd className="mono">{selected.versionId}</dd></div>
                  <div><dt>SHA-256</dt><dd className="mono hash">{selected.sha256}</dd></div>
                  <div><dt>Páginas</dt><dd>{selected.pageCount ?? "Pendiente de extracción"}</dd></div>
                </dl>
                <div className="review-placeholder">
                  <h4>Revisión documental pendiente</h4>
                  <p>El archivo se conserva de forma privada. El visor y las observaciones con citas por página se habilitarán después de incorporar las verificaciones de seguridad y el procesamiento documental.</p>
                  <button className="button secondary" disabled title="Función todavía no disponible">Crear observación</button>
                </div>
              </div>
            ) : (
              <div className="empty-evidence">
                <div className="placeholder-art" aria-hidden="true"><span/><span/><span/></div>
                <h3>Evidencia, no suposiciones</h3>
                <p>Selecciona un documento para ver su versión, huella de integridad y estado de procesamiento.</p>
              </div>
            )}
          </section>
        </div>
        <footer className="page-footer">Folio Cívico · Herramienta de apoyo técnico-administrativo · Las decisiones corresponden a la comisión.</footer>
      </main>
    </div>
  );
}
