import { useEffect, useRef, useState, type FormEvent } from "react";
import { ApiError, loadCommissions, loadCommissionBatches, loadDocuments, loadSession, makeDocumentsPath, uploadPdf, createCommissionBatch, type Commission, type CommissionBatch, type DocumentRow, type Scope, type SessionInfo } from "./api";
import "./styles.css";
import { ReviewWorkspace } from "./ReviewWorkspace";
import { InspectedTextViewer } from "./InspectedTextViewer";
import { CommissionAdminPanel, BootstrapCommissionPanel } from "./CommissionAdmin";
import { Button } from "./ui/Button";
import { InlineAlert } from "./ui/InlineAlert";
import { StatusBadge } from "./ui/StatusBadge";
import { SelectField } from "./ui/Fields";
import { Card } from "./ui/Card";
import { DocumentListState } from "./ui/DocumentListState";
import { DocumentProcessingGuidance } from "./ui/DocumentProcessingGuidance";
import { TaskNavigation } from "./layout/TaskNavigation";
import { CommissionOverview, summaryScopeKey, type ReviewSummary } from "./layout/CommissionOverview";

const statusText: Record<DocumentRow["extractionStatus"], string> = {
  pending: "Pendiente de procesamiento", processing: "Procesamiento técnico en curso",
  ready: "Texto inspeccionado disponible", needs_review: "Revisión técnica requerida",
  failed: "Procesamiento fallido"
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
  const [administrationOpen, setAdministrationOpen] = useState(false);
  const [batchId, setBatchId] = useState(initial?.batchId ?? "");
  const [scope, setScope] = useState<Scope | null>(initial);
  const [commissions, setCommissions] = useState<Commission[]>([]);
  const [batches, setBatches] = useState<CommissionBatch[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const [session,setSession]=useState<SessionInfo|null>(null);
  const [sessionError,setSessionError]=useState("");
  const [batchesLoading, setBatchesLoading] = useState(false);
  const [catalogError, setCatalogError] = useState("");
  const [documents, setDocuments] = useState<DocumentRow[]>([]);
  const [loadedDocumentScopeKey, setLoadedDocumentScopeKey] = useState<string | null>(null);
  const [documentsFailed, setDocumentsFailed] = useState(false);
  const [reviewSummary, setReviewSummary] = useState<ReviewSummary | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [reviewRefresh,setReviewRefresh]=useState(0);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [newBatchLabel,setNewBatchLabel]=useState("");
  const [batchCreating,setBatchCreating]=useState(false);
  const pendingBatch=useRef<{fingerprint:string;key:string}|null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  // Preserve the same key on a retry after network failure, while the File remains selected.
  const pendingUpload = useRef<{ file: File; key: string } | null>(null);

  useEffect(()=>{
    let active=true;
    loadSession().then(value=>{
      if(active)setSession(value);
    }).catch(problem=>{
      if(active)setSessionError(problem instanceof Error?problem.message:"No se pudo verificar la sesión.");
    });
    return()=>{active=false;};
  },[]);

  useEffect(() => {
    let active = true;
    loadCommissions().then((items) => {
      if (!active) return;
      setCommissions(items);
      if (!items.some((item) => item.id === initial?.commissionId)) {
        setCommissionId("");
        setBatchId("");
        setScope(null);
      }
    }).catch((problem: unknown) => {
      if (active) setCatalogError(problem instanceof Error ? problem.message : "No se pudieron cargar las comisiones.");
    }).finally(() => { if (active) setCatalogLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!commissionId) {
      setBatches([]);
      return;
    }
    let active = true;
    setBatchesLoading(true);
    loadCommissionBatches(commissionId).then((items) => {
      if (!active) return;
      setBatches(items);
      setBatchId((current) => items.some((item) => item.id === current) ? current : "");
    }).catch((problem: unknown) => {
      if (!active) return;
      setBatches([]);
      setBatchId("");
      setCatalogError(problem instanceof Error ? problem.message : "No se pudieron cargar los lotes.");
    }).finally(() => { if (active) setBatchesLoading(false); });
    return () => { active = false; };
  }, [commissionId]);

  useEffect(() => {
    if (!scope) return;
    let alive = true;
    setLoading(true);
    setError("");
    setDocumentsFailed(false);
    setLoadedDocumentScopeKey(null);
    loadDocuments(scope).then((rows) => {
      if (alive) {
        setDocuments(rows);
        setLoadedDocumentScopeKey(summaryScopeKey(scope));
        setSelectedId((id) => id && rows.some((row) => row.id === id) ? id : (rows[0]?.id ?? null));
      }
    }).catch((problem: unknown) => {
      if (alive) {
        setDocuments([]);
        setLoadedDocumentScopeKey(null);
        setDocumentsFailed(true);
        setSelectedId(null);
        setError(problem instanceof Error ? problem.message : "No se pudo cargar el lote.");
      }
    }).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scope, refresh]);

  // Never retain the previous lot's evidence when a scope is changing, loading,
  // or unavailable. The loaded scope key is the UI's freshness guard.
  const documentsReady = scope !== null && !loading && !documentsFailed
    && loadedDocumentScopeKey === summaryScopeKey(scope);
  const selected = documentsReady
    ? documents.find((document) => document.id === selectedId) ?? null
    : null;
  const documentListPhase = !scope ? "unselected"
    : loading || (loadedDocumentScopeKey !== summaryScopeKey(scope) && !documentsFailed)
      ? "loading"
      : documentsFailed ? "failed"
        : documentsReady && documents.length === 0 ? "empty" : null;
  const selectedCommission = commissions.find((item) => item.id === commissionId);
  // The opened scope may differ from an unsubmitted dropdown selection.
  const activeCommission = scope
    ? commissions.find((item) => item.id === scope.commissionId)
    : undefined;
  const activeBatch = scope
    ? batches.find((item) => item.id === scope.batchId)
    : undefined;
  const canUpload = selectedCommission?.status === "active" && selectedCommission.role !== "observer";
  const canManage = selectedCommission?.status === "active" && selectedCommission.role === "president";

  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      makeDocumentsPath(commissionId.trim(), batchId.trim());
      if (!commissions.some((item) => item.id === commissionId.trim())
        || !batches.some((item) => item.id === batchId.trim())) {
        throw new ApiError(404, "Selecciona una comisión y un lote autorizados.");
      }
      const nextScope = { commissionId: commissionId.trim(), batchId: batchId.trim() };
      setScope(nextScope);
      setReviewSummary(null);
      setLoadedDocumentScopeKey(null);
      setDocumentsFailed(false);
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

  async function createBatch(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if(!canManage||!commissionId||batchCreating||batchesLoading) return;
    setBatchCreating(true);setError("");setNotice("");
    try {
      const fingerprint=JSON.stringify([commissionId,newBatchLabel.trim()]);
      const key=pendingBatch.current?.fingerprint===fingerprint
        ? pendingBatch.current.key : crypto.randomUUID();
      pendingBatch.current={fingerprint,key};
      const created=await createCommissionBatch({commissionId,label:newBatchLabel},fetch,()=>key);
      pendingBatch.current=null;
      setBatches(rows=>[{id:created.id,label:created.label},...rows.filter(row=>row.id!==created.id)]);
      setBatchId(created.id);
      setNewBatchLabel("");
      setNotice(created.replayed?"Lote ya registrado; se recuperó el mismo ID.":"Lote creado y seleccionado. Pulsa «Abrir lote» para continuar.");
    } catch(problem) {
      setError(problem instanceof Error?problem.message:"No se pudo crear el lote.");
    } finally {setBatchCreating(false);}
  }

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const file = fileInput.current?.files?.[0];
    if (!scope || !file || !canUpload) return;
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
      <a className="skip-link" href="#main-content">Saltar al contenido principal</a>
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

      <main className="main-content" id="main-content" tabIndex={-1}>
        <section className="intro" aria-labelledby="page-title">
          <div>
            <p className="eyebrow">TRANSFERENCIA DE GESTIÓN · OBRAS Y CONTRATACIONES</p>
            <h1 id="page-title">Mesa de revisión</h1>
            <p>Recibe expedientes, conserva sus versiones y prepara evidencia para revisión humana.</p>
          </div>
          <StatusBadge status="warning" className="status-label">Sin validación automática</StatusBadge>
        </section>

        <form className="scope-form" onSubmit={connect} aria-label="Conectar comisión y lote">
          <SelectField id="scope-commission" label="Comisión"
            aria-label="Identificador de comisión" value={commissionId}
            onChange={(event) => {
              setCommissionId(event.target.value);
              setAdministrationOpen(false);
              setReviewSummary(null);
              setLoadedDocumentScopeKey(null);
              setDocumentsFailed(false);
              setBatchId("");
              setBatches([]);
              setScope(null);
              setDocuments([]);
              setSelectedId(null);
              setCatalogError("");
              setNewBatchLabel("");
              pendingBatch.current=null;
            }} disabled={catalogLoading} required>
            <option value="">{catalogLoading ? "Consultando comisiones…" : "Selecciona una comisión"}</option>
            {commissions.map((item) => <option key={item.id} value={item.id}>{item.name}{item.status === "closed" ? " · Cerrada" : ""}</option>)}
          </SelectField>
          <SelectField id="scope-batch" label="Lote de expedientes"
            aria-label="Identificador de lote" value={batchId}
            onChange={(event) => setBatchId(event.target.value)} disabled={!commissionId || batchesLoading} required>
            <option value="">{batchesLoading ? "Consultando lotes…" : "Selecciona un lote"}</option>
            {batches.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
          </SelectField>
          <Button variant="primary" type="submit" disabled={!commissionId || !batchId || catalogLoading || batchesLoading}>Abrir lote</Button>
        </form>

        <TaskNavigation hasScope={Boolean(scope)} canDraft={Boolean(canUpload)}
          canAdmin={Boolean(canManage || session?.canBootstrap)}
          commissionName={activeCommission?.name ?? selectedCommission?.name}
          batchLabel={activeBatch?.label}
          onOpenAdministration={()=>setAdministrationOpen(true)}/>
        {scope && (
          <CommissionOverview scope={scope}
            commissionName={activeCommission?.name} batchLabel={activeBatch?.label}
            documents={!loading && loadedDocumentScopeKey === summaryScopeKey(scope) ? documents : null}
            documentsFailed={documentsFailed}
            review={reviewSummary}
            canDraft={Boolean(canUpload)}/>
        )}

        {(canManage || session?.canBootstrap) && (
          <details id="administracion" className="administration-drawer"
            open={administrationOpen} onToggle={event=>setAdministrationOpen(event.currentTarget.open)}>
            <summary>Administración de la comisión</summary>
            <p className="review-note">Área de gestión de accesos, lotes y configuración. El trabajo documental continúa debajo.</p>
            {session?.canBootstrap && (
              <BootstrapCommissionPanel onCreated={()=> {
                void loadCommissions().then(setCommissions).catch(problem=>
                  setCatalogError(problem instanceof Error?problem.message:"No se actualizaron las comisiones."));
              }}/>
            )}
            {canManage && (
              <form className="manage-form" onSubmit={createBatch} aria-label="Crear lote de expedientes">
                <label htmlFor="new-batch-label">Nuevo lote de expedientes</label>
                <input id="new-batch-label" value={newBatchLabel} maxLength={120}
                  onChange={event=>setNewBatchLabel(event.target.value)}
                  placeholder="Obras y contrataciones · 2026" required
                  disabled={batchCreating||batchesLoading}/>
                <button type="submit" className="button secondary"
                  disabled={batchCreating||batchesLoading||newBatchLabel.trim().length<3}>
                  {batchCreating?"Creando lote…":"Crear lote"}
                </button>
              </form>
            )}
            {canManage && session && commissionId && (
              <CommissionAdminPanel key={commissionId} commissionId={commissionId}
                currentSubject={session.subject}/>
            )}
          </details>
        )}
        {sessionError && <p role="alert" className="message error">
          La administración no está disponible: {sessionError}
        </p>}
        {catalogError && <InlineAlert tone="error">{catalogError}</InlineAlert>}
        {!catalogLoading && !catalogError && !session?.canBootstrap && commissions.length === 0 && <div className="message" role="status">No tienes comisiones asignadas. Solicita acceso al administrador de la entidad.</div>}
        {(error || notice) && (
          <InlineAlert tone={error ? "error" : "success"}>{error || notice}</InlineAlert>
        )}

        <div className="workspace">
          <Card as="section" id="expedientes" className="documents-panel" aria-labelledby="documents-title">
            <div className="panel-header">
              <div>
                <p className="eyebrow">01 · DOCUMENTACIÓN</p>
                <h2 id="documents-title">Documentos del lote</h2>
              </div>
              <span className="count" aria-label={
                !documentsReady ? "Cantidad de documentos no disponible"
                : `${documents.length} documentos en el lote`
              }>{documentsReady ? documents.length : "—"}</span>
            </div>

            <form className="upload-form" onSubmit={upload}>
              <label htmlFor="upload-pdf">Incorporar un expediente PDF</label>
              <input id="upload-pdf" ref={fileInput} type="file" accept=".pdf,application/pdf"
                disabled={!scope || !canUpload || uploading} required/>
              <p>{scope && !canUpload ? "Solo las comisiones activas con rol de revisión pueden cargar archivos. " : ""}Máximo 8 MiB. Se conservará en cuarentena, sin lectura automática.</p>
              <Button variant="primary" className="upload-button" type="submit" busy={uploading}
                disabled={!scope || !canUpload}>
                {uploading ? "Registrando…" : "Registrar PDF"}
              </Button>
            </form>

            <div className="document-list" aria-live="polite">
              {documentListPhase && <DocumentListState phase={documentListPhase}
                canUpload={Boolean(scope && canUpload)}
                onRetry={()=>setRefresh(value=>value+1)}/>}
              {documentsReady && documents.map((document) => (
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
          </Card>

          <Card as="section" className="evidence-panel" aria-labelledby="evidence-title">
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
                <DocumentProcessingGuidance status={selected.extractionStatus}/>
                {selected.extractionStatus==="ready" && scope
                  ? <InspectedTextViewer key={selected.versionId} scope={scope}
                      versionId={selected.versionId} sha256={selected.sha256}
                      canDraft={Boolean(canUpload)}
                      onDraftCreated={()=>setReviewRefresh(value=>value+1)}/>
                  : <div className="review-placeholder">
                    <h4>Revisión documental pendiente</h4>
                    <p>El PDF original permanece en cuarentena. La consulta por página solo aparece después de verificar su integridad física y recibir un informe firmado de un inspector externo autorizado.</p>
                    <button className="button secondary" disabled title="El documento aún no ha superado la revisión de seguridad">Crear observación</button>
                  </div>}

              </div>
            ) : (
              <div className="empty-evidence">
                <div className="placeholder-art" aria-hidden="true"><span/><span/><span/></div>
                <h3>{!scope ? "Primero abre un lote"
                  : loading || (!documentsFailed && !documentsReady) ? "Consultando evidencia"
                    : documentsFailed ? "Evidencia no disponible" : "Evidencia, no suposiciones"}</h3>
                <p>{!scope
                  ? "Selecciona una comisión y un lote para comenzar la consulta autorizada."
                  : loading || (!documentsFailed && !documentsReady)
                    ? "La información del lote todavía se está consultando."
                    : documentsFailed
                      ? "No fue posible consultar los documentos. Reintenta desde el listado; no se ha verificado ninguna ausencia."
                      : documents.length === 0
                        ? "Todavía no hay documentos registrados para mostrar su versión, huella y estado."
                        : "Selecciona un documento para ver su versión, huella de integridad y estado de procesamiento."}</p>
              </div>
            )}
          </Card>
        </div>
        {scope && <ReviewWorkspace key={scope.commissionId+":"+scope.batchId+":"+reviewRefresh}
          scope={scope} canDraft={Boolean(canUpload)} canManage={Boolean(canManage)}
          onSummaryChange={setReviewSummary}/>} 
        <footer className="page-footer">Folio Cívico · Herramienta de apoyo técnico-administrativo · Las decisiones corresponden a la comisión.</footer>
      </main>
    </div>
  );
}
