import { useEffect, useRef, useState, type FormEvent } from "react";
import {InspectedTextViewer} from "./InspectedTextViewer";
import { Field, SelectField, TextareaField } from "./ui/Fields";
import { EmptyState } from "./ui/FeedbackStates";
import { StatusBadge } from "./ui/StatusBadge";
import { ReviewEvidenceContext, canPrepareReviewDecision } from "./ui/ReviewEvidenceContext";
import { ChecklistFilters, countChecklistByStatus, filterChecklistRows, isInternallyValidated, type ChecklistAreaFilter, type ChecklistStatusFilter } from "./ui/ChecklistFilters";
import { ObservationInboxFilters, countLoadedObservations, filterLoadedObservations, inboxEmptyText, type InboxFilter } from "./ui/ObservationInbox";
import { makeReviewSummary, type ReviewSummary } from "./layout/CommissionOverview";
import {
  loadChecklist, loadObservationHistory, loadObservationDetail, loadVerifiedReviewReport, createCommissionChecklistItem, submitSearchScopeDraft,
  transitionObservation as requestTransition,
  type ChecklistRow, type ObservationRow, type ObservationEvidence, type Scope
} from "./api";

const labels: Record<ChecklistRow["status"], string> = {
  pending: "Pendiente", located: "Ubicado",
  not_located: "No ubicado", observed: "Observado"
};

export function ChecklistStatus({item,onOpenValidation}: {item: ChecklistRow; onOpenValidation?: (id:string)=>void}) {
  const internallyValidated = isInternallyValidated(item);
  return (
    <>
      <StatusBadge className="checklist-status" status={internallyValidated ? "validated" : item.status==="pending" ? "warning" : item.status==="located" ? "ready" : "reviewing"}>
        {labels[item.status]}{internallyValidated ? " · validación interna" : ""}
      </StatusBadge>
      {internallyValidated && (
        <>
          <small className="checklist-proof">
            Revisor: {item.reviewedBy} · Observación: <code>{item.validatedSearchObservationId}</code>
          </small>
          {onOpenValidation && (
            <button className="button secondary" type="button"
              onClick={()=>onOpenValidation(item.validatedSearchObservationId!)}>
              Ver validación
            </button>
          )}
        </>
      )}
    </>
  );
}

export function ObservationHistoryControls({nextCursor,loading,error,onNext}:{
  nextCursor:string|null;loading:boolean;error:string;onNext:()=>void;
}) {
  if(nextCursor===null) return null;
  return (
    <div className="history-controls">
      {error && <p role="alert" className="message error">{error}</p>}
      <button className="button secondary" type="button" disabled={loading}
        onClick={onNext}>
        {loading?"Cargando historial…":"Cargar observaciones anteriores"}
      </button>
    </div>
  );
}

export interface InspectedEvidenceReference {
  versionId:string;sha256:string;page:number;
}

/** Only inspected text may be navigated; original PDF bytes are never linked. */
export function DocumentEvidenceAction({proof,onOpen}:{
  proof:ObservationEvidence;onOpen:(reference:InspectedEvidenceReference)=>void;
}) {
  if(proof.type!=="DOCUMENT_PAGE"
    || typeof proof.documentVersionId!=="string"
    || !/^[A-Za-z0-9_-]{1,64}$/.test(proof.documentVersionId)
    || typeof proof.sha256!=="string" || !/^[a-f0-9]{64}$/.test(proof.sha256)
    || typeof proof.page!=="number" || !Number.isSafeInteger(proof.page)
    || proof.page<1 || proof.page>100) return null;
  const reference={versionId:proof.documentVersionId,sha256:proof.sha256,page:proof.page};
  return <button className="button secondary" type="button"
    onClick={()=>onOpen(reference)}>
    Ver página inspeccionada {reference.page}
  </button>;
}

export function ReviewWorkspace({scope, canDraft, canManage=false, onSummaryChange}: {
  scope: Scope; canDraft: boolean; canManage?: boolean;
  onSummaryChange?: (summary: ReviewSummary | null) => void;
}) {
  const [checklist,setChecklist] = useState<ChecklistRow[]>([]);
  const [checklistFilterStatus,setChecklistFilterStatus] = useState<ChecklistStatusFilter>("all");
  const [checklistFilterArea,setChecklistFilterArea] = useState<ChecklistAreaFilter>("all");
  const [observations,setObservations] = useState<ObservationRow[]>([]);
  const [observationFilter,setObservationFilter] = useState<InboxFilter>("all");
  const [historyCursor,setHistoryCursor] = useState<string|null>(null);
  const [historyBusy,setHistoryBusy] = useState(false);
  const [historyError,setHistoryError] = useState("");
  const historyEpoch=useRef(0);
  const [itemId,setItemId] = useState("");
  const [title,setTitle] = useState("");
  const [description,setDescription] = useState("");
  const [attested,setAttested] = useState(false);
  const [busy,setBusy] = useState(false);
  const [loading,setLoading] = useState(true);
  const [error,setError] = useState("");
  const [notice,setNotice] = useState("");
  const [reload,setReload] = useState(0);
  const pendingDraft=useRef<{fingerprint:string;key:string}|null>(null);
  const pendingTransition=useRef<{fingerprint:string;key:string}|null>(null);
  const [activeReviewId,setActiveReviewId]=useState<string|null>(null);
  const [reviewNote,setReviewNote]=useState("");
  const [reviewConfirmed,setReviewConfirmed]=useState(false);
  const [transitionBusy,setTransitionBusy]=useState(false);
  const [linkedRecord,setLinkedRecord]=useState<ObservationRow|null>(null);
  const [focusedPage,setFocusedPage]=useState<InspectedEvidenceReference|null>(null);
  const [linkedLoading,setLinkedLoading]=useState(false);
  const [linkedError,setLinkedError]=useState("");
  const [exportBusy,setExportBusy]=useState(false);
  const [exportError,setExportError]=useState("");
  const [exportHash,setExportHash]=useState("");
  const [checklistArea,setChecklistArea]=useState<"works"|"procurement">("works");
  const [expectedDocument,setExpectedDocument]=useState("");
  const [checklistCreating,setChecklistCreating]=useState(false);
  const pendingChecklist=useRef<{fingerprint:string;key:string}|null>(null);
  const linkedRequest=useRef(0);

  useEffect(() => {
    let active = true;
    historyEpoch.current+=1;
    ++linkedRequest.current;
    setLinkedRecord(null);setFocusedPage(null);setLinkedLoading(false);setLinkedError("");
    setLoading(true); setError("");
    onSummaryChange?.(null);
    setHistoryCursor(null);setHistoryBusy(false);setHistoryError("");
    setChecklist([]); setObservations([]); setItemId("");
    Promise.all([
      loadChecklist(scope.commissionId),
      loadObservationHistory(scope.commissionId)
    ]).then(([items,page]) => {
      if (!active) return;
      setChecklist(items);
      setObservations(page.items);
      setHistoryCursor(page.nextCursor);
      onSummaryChange?.(makeReviewSummary(scope, items, page.items, page.nextCursor !== null));
      const eligible = items.filter((item) => item.status === "pending" || item.status === "not_located");
      setItemId((current) => eligible.some((item) => item.id === current) ? current : (eligible[0]?.id ?? ""));
    }).catch((problem: unknown) => {
      if (active) setError(problem instanceof Error ? problem.message : "No se pudo cargar la revisión.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [scope.commissionId, scope.batchId, reload, onSummaryChange]);

  async function loadOlderObservations() {
    if(!historyCursor || historyBusy || loading) return;
    const epoch=historyEpoch.current;
    const cursor=historyCursor;
    setHistoryBusy(true);setHistoryError("");
    try {
      const page=await loadObservationHistory(scope.commissionId,cursor);
      if(epoch!==historyEpoch.current) return;
      if(page.nextCursor===cursor) {
        throw new Error("El servidor devolvió un cursor repetido.");
      }
      setObservations(current=>{
        const seen=new Set(current.map(item=>item.id));
        return [...current,...page.items.filter(item=>!seen.has(item.id))];
      });
      setHistoryCursor(page.nextCursor);
    } catch(problem) {
      if(epoch===historyEpoch.current) {
        setHistoryError(problem instanceof Error?problem.message:"No se pudo cargar el historial.");
      }
    } finally {
      if(epoch===historyEpoch.current) setHistoryBusy(false);
    }
  }

  async function addChecklistItem(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if(!canManage||checklistCreating||loading) return;
    setChecklistCreating(true);setError("");setNotice("");
    try {
      const fingerprint=JSON.stringify([scope.commissionId,checklistArea,expectedDocument.trim()]);
      const key=pendingChecklist.current?.fingerprint===fingerprint
        ? pendingChecklist.current.key:crypto.randomUUID();
      pendingChecklist.current={fingerprint,key};
      const created=await createCommissionChecklistItem({
        commissionId:scope.commissionId,area:checklistArea,expectedDocument
      },fetch,()=>key);
      pendingChecklist.current=null;
      setExpectedDocument("");
      setNotice(created.replayed?"Ítem existente recuperado por reintento.":"Ítem pendiente incorporado al checklist.");
      setReload(value=>value+1);
    }catch(problem){
      setError(problem instanceof Error?problem.message:"No se pudo incorporar el ítem.");
    }finally{setChecklistCreating(false);}
  }

  async function saveDraft(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canDraft || !attested || !itemId || busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const fingerprint=JSON.stringify([scope.commissionId,scope.batchId,itemId,title.trim(),description.trim()]);
      const key=pendingDraft.current?.fingerprint===fingerprint
        ? pendingDraft.current.key : crypto.randomUUID();
      pendingDraft.current={fingerprint,key};
      await submitSearchScopeDraft({
        commissionId:scope.commissionId,batchId:scope.batchId,
        checklistItemId:itemId,title,description
      },fetch,()=>key);
      pendingDraft.current=null;
      setNotice("Se registró un borrador de búsqueda con revisor y fecha. Requiere revisión humana.");
      setTitle(""); setDescription(""); setAttested(false);
      setReload((value) => value + 1);
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : "No se pudo registrar el borrador.");
    } finally { setBusy(false); }
  }

  async function changeStatus(record:ObservationRow,action:"submit"|"validate"|"dismiss") {
    if(action==="submit") {
      if(transitionBusy || record.status!=="draft" || record.canSubmit!==true) return;
    } else if(!canPrepareReviewDecision(record, activeReviewId, reviewNote, reviewConfirmed, transitionBusy)) return;
    setTransitionBusy(true);setError("");setNotice("");
    try {
      const note=action==="submit"?undefined:reviewNote.trim();
      const fingerprint=JSON.stringify([scope.commissionId,record.id,action,note]);
      const key=pendingTransition.current?.fingerprint===fingerprint
        ? pendingTransition.current.key : crypto.randomUUID();
      pendingTransition.current={fingerprint,key};
      await requestTransition({
        commissionId:scope.commissionId,observationId:record.id,action,note
      },fetch,()=>key);
      pendingTransition.current=null;
      setNotice(action==="submit"
        ? "Borrador enviado a revisión. Aún no ha sido validado."
        : action==="validate"
          ? "Registro validado por un segundo revisor. Si documenta una búsqueda sin resultado, el checklist reflejará «No ubicado · validación interna»."
          : "Observación descartada tras revisión humana.");
      setActiveReviewId(null);setReviewNote("");setReviewConfirmed(false);
      setReload(v=>v+1);
    } catch(problem) {
      setError(problem instanceof Error?problem.message:"No se pudo registrar la decisión.");
    } finally {setTransitionBusy(false);}
  }

  async function exportReviewReport() {
    if (exportBusy) return;
    setExportBusy(true);setExportError("");setExportHash("");
    try {
      const report=await loadVerifiedReviewReport(scope.commissionId);
      const url=URL.createObjectURL(new Blob([report.file],{type:"application/json;charset=utf-8"}));
      try {
        const link=document.createElement("a");
        link.href=url;
        link.download=`folio-civico-${scope.commissionId}-revision-interna.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
      } finally {
        // Allow the browser to begin handling the download before releasing it.
        window.setTimeout(()=>URL.revokeObjectURL(url),1000);
      }
      setExportHash(report.sha256);
    } catch(problem) {
      setExportError(problem instanceof Error ? problem.message : "No se pudo exportar el informe.");
    } finally {
      setExportBusy(false);
    }
  }

  async function openValidation(observationId:string) {
    const requestNumber=++linkedRequest.current;
    setLinkedRecord(null);setFocusedPage(null);setLinkedError("");setLinkedLoading(true);
    try {
      const record=await loadObservationDetail(scope.commissionId,observationId);
      if(requestNumber===linkedRequest.current) setLinkedRecord(record);
    } catch(problem) {
      if(requestNumber===linkedRequest.current) {
        setLinkedError(problem instanceof Error ? problem.message : "No se pudo consultar la validación.");
      }
    } finally {
      if(requestNumber===linkedRequest.current) setLinkedLoading(false);
    }
  }

  const visibleChecklist = filterChecklistRows(checklist, checklistFilterStatus, checklistFilterArea);
  const checklistCounts = countChecklistByStatus(checklist, checklistFilterArea);
  const visibleObservations = filterLoadedObservations(observations, observationFilter);
  const inboxCounts = countLoadedObservations(observations);

  return (
    <section className="review-area" aria-labelledby="review-title">
      <div className="review-heading">
        <p className="eyebrow">03 · CONTROL Y OBSERVACIONES</p>
        <h2 id="review-title">Constatación documental</h2>
        <p>Registro de búsquedas realizadas por personas autorizadas. No equivale a declarar una irregularidad.</p>
        <div className="review-export" id="informes">
          <button type="button" className="button secondary" disabled={exportBusy}
            onClick={()=>void exportReviewReport()}>
            {exportBusy ? "Preparando informe…" : "Exportar revisión interna (JSON)"}
          </button>
          <p className="review-note">
            Incluye decisiones internas validadas y descartadas, sus evidencias, autores y revisores.
            No incluye borradores ni archivos PDF. No constituye un acta oficial.
          </p>
          {exportError && <p role="alert" className="message error">{exportError}</p>}
          {exportHash && <p role="status" className="review-note">
            Integridad verificada. SHA-256: <code className="report-digest">{exportHash}</code>.
            Conserva esta huella por separado; no es una firma digital.
          </p>}
        </div>
      </div>
      {error && <p role="alert" className="message error">{error}</p>}
      {notice && <p role="status" className="message success">{notice}</p>}
      <div className="review-grid">
        <div className="review-card" id="checklist">
          <h3>Checklist de constatación</h3>
          {canManage && (
            <form className="manage-form" onSubmit={addChecklistItem}
              aria-label="Incorporar ítem al checklist">
              <label htmlFor="checklist-area-input">Área del checklist</label>
              <select id="checklist-area-input" value={checklistArea}
                disabled={checklistCreating||loading}
                onChange={event=>setChecklistArea(event.target.value as "works"|"procurement")}>
                <option value="works">Obras</option>
                <option value="procurement">Contrataciones</option>
              </select>
              <label htmlFor="checklist-expected-document">Ítem esperado del checklist</label>
              <input id="checklist-expected-document" value={expectedDocument}
                onChange={event=>setExpectedDocument(event.target.value)}
                placeholder="Documento o expediente a constatar" maxLength={160}
                disabled={checklistCreating||loading} required/>
              <button type="submit" className="button secondary"
                disabled={checklistCreating||loading||expectedDocument.trim().length<3}>
                {checklistCreating?"Incorporando…":"Incorporar ítem"}
              </button>
            </form>
          )}
          {!loading && checklist.length > 0 && (
            <ChecklistFilters selectedStatus={checklistFilterStatus} selectedArea={checklistFilterArea}
              counts={checklistCounts} onStatusChange={setChecklistFilterStatus}
              onAreaChange={setChecklistFilterArea}/>
          )}
          {loading ? <p>Consultando ítems…</p> :
            checklist.length === 0 ? <p>No hay ítems configurados para esta comisión.</p> :
            visibleChecklist.length === 0 ? <EmptyState>No hay ítems que coincidan con los filtros actuales. Cambia el área o el estado.</EmptyState> :
            <ul className="checklist-items">
              {visibleChecklist.map((item) => (
                <li key={item.id}>
                  <span className="checklist-area">{item.area === "works" ? "Obras" : "Contrataciones"}</span>
                  <strong>{item.expectedDocument}</strong>
                  <ChecklistStatus item={item} onOpenValidation={(id)=>void openValidation(id)}/>
                </li>
              ))}
            </ul>}
          <p className="review-note">Un ítem pasa a «No ubicado · validación interna» solo cuando otro revisor valida la búsqueda documentada. El checklist institucional original no se altera.</p>
        </div>
        <div className="review-card" id="registrar-busqueda">
          <h3>Registrar búsqueda</h3>
          <p className="review-note">Documenta que se revisó un lote y no se ubicó un ítem esperado. La autoría y la fecha las fija el servidor.</p>
          <form className="review-form" onSubmit={saveDraft}>
            <SelectField id="review-item" label="Ítem esperado" value={itemId}
              onChange={(event) => setItemId(event.target.value)}
              disabled={!canDraft || busy || loading || checklist.length === 0} required>
              <option value="">Selecciona un ítem</option>
              {checklist.filter((item) => item.status === "pending" || item.status === "not_located")
                .map((item) => <option key={item.id} value={item.id}>{item.expectedDocument}</option>)}
            </SelectField>
            <Field id="review-title-input" label="Título del registro" value={title}
              onChange={(event) => setTitle(event.target.value)}
              maxLength={160} placeholder="Expediente no ubicado durante la revisión"
              disabled={!canDraft || busy} required/>
            <TextareaField id="review-description" label="Alcance de la búsqueda" value={description}
              onChange={(event) => setDescription(event.target.value)} maxLength={4000}
              placeholder="Indica qué archivos, fechas o registros se revisaron."
              rows={4} disabled={!canDraft || busy} required/>
            <label className="attestation">
              <input type="checkbox" checked={attested} onChange={(event) => setAttested(event.target.checked)}
                disabled={!canDraft || busy}/>
              <span>Confirmo que realicé esta búsqueda y describí su alcance, sin inferir una irregularidad.</span>
            </label>
            <button type="submit" className="button primary" disabled={!canDraft || busy || !attested || !itemId || !title.trim() || !description.trim()}>
              {busy ? "Registrando…" : "Guardar borrador"}
            </button>
          </form>
          {!canDraft && <p className="review-note">No puedes crear observaciones con tu rol o en una comisión cerrada.</p>}
        </div>
      </div>
      {(linkedLoading || linkedRecord || linkedError) && (
        <section className="review-card linked-observation-card" aria-labelledby="linked-observation-title">
          <div className="observation-heading">
            <h3 id="linked-observation-title">Detalle de la observación</h3>
            <button type="button" className="button secondary" onClick={()=>{
              ++linkedRequest.current;setLinkedRecord(null);setFocusedPage(null);setLinkedError("");setLinkedLoading(false);
            }}>Cerrar detalle</button>
          </div>
          {linkedLoading && <p role="status">Consultando el detalle autorizado de la observación…</p>}
          {linkedError && <p role="alert" className="message error">{linkedError}</p>}
          {linkedRecord && (
            <div>
              <p className="review-note">Registro de revisión interna · No constituye decisión oficial.</p>
              <h4>{linkedRecord.title}</h4>
              <p>{linkedRecord.description}</p>
              <dl>
                <div><dt>Identificador</dt><dd className="linked-observation-id">{linkedRecord.id}</dd></div>
                <div><dt>Autor</dt><dd>{linkedRecord.authorSubject}</dd></div>
                <div><dt>Revisor</dt><dd>{linkedRecord.reviewedBy ?? "Sin decisión"}</dd></div>
                <div><dt>Fecha de revisión</dt><dd>{linkedRecord.reviewedAt ?? "Pendiente"}</dd></div>
                <div><dt>Justificación</dt><dd>{linkedRecord.reviewNote ?? "Pendiente"}</dd></div>
              </dl>
              <h4>Evidencia registrada</h4>
              <ul className="observation-items">
                {linkedRecord.evidence.map((proof,index)=>(
                  <li key={index}>
                    {proof.type==="SEARCH_SCOPE"
                      ? `Búsqueda en lote ${String(proof.batchId)} · Ítem ${String(proof.checklistItemId)} · Fecha ${String(proof.searchedAt)}`
                      : proof.type==="DOCUMENT_PAGE"
                        ? `Versión ${String(proof.documentVersionId)} · Página ${String(proof.page)}`
                        : "Referencia externa"}
                    <DocumentEvidenceAction proof={proof}
                      onOpen={reference=>setFocusedPage(reference)}/>
                  </li>
                ))}
              </ul>
              {focusedPage && (
                <section className="history-document-reference" aria-label="Página documental citada">
                  <button className="button secondary" type="button"
                    onClick={()=>setFocusedPage(null)}>Cerrar página inspeccionada</button>
                  <InspectedTextViewer key={focusedPage.versionId+":"+focusedPage.page}
                    scope={scope} versionId={focusedPage.versionId}
                    sha256={focusedPage.sha256} focusPage={focusedPage.page}
                    canDraft={false}/>
                </section>
              )}
            </div>
          )}
        </section>
      )}
      <div className="review-card observations-card" id="observaciones">
        <h3>Historial de observaciones</h3>
        <p className="review-note">Se muestran primero 25 registros. Puedes consultar el historial anterior sin perder las observaciones ya cargadas.</p>
        {!loading && observations.length > 0 && (
          <ObservationInboxFilters counts={inboxCounts} selected={observationFilter}
            canDraft={canDraft} hasOlderRecords={historyCursor !== null}
            disabled={transitionBusy || historyBusy}
            onSelect={next => {
              if (next === observationFilter) return;
              setObservationFilter(next);
              setActiveReviewId(null);setReviewNote("");setReviewConfirmed(false);
            }}/>
        )}
        {loading ? <p>Consultando observaciones…</p> :
          observations.length === 0 ? <p>La comisión todavía no tiene observaciones registradas.</p> :
          visibleObservations.length === 0 ? <EmptyState>{inboxEmptyText(observationFilter)}{historyCursor !== null ? " Pueden existir registros coincidentes en páginas anteriores." : ""}</EmptyState> :
          <ul className="observation-items">
            {visibleObservations.map((record) => <li key={record.id}>
              <div className="observation-heading"><strong>{record.title}</strong>
                <StatusBadge status={
                  record.status==="draft"?"neutral":
                  record.status==="in_review"?"reviewing":
                  record.status==="validated"?"validated":"dismissed"
                }>{
                  record.status==="draft"?"Borrador":
                  record.status==="in_review"?"En revisión":
                  record.status==="validated"?"Validación interna":"Descartada"
                }</StatusBadge>
              </div>
              <p>{record.description}</p>
              <button type="button" className="button secondary"
                onClick={()=>void openValidation(record.id)}>
                Ver detalle
              </button>
              {record.evidence.map((proof,index) =>
                <p className="proof-reference" key={index}>
                  {proof.type === "SEARCH_SCOPE" ? "Búsqueda documentada" : proof.type === "DOCUMENT_PAGE" ? "Referencia a página documental" : "Fuente registrada"}
                  {" · "}
                  {proof.type === "SEARCH_SCOPE" ? `Lote ${String(proof.batchId)} · ${String(proof.searchedAt)}` :
                    proof.type === "DOCUMENT_PAGE" ? `Versión ${String(proof.documentVersionId)} · Página ${String(proof.page)}` :
                      String(proof.source)}
                </p>
              )}
              {record.reviewedBy && (
                <p className="review-note">Decisión de {record.reviewedBy}: {record.reviewNote}</p>
              )}
              {record.canSubmit && <button type="button" className="button secondary"
                disabled={transitionBusy} onClick={()=>void changeStatus(record,"submit")}>
                Enviar a revisión
              </button>}
              {record.canReview && activeReviewId!==record.id && (
                <button type="button" className="button secondary" disabled={transitionBusy}
                  onClick={()=>{setActiveReviewId(record.id);setReviewNote("");setReviewConfirmed(false);}}>
                  Revisar registro
                </button>
              )}
              {record.canReview && activeReviewId===record.id && (
                <div className="decision-panel">
                  <ReviewEvidenceContext record={record}/>
                  <TextareaField id={`review-note-${record.id}`} label="Justificación de la decisión humana"
                    rows={3} maxLength={1000} value={reviewNote} disabled={transitionBusy}
                    onChange={event=>setReviewNote(event.target.value)}
                    hint="Mínimo 15 caracteres. La revisión debe ser independiente."
                    placeholder="Describe la comprobación independiente realizada (mínimo 15 caracteres)."/>
                  <label className="attestation">
                    <input type="checkbox" checked={reviewConfirmed} disabled={transitionBusy}
                      onChange={event=>setReviewConfirmed(event.target.checked)}/>
                    <span>Confirmo que revisé la evidencia, soy distinto del autor y asumo esta decisión de la comisión.</span>
                  </label>
                  <div className="decision-actions">
                    <button type="button" className="button primary"
                      disabled={!canPrepareReviewDecision(record, activeReviewId, reviewNote, reviewConfirmed, transitionBusy)}
                      onClick={()=>void changeStatus(record,"validate")}>Validar internamente</button>
                    <button type="button" className="button secondary"
                      disabled={!canPrepareReviewDecision(record, activeReviewId, reviewNote, reviewConfirmed, transitionBusy)}
                      onClick={()=>void changeStatus(record,"dismiss")}>Descartar</button>
                  </div>
                </div>
              )}
            </li>)}
          </ul>}
        {!loading && <ObservationHistoryControls
          nextCursor={historyCursor} loading={historyBusy} error={historyError}
          onNext={()=>void loadOlderObservations()}/>}
      </div>
    </section>
  );
}
