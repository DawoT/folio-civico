import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  loadChecklist, loadObservationDrafts, submitSearchScopeDraft,
  transitionObservation as requestTransition,
  type ChecklistRow, type ObservationRow, type Scope
} from "./api";

const labels: Record<ChecklistRow["status"], string> = {
  pending: "Pendiente", located: "Ubicado",
  not_located: "No ubicado", observed: "Observado"
};

export function ChecklistStatus({item}: {item: ChecklistRow}) {
  const internallyValidated = item.statusSource === "validated_search"
    && item.validatedSearchObservationId !== null;
  return (
    <>
      <span className="checklist-status">
        {labels[item.status]}{internallyValidated ? " · validación interna" : ""}
      </span>
      {internallyValidated && (
        <small className="checklist-proof">
          Revisor: {item.reviewedBy} · Observación: <code>{item.validatedSearchObservationId}</code>
        </small>
      )}
    </>
  );
}

export function ReviewWorkspace({scope, canDraft}: {scope: Scope; canDraft: boolean}) {
  const [checklist,setChecklist] = useState<ChecklistRow[]>([]);
  const [observations,setObservations] = useState<ObservationRow[]>([]);
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

  useEffect(() => {
    let active = true;
    setLoading(true); setError("");
    setChecklist([]); setObservations([]); setItemId("");
    Promise.all([
      loadChecklist(scope.commissionId),
      loadObservationDrafts(scope.commissionId)
    ]).then(([items,drafts]) => {
      if (!active) return;
      setChecklist(items);
      setObservations(drafts);
      const eligible = items.filter((item) => item.status === "pending" || item.status === "not_located");
      setItemId((current) => eligible.some((item) => item.id === current) ? current : (eligible[0]?.id ?? ""));
    }).catch((problem: unknown) => {
      if (active) setError(problem instanceof Error ? problem.message : "No se pudo cargar la revisión.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [scope.commissionId,reload]);

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
    if(transitionBusy || (action!=="submit" && (!reviewConfirmed || reviewNote.trim().length<15))) return;
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

  return (
    <section className="review-area" aria-labelledby="review-title">
      <div className="review-heading">
        <p className="eyebrow">03 · CONTROL Y OBSERVACIONES</p>
        <h2 id="review-title">Constatación documental</h2>
        <p>Registro de búsquedas realizadas por personas autorizadas. No equivale a declarar una irregularidad.</p>
      </div>
      {error && <p role="alert" className="message error">{error}</p>}
      {notice && <p role="status" className="message success">{notice}</p>}
      <div className="review-grid">
        <div className="review-card">
          <h3>Checklist de constatación</h3>
          {loading ? <p>Consultando ítems…</p> :
            checklist.length === 0 ? <p>No hay ítems configurados. La comisión deberá cargar su checklist aprobado.</p> :
            <ul className="checklist-items">
              {checklist.map((item) => (
                <li key={item.id}>
                  <span className="checklist-area">{item.area === "works" ? "Obras" : "Contrataciones"}</span>
                  <strong>{item.expectedDocument}</strong>
                  <ChecklistStatus item={item}/>
                </li>
              ))}
            </ul>}
          <p className="review-note">Un ítem pasa a «No ubicado · validación interna» solo cuando otro revisor valida la búsqueda documentada. El checklist institucional original no se altera.</p>
        </div>
        <div className="review-card">
          <h3>Registrar búsqueda</h3>
          <p className="review-note">Documenta que se revisó un lote y no se ubicó un ítem esperado. La autoría y la fecha las fija el servidor.</p>
          <form className="review-form" onSubmit={saveDraft}>
            <label htmlFor="review-item">Ítem esperado</label>
            <select id="review-item" value={itemId} onChange={(event) => setItemId(event.target.value)}
              disabled={!canDraft || busy || loading || checklist.length === 0} required>
              <option value="">Selecciona un ítem</option>
              {checklist.filter((item) => item.status === "pending" || item.status === "not_located")
                .map((item) => <option key={item.id} value={item.id}>{item.expectedDocument}</option>)}
            </select>
            <label htmlFor="review-title-input">Título del registro</label>
            <input id="review-title-input" value={title} onChange={(event) => setTitle(event.target.value)}
              maxLength={160} placeholder="Expediente no ubicado durante la revisión" disabled={!canDraft || busy} required/>
            <label htmlFor="review-description">Alcance de la búsqueda</label>
            <textarea id="review-description" value={description}
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
      <div className="review-card observations-card">
        <h3>Borradores y observaciones</h3>
        {loading ? <p>Consultando observaciones…</p> :
          observations.length === 0 ? <p>La comisión todavía no tiene observaciones registradas.</p> :
          <ul className="observation-items">
            {observations.map((record) => <li key={record.id}>
              <div className="observation-heading"><strong>{record.title}</strong><span>{
                record.status==="draft"?"Borrador":
                record.status==="in_review"?"En revisión":
                record.status==="validated"?"Validación interna":"Descartada"
              }</span></div>
              <p>{record.description}</p>
              {record.evidence.map((proof,index) =>
                <p className="proof-reference" key={index}>
                  {proof.type === "SEARCH_SCOPE" ? "Búsqueda documentada" : proof.type === "DOCUMENT_PAGE" ? "Página verificada" : "Fuente oficial"}
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
                  <label htmlFor={`review-note-${record.id}`}>Justificación de la decisión humana</label>
                  <textarea id={`review-note-${record.id}`} rows={3} maxLength={1000}
                    value={reviewNote} disabled={transitionBusy}
                    onChange={event=>setReviewNote(event.target.value)}
                    placeholder="Describe la comprobación independiente realizada (mínimo 15 caracteres)."/>
                  <label className="attestation">
                    <input type="checkbox" checked={reviewConfirmed} disabled={transitionBusy}
                      onChange={event=>setReviewConfirmed(event.target.checked)}/>
                    <span>Confirmo que revisé la evidencia, soy distinto del autor y asumo esta decisión de la comisión.</span>
                  </label>
                  <div className="decision-actions">
                    <button type="button" className="button primary"
                      disabled={transitionBusy || !reviewConfirmed || reviewNote.trim().length<15}
                      onClick={()=>void changeStatus(record,"validate")}>Validar internamente</button>
                    <button type="button" className="button secondary"
                      disabled={transitionBusy || !reviewConfirmed || reviewNote.trim().length<15}
                      onClick={()=>void changeStatus(record,"dismiss")}>Descartar</button>
                  </div>
                </div>
              )}
            </li>)}
          </ul>}
      </div>
    </section>
  );
}
