import { useEffect,useRef,useState,type FormEvent } from "react";
import {
  loadDocumentText,submitDocumentPageDraft,
  type DocumentTextPage,type DocumentTextView,type Scope
} from "./api";

/** React renders inspector text as text nodes; never inject HTML or embed original PDF. */
export function InspectedPage({
  page,versionId,sha256,onCite
}: {page:DocumentTextPage;versionId:string;sha256:string;onCite?:()=>void}) {
  return (
    <article className="inspected-page" aria-label={`Texto de la página ${page.page}`}>
      <div className="inspected-page-header">
        <strong>Página {page.page}</strong>
        <span>Texto extraído</span>
      </div>
      <p className="inspected-page-text">{page.text}</p>
      <p className="inspected-page-citation">
        Referencia: versión <code>{versionId}</code> · página {page.page} · SHA-256 <code>{sha256}</code>
      </p>
      {onCite && <button className="button secondary" type="button" onClick={onCite}>
        Crear borrador con esta página
      </button>}
    </article>
  );
}

/** Accessible text view, not a PDF renderer. Page drafts always require a human action. */
export function InspectedTextViewer({
  scope,versionId,sha256,canDraft,onDraftCreated,focusPage
}: {scope:Scope;versionId:string;sha256:string;canDraft:boolean;onDraftCreated?:()=>void;focusPage?:number}) {
  const [view,setView]=useState<DocumentTextView|null>(null);
  const [busy,setBusy]=useState(true);
  const [error,setError]=useState("");
  const [activePage,setActivePage]=useState<number|null>(null);
  const [title,setTitle]=useState("");
  const [description,setDescription]=useState("");
  const [confirmed,setConfirmed]=useState(false);
  const [saving,setSaving]=useState(false);
  const [notice,setNotice]=useState("");
  const pending=useRef<{fingerprint:string;key:string}|null>(null);

  useEffect(()=>{
    let active=true;
    setBusy(true);setError("");setView(null);setActivePage(null);setNotice("");
    loadDocumentText(scope.commissionId,versionId).then(result=>{
      if(!active)return;
      if(result.versionId!==versionId || result.sha256!==sha256
        || result.pageCount!==result.pages.length) {
        setError("Las referencias documentales no coinciden con la versión seleccionada.");
        return;
      }
      if(focusPage!==undefined && (!Number.isSafeInteger(focusPage)
        || !result.pages.some(page=>page.page===focusPage))) {
        setError("La página citada no existe en el texto inspeccionado.");
        return;
      }
      setView(result);
    }).catch((reason:unknown)=>{
      if(active)setError(reason instanceof Error?reason.message:"No se pudo recuperar el texto procesado.");
    }).finally(()=>{if(active)setBusy(false);});
    return ()=>{active=false;};
  },[scope.commissionId,versionId,sha256,focusPage]);

  async function saveCitation(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if(!canDraft || activePage===null || !confirmed || saving || !view
      || !view.pages.some(item=>item.page===activePage))return;
    setSaving(true);setError("");setNotice("");
    try {
      const fingerprint=JSON.stringify([scope.commissionId,versionId,activePage,title.trim(),description.trim()]);
      const key=pending.current?.fingerprint===fingerprint?pending.current.key:crypto.randomUUID();
      pending.current={fingerprint,key};
      await submitDocumentPageDraft({
        commissionId:scope.commissionId,documentVersionId:versionId,
        page:activePage,title,description
      },fetch,()=>key);
      pending.current=null;
      setTitle("");setDescription("");setConfirmed(false);setActivePage(null);
      setNotice("Borrador guardado con versión, SHA-256 y página. Requiere revisión humana.");
      onDraftCreated?.();
    }catch(reason){
      setError(reason instanceof Error?reason.message:"No se pudo registrar la referencia.");
    }finally{setSaving(false);}
  }
  return (
    <section className="inspected-text-viewer" aria-label="Consulta de texto inspeccionado">
      <h4>Consulta documental por página</h4>
      <p className="review-note">
        Solo texto entregado por un inspector externo autorizado.
        El PDF original continúa en cuarentena y no se muestra en este visor.
      </p>
      {busy && <p role="status">Consultando páginas verificadas…</p>}
      {error && <p className="message error" role="alert">{error}</p>}
      {notice && <p className="message success" role="status">{notice}</p>}
      {view && <div className="inspected-pages">
        {view.pages.filter(page=>focusPage===undefined || page.page===focusPage).map(page=><InspectedPage key={page.page}
          page={page} versionId={view.versionId} sha256={view.sha256}
          onCite={canDraft?()=>{setActivePage(page.page);setConfirmed(false);setError("");}:undefined}/>)}
      </div>}
      {view && activePage!==null && canDraft && (
        <form className="review-form inspected-citation-form" onSubmit={saveCitation}>
          <h4>Borrador basado en página {activePage}</h4>
          <p className="review-note">Este registro cita texto inspeccionado; no implica un hallazgo ni una aprobación oficial.</p>
          <label htmlFor="inspected-citation-title">Título de la observación</label>
          <input id="inspected-citation-title" value={title} maxLength={160} required
            onChange={event=>setTitle(event.target.value)} disabled={saving}/>
          <label htmlFor="inspected-citation-description">Constatación personal</label>
          <textarea id="inspected-citation-description" rows={3} value={description}
            maxLength={4000} required disabled={saving}
            onChange={event=>setDescription(event.target.value)}/>
          <label className="attestation">
            <input type="checkbox" checked={confirmed} disabled={saving}
              onChange={event=>setConfirmed(event.target.checked)}/>
            <span>Confirmo que revisé personalmente el contenido de esta página.</span>
          </label>
          <div className="decision-actions">
            <button className="button primary" type="submit"
              disabled={saving || !confirmed || !title.trim() || !description.trim()}>
              {saving?"Guardando…":"Guardar borrador de página"}
            </button>
            <button className="button secondary" type="button" disabled={saving}
              onClick={()=>{setActivePage(null);setConfirmed(false);}}>Cancelar</button>
          </div>
        </form>
      )}
    </section>
  );
}
