import {useEffect,useRef,useState,type FormEvent} from "react";
import {
  loadCommissionMembers,grantCommissionMember,revokeCommissionMember,
  bootstrapPilotCommission,
  type BootstrapCommissionResult,type CommissionMember,type CommissionMemberRole
} from "./api";

const roleOptions:{value:CommissionMemberRole;label:string}[]=[
  {value:"president",label:"Presidencia"},
  {value:"member",label:"Miembro"},
  {value:"advisor",label:"Asesoría"},
  {value:"observer",label:"Observación"}
];

function MemberLine({member,currentSubject,busy,onGrant,onRevoke}:{
  member:CommissionMember;currentSubject:string;busy:boolean;
  onGrant:(member:CommissionMember,role:CommissionMemberRole)=>void;
  onRevoke:(member:CommissionMember)=>void;
}) {
  const [role,setRole]=useState(member.role);
  const [confirmRevoke,setConfirmRevoke]=useState(false);
  useEffect(()=>{setRole(member.role);setConfirmRevoke(false);},[member.role,member.revision]);
  const self=member.subject===currentSubject;
  const allowed=!self&&!busy;
  return (
    <li className="member-line">
      <div className="member-identity">
        <strong className="member-subject">{member.subject}</strong>
        <span>{member.active?"Acceso vigente":"Acceso revocado"} · Versión {member.revision}</span>
        {self && <small>Tu propia identidad: no puedes cambiar ni revocar tu presidencia</small>}
      </div>
      {!self && (
        <div className="member-controls">
          <label>
            <span>Rol de {member.subject}</span>
            <select value={role} disabled={!allowed}
              onChange={event=>setRole(event.target.value as CommissionMemberRole)}>
              {roleOptions.map(option=><option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <button type="button" className="button secondary"
            aria-label={member.active?`Actualizar rol de ${member.subject}`:`Reactivar ${member.subject}`}
            disabled={!allowed||(member.active&&role===member.role)}
            onClick={()=>onGrant(member,role)}>
            {member.active?"Actualizar rol":"Reactivar"}
          </button>
          {member.active && (
            confirmRevoke ? (
              <div className="revoke-confirm">
                <span>¿Confirmas la revocación de {member.subject}?</span>
                <button className="button secondary" type="button"
                  aria-label={`Confirmar revocación de ${member.subject}`}
                  disabled={!allowed} onClick={()=>{setConfirmRevoke(false);onRevoke(member);}}>
                  Confirmar revocación
                </button>
                <button className="button secondary" type="button"
                  onClick={()=>setConfirmRevoke(false)}>Cancelar</button>
              </div>
            ):(
              <button className="button secondary" type="button" disabled={!allowed}
                aria-label={`Revocar acceso de ${member.subject}`}
                onClick={()=>setConfirmRevoke(true)}>Revocar acceso</button>
            )
          )}
        </div>
      )}
    </li>
  );
}

export function CommissionAdminPanel({commissionId,currentSubject}:{
  commissionId:string;currentSubject:string;
}) {
  const [members,setMembers]=useState<CommissionMember[]>([]);
  const [loading,setLoading]=useState(true);
  const [reload,setReload]=useState(0);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [busy,setBusy]=useState(false);
  const [newSubject,setNewSubject]=useState("");
  const [newRole,setNewRole]=useState<CommissionMemberRole>("member");
  const pending=useRef<{fingerprint:string;key:string}|null>(null);

  useEffect(()=>{
    let active=true;
    setLoading(true);setError("");setNotice("");setMembers([]);
    loadCommissionMembers(commissionId).then(rows=>{
      if(active)setMembers(rows);
    }).catch(problem=>{
      if(active)setError(problem instanceof Error?problem.message:"No se pudieron consultar los miembros.");
    }).finally(()=>{if(active)setLoading(false);});
    return()=>{active=false;};
  },[commissionId,reload]);

  async function updateMember(
    input:{subject:string;expectedRevision:number|null;role?:CommissionMemberRole},
    action:"grant"|"revoke"
  ) {
    if(busy) return;
    setBusy(true);setError("");setNotice("");
    const fingerprint=JSON.stringify([commissionId,action,...Object.values(input)]);
    const key=pending.current?.fingerprint===fingerprint
      ?pending.current.key:crypto.randomUUID();
    pending.current={fingerprint,key};
    try {
      const result=action==="grant"
        ?await grantCommissionMember({
          commissionId,subject:input.subject,role:input.role!,expectedRevision:input.expectedRevision
        },fetch,()=>key)
        :await revokeCommissionMember({
          commissionId,subject:input.subject,expectedRevision:input.expectedRevision!
        },fetch,()=>key);
      pending.current=null;
      setMembers(old=>[...old.filter(member=>member.subject!==result.subject),{
        subject:result.subject,role:result.role,active:result.active,revision:result.revision
      }].sort((a,b)=>Number(b.active)-Number(a.active)||a.subject.localeCompare(b.subject)));
      setNewSubject("");
      setNotice(result.replayed?"Solicitud ya aplicada, sin duplicar auditoría."
        :action==="revoke"?"Acceso revocado. La identidad ya no podrá consultar esta comisión."
        :"Membresía actualizada; el nuevo rol está activo.");
    }catch(problem){
      setError(problem instanceof Error?problem.message:"La membresía no pudo actualizarse.");
    }finally{setBusy(false);}
  }

  function submitMember(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if(!newSubject || newSubject===currentSubject || members.some(member=>member.subject===newSubject))return;
    void updateMember({subject:newSubject,role:newRole,expectedRevision:null},"grant");
  }

  return (
    <section className="admin-panel" aria-labelledby="member-admin-title">
      <div className="observation-heading">
        <h2 id="member-admin-title">Administración de miembros</h2>
        <button type="button" className="button secondary" disabled={busy||loading}
          onClick={()=>setReload(value=>value+1)}>
          Actualizar miembros
        </button>
      </div>
      <p className="review-note">Solo la presidencia activa administra accesos. Usa el identificador
        exacto <code>sub</code> de Cloudflare Access, no una dirección de correo supuesta.</p>
      <form className="manage-form" onSubmit={submitMember} aria-label="Incorporar miembro">
        <label htmlFor="new-member-subject">Identificador de Access (sub)</label>
        <input id="new-member-subject" value={newSubject} maxLength={200}
          onChange={event=>setNewSubject(event.target.value)}
          placeholder="Identidad Access verificada" required disabled={busy||loading}/>
        <label htmlFor="new-member-role">Rol inicial</label>
        <select id="new-member-role" value={newRole} disabled={busy||loading}
          onChange={event=>setNewRole(event.target.value as CommissionMemberRole)}>
          {roleOptions.map(option=><option value={option.value} key={option.value}>{option.label}</option>)}
        </select>
        <button className="button secondary" type="submit"
          disabled={busy||loading||!newSubject||newSubject===currentSubject
            ||members.some(member=>member.subject===newSubject)}>
          {busy?"Guardando…":"Incorporar miembro"}
        </button>
      </form>
      {error && <p className="message error" role="alert">{error}</p>}
      {notice && <p className="message success" role="status">{notice}</p>}
      {loading? <p role="status">Consultando miembros…</p> :
        <ul className="member-list">
          {members.map(member=><MemberLine key={member.subject} member={member}
            currentSubject={currentSubject} busy={busy}
            onGrant={(record,role)=>void updateMember({
              subject:record.subject,role,expectedRevision:record.revision
            },"grant")}
            onRevoke={record=>void updateMember({
              subject:record.subject,expectedRevision:record.revision
            },"revoke")}/>)}
        </ul>
      }
    </section>
  );
}

export function BootstrapCommissionPanel({onCreated}:{
  onCreated:(result:BootstrapCommissionResult)=>void;
}) {
  const [name,setName]=useState("");
  const [president,setPresident]=useState("");
  const [confirmed,setConfirmed]=useState(false);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const pending=useRef<{fingerprint:string;key:string}|null>(null);

  async function create(event:FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if(!confirmed||busy||!name.trim()||!president)return;
    setBusy(true);setError("");setNotice("");
    const fingerprint=JSON.stringify([name.trim(),president]);
    const key=pending.current?.fingerprint===fingerprint?pending.current.key:crypto.randomUUID();
    pending.current={fingerprint,key};
    try {
      const result=await bootstrapPilotCommission({name,initialPresidentSubject:president},fetch,()=>key);
      pending.current=null;
      setName("");setPresident("");setConfirmed(false);
      setNotice(`Comisión creada: ${result.id}. La identidad designada tiene la presidencia inicial.`);
      onCreated(result);
    }catch(problem){
      setError(problem instanceof Error?problem.message:"No se pudo crear la comisión.");
    }finally{setBusy(false);}
  }

  return (
    <section className="admin-panel" aria-labelledby="bootstrap-title">
      <h2 id="bootstrap-title">Crear comisión</h2>
      <p className="review-note">Alta inicial reservada a una identidad operadora autorizada.
        La identidad designada como presidente debe estar verificada previamente en Access.</p>
      <form className="manage-form" onSubmit={create} aria-label="Crear comisión institucional de piloto">
        <label htmlFor="bootstrap-name">Nombre de la comisión</label>
        <input id="bootstrap-name" value={name} maxLength={160} required disabled={busy}
          onChange={event=>setName(event.target.value)} placeholder="Comisión distrital de transferencia"/>
        <label htmlFor="bootstrap-president">Primer presidente — identidad Access (sub)</label>
        <input id="bootstrap-president" value={president} maxLength={200} required disabled={busy}
          onChange={event=>setPresident(event.target.value)} placeholder="Identidad verificada"/>
        <label className="attestation">
          <input type="checkbox" checked={confirmed} disabled={busy}
            onChange={event=>setConfirmed(event.target.checked)}/>
          Confirmo que verifiqué la identidad del primer presidente y tengo autorización de la entidad
        </label>
        <button className="button primary" type="submit"
          disabled={busy||!confirmed||name.trim().length<6||!president}>
          {busy?"Registrando comisión…":"Crear comisión"}
        </button>
      </form>
      {error && <p className="message error" role="alert">{error}</p>}
      {notice && <p className="message success" role="status">{notice}</p>}
    </section>
  );
}
