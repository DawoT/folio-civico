import {describe,expect,it,vi} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {
  loadSession,loadCommissionMembers,grantCommissionMember,revokeCommissionMember,
  bootstrapPilotCommission
} from "./api";
import {CommissionAdminPanel,BootstrapCommissionPanel} from "./CommissionAdmin";

describe("pilot administration web client",()=>{
  it("loads JWT-derived session and permission-scoped membership",async()=>{
    const fetcher=vi.fn(async (url:RequestInfo|URL)=>{
      if(url==="/api/session") return Response.json({subject:"president",canBootstrap:false});
      return Response.json([{subject:"president",role:"president",active:true,revision:1}]);
    });
    expect(await loadSession(fetcher)).toEqual({subject:"president",canBootstrap:false});
    expect(await loadCommissionMembers("c_a",fetcher)).toMatchObject([
      {subject:"president",role:"president",revision:1}
    ]);
    expect(fetcher).toHaveBeenCalledWith("/api/session",{credentials:"same-origin",cache:"no-store"});
    expect(fetcher).toHaveBeenCalledWith("/api/commissions/c_a/members",{
      credentials:"same-origin",cache:"no-store"
    });
    await expect(loadCommissionMembers("../c_b",fetcher)).rejects.toThrow();
  });

  it("sends grant, promotion and revoke with revisions and idempotency, not client-supplied actor",async()=>{
    const fetcher=vi.fn(async (_url:RequestInfo|URL,_init?:RequestInit)=>Response.json({
      subject:"subject_2",role:"member",active:true,revision:1,replayed:false
    },{status:201}));
    const created=await grantCommissionMember({
      commissionId:"c_a",subject:"subject_2",role:"member",expectedRevision:null
    },fetcher,()=>"admin_create_12345");
    expect(created.revision).toBe(1);
    await revokeCommissionMember({
      commissionId:"c_a",subject:"subject_2",expectedRevision:1
    },fetcher,()=>"admin_revoke_12345");
    const calls=fetcher.mock.calls;
    expect(calls[0]?.[0]).toBe("/api/commissions/c_a/members");
    expect(calls[1]?.[0]).toBe("/api/commissions/c_a/members/revoke");
    for(const [url,options] of calls) {
      expect(url).toContain("/api/commissions/c_a/members");
      expect(options).toMatchObject({method:"POST",credentials:"same-origin",cache:"no-store",
        headers:{"Content-Type":"application/json","Idempotency-Key":expect.any(String)}});
      const body=JSON.parse(options?.body as string);
      expect(body).not.toHaveProperty("actor");
      expect(body).not.toHaveProperty("commissionId");
    }
    await expect(grantCommissionMember({
      commissionId:"c_a",subject:"evil\nsubject",role:"member",expectedRevision:null
    },fetcher)).rejects.toThrow();
    await expect(revokeCommissionMember({
      commissionId:"c_a",subject:"subject_2",expectedRevision:0
    },fetcher)).rejects.toThrow();
  });

  it("bootstraps only server-selected operator identity and validates responses",async()=>{
    const fetcher=vi.fn(async (_url:RequestInfo|URL,_init?:RequestInit)=>Response.json({
      id:"generated_id_123",name:"Comisión de Transferencia",
      initialPresidentSubject:"lead",replayed:false
    },{status:201}));
    const created=await bootstrapPilotCommission({
      name:"Comisión de Transferencia",initialPresidentSubject:"lead"
    },fetcher,()=>"operator_creation_001");
    expect(created.id).toBe("generated_id_123");
    const [url,init]=fetcher.mock.calls[0]!;
    if(!init) throw new Error("Missing request init");
    expect(url).toBe("/api/commissions");
    expect(init).toMatchObject({
      method:"POST",credentials:"same-origin",cache:"no-store",
      headers:{"Content-Type":"application/json","Idempotency-Key":"operator_creation_001"}
    });
    expect(JSON.parse(init.body as string)).toEqual({
      name:"Comisión de Transferencia",initialPresidentSubject:"lead"
    });
    await expect(bootstrapPilotCommission({
      name:"Abc",initialPresidentSubject:"lead"
    },fetcher)).rejects.toThrow();
  });

  it("renders member management only for an eligible commission president and bootstrap only for operator",()=>{
    const html=renderToStaticMarkup(<CommissionAdminPanel commissionId="c_a"
      currentSubject="president" />);
    expect(html).toContain("Administración de miembros");
    expect(html).toContain("Identificador de Access");
    expect(html).toContain("Incorporar miembro");
    expect(html).toContain("Actualizar miembros");
    const bootstrap=renderToStaticMarkup(<BootstrapCommissionPanel
      onCreated={()=>{}}/>);
    expect(bootstrap).toContain("Crear comisión");
    expect(bootstrap).toContain("Primer presidente");
    expect(bootstrap).toContain("Confirmo");
  });
});
