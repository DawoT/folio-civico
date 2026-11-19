import { afterEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleApiRequest, type ApiEnv } from "./index";
import { loadVerifiedReviewReport } from "../../web/src/api";

const issuer = "https://folio-pilot-test.cloudflareaccess.com";
const audience = "folio-civico-pilot-local";
const base = "https://folio.test";
const PDF_BYTES = new TextEncoder().encode(
  "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
);
const RATIONALE = "He cotejado el alcance y la evidencia de la búsqueda realizada por otro miembro.";

type Json = Record<string, unknown>;
afterEach(() => vi.unstubAllGlobals());

async function pilot() {
  const sqlite = makeD1();
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "pilot-e2e-shared-key";
  const jwks = vi.fn(async () => Response.json({ keys: [jwk] }));
  vi.stubGlobal("fetch", jwks);

  const objects = new Map<string, Uint8Array>();
  const put = vi.fn(async (key: string, bytes: Uint8Array) => {
    objects.set(key, bytes);
    return {key};
  });
  const del = vi.fn(async (key: string) => { objects.delete(key); });
  const env: ApiEnv = {
    DB: sqlite.db, DOCUMENTS: { put, delete: del } as unknown as R2Bucket,
    ACCESS_TEAM_DOMAIN: issuer, ACCESS_AUD: audience,
    COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT: "operator"
  };

  async function token(subject: string) {
    return new SignJWT({ purpose: "pilot-synthetic-e2e" })
      .setProtectedHeader({ alg:"RS256", kid:jwk.kid })
      .setIssuer(issuer).setAudience(audience).setSubject(subject)
      .setIssuedAt().setExpirationTime("15m").sign(privateKey);
  }

  async function call(subjectToken: string, path: string, method="GET",
    data?: object | Uint8Array, key?: string) {
    const pdf = data instanceof Uint8Array;
    return handleApiRequest(new Request(base+path, {
      method,
      headers: {
        "Cf-Access-Jwt-Assertion": subjectToken,
        ...(data?{"Content-Type":pdf?"application/pdf":"application/json"}:{}),
        ...(pdf?{"X-Document-Filename":"Expediente%20sintetico.pdf"}:{}),
        ...(key?{"Idempotency-Key":key}:{})
      },
      ...(data?{body:pdf?data as BodyInit:JSON.stringify(data)}:{})
    }), env);
  }
  async function typed<T>(response: Response, status: number): Promise<T> {
    expect(response.status).toBe(status);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    return await response.json() as T;
  }
  return { ...sqlite, env, objects, put, del, jwks, token, call, typed };
}

describe("F5 · complete local pilot journey through signed Worker routes",()=>{
  it("operator → commission → members → batch → quarantine → dual review → checklist → verified offline export",async()=>{
    const p=await pilot();
    const dir=mkdtempSync(join(tmpdir(),"folio-pilot-e2e-"));
    try {
      const operator=await p.token("operator");
      const president=await p.token("president");
      const author=await p.token("author");
      const stranger=await p.token("stranger");

      // No valid JWT subject receives implicit global privileges.
      const attempt=await p.call(stranger,"/api/commissions","POST",{
        name:"Comisión clandestina",initialPresidentSubject:"stranger"
      },"unauthorized-bootstrap-001");
      expect(attempt.status).toBe(403);

      const created=await p.typed<{id:string;replayed:boolean}>(
        await p.call(operator,"/api/commissions","POST",{
          name:"Comisión Distrital Sintética 2026",initialPresidentSubject:"president"
        },"bootstrap-pilot-001"),201);
      const commissionId=created.id;
      expect(created.replayed).toBe(false);
      const repeated=await p.typed<{id:string;replayed:boolean}>(
        await p.call(operator,"/api/commissions","POST",{
          name:"Comisión Distrital Sintética 2026",initialPresidentSubject:"president"
        },"bootstrap-pilot-001"),200);
      expect(repeated).toMatchObject({id:commissionId,replayed:true});

      const prefix=`/api/commissions/${commissionId}`;
      await p.typed(await p.call(president,prefix+"/members","POST",{
        subject:"author",role:"member",expectedRevision:null
      },"pilot-member-author-001"),201);
      await p.typed(await p.call(president,prefix+"/members","POST",{
        subject:"reviewer",role:"member",expectedRevision:null
      },"pilot-member-reviewer-001"),201);
      const reviewer=await p.token("reviewer");

      const batch=await p.typed<{id:string}>(await p.call(president,prefix+"/batches","POST",{
        label:"Lote piloto de obras"
      },"pilot-batch-create-001"),201);
      const checklistItem=await p.typed<{id:string}>(await p.call(
        president,prefix+"/checklist/items","POST",{
          area:"works",expectedDocument:"Expediente de obra a ubicar"
        },"pilot-checklist-create-001"),201);

      const documentsPath=`${prefix}/batches/${batch.id}/documents`;
      const uploaded=await p.typed<{
        documentId:string;versionId:string;sha256:string;
        ingestStatus:string;processingStatus:string;repeated:boolean
      }>(await p.call(author,documentsPath,"POST",PDF_BYTES,"pilot-pdf-upload-001"),201);
      expect(uploaded).toMatchObject({
        ingestStatus:"quarantined",processingStatus:"pending",repeated:false
      });
      expect(uploaded.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(p.objects.size).toBe(1);
      expect(p.put).toHaveBeenCalledTimes(1);

      const retry=await p.typed<{documentId:string;repeated:boolean}>(
        await p.call(author,documentsPath,"POST",PDF_BYTES,"pilot-pdf-upload-001"),200);
      expect(retry).toMatchObject({documentId:uploaded.documentId,repeated:true});
      expect(p.put).toHaveBeenCalledTimes(1);
      const docs=await p.typed<Array<{extractionStatus:string;versionId:string}>>(
        await p.call(author,documentsPath),200);
      expect(docs).toMatchObject([
        {extractionStatus:"pending",versionId:uploaded.versionId}
      ]);
      expect(JSON.stringify(docs)).not.toContain("quarantine/");
      expect((await p.call(author,
        `${prefix}/documents/${uploaded.versionId}/pages`)).status).toBe(404);
      // Quarantined bytes cannot be used as a page citation until a verified
      // inspector manifest has been accepted; this pilot intentionally has no scanner.
      expect((await p.call(author,prefix+"/observations/page-drafts","POST",{
        title:"Cita documental aún no verificada",
        description:"Este PDF no ha sido inspeccionado ni contiene texto certificado.",
        documentVersionId:uploaded.versionId,page:1
      },"pilot-uninspected-page-001")).status).toBe(422);

      const itemBefore=await p.typed<Array<{id:string;status:string}>>(
        await p.call(author,prefix+"/checklist"),200);
      expect(itemBefore).toEqual(expect.arrayContaining([
        expect.objectContaining({id:checklistItem.id,status:"pending"})
      ]));

      const draft=await p.typed<{
        id:string;status:string;authorSubject:string;
        evidence:Array<{type:string;batchId:string;checklistItemId:string}>
      }>(await p.call(author,prefix+"/observations/drafts","POST",{
        title:"Expediente de obra no ubicado",
        description:"Se revisó manualmente el alcance documental del lote sintético.",
        checklistItemId:checklistItem.id,batchId:batch.id
      },"pilot-search-draft-001"),201);
      expect(draft).toMatchObject({
        status:"draft",authorSubject:"author",evidence:[
          {type:"SEARCH_SCOPE",batchId:batch.id,checklistItemId:checklistItem.id}
        ]
      });
      expect((await p.call(author,`${prefix}/observations/${draft.id}/actions`,"POST",{
        action:"validate",note:RATIONALE
      },"pilot-self-approve-001")).status).toBe(403);

      const submitted=await p.typed<{status:string}>(
        await p.call(author,`${prefix}/observations/${draft.id}/actions`,"POST",{
          action:"submit"
        },"pilot-submit-001"),200);
      expect(submitted.status).toBe("in_review");
      expect((await p.typed<Array<{id:string;status:string}>>(
        await p.call(reviewer,prefix+"/checklist"),200)).find(item=>item.id===checklistItem.id)?.status)
        .toBe("pending");

      const validated=await p.typed<{status:string;reviewedBy:string}>(
        await p.call(reviewer,`${prefix}/observations/${draft.id}/actions`,"POST",{
          action:"validate",note:RATIONALE
        },"pilot-review-001"),200);
      expect(validated).toMatchObject({status:"validated",reviewedBy:"reviewer"});
      const checklist=await p.typed<Array<{
        id:string;status:string;statusSource:string;validatedSearchObservationId:string
      }>>(await p.call(author,prefix+"/checklist"),200);
      expect(checklist).toEqual(expect.arrayContaining([
        expect.objectContaining({
          id:checklistItem.id,status:"not_located",statusSource:"validated_search",
          validatedSearchObservationId:draft.id
        })
      ]));
      const detail=await p.typed<{id:string;status:string;reviewedBy:string}>(
        await p.call(author,`${prefix}/observations/${draft.id}`),200);
      expect(detail).toMatchObject({id:draft.id,status:"validated",reviewedBy:"reviewer"});

      const reportPath=prefix+"/observations/export";
      const blocked=await p.call(stranger,reportPath);
      expect(blocked.status).toBe(404);
      const report=await p.call(reviewer,reportPath);
      const payload=await p.typed<{sha256:string;format:string;payload:string}>(report,200);
      expect(payload.format).toBe("folio-civico.review-export.v1");
      const data=JSON.parse(payload.payload) as {
        disclaimer:string;completeness:{included:number;truncated:boolean};
        observations:Array<{id:string;status:string;evidence:Array<{type:string}>}>
      };
      expect(data.completeness).toEqual(expect.objectContaining({included:1,truncated:false}));
      expect(data.observations).toEqual(expect.arrayContaining([
        expect.objectContaining({id:draft.id,status:"validated",
          evidence:[expect.objectContaining({type:"SEARCH_SCOPE"})]})
      ]));
      expect(data.disclaimer).toMatch(/no constituye acta oficial/i);
      expect(JSON.stringify(payload)).not.toMatch(/quarantine\//);
      expect(JSON.stringify(payload)).not.toMatch(/(?:submit|review)RequestKey/);
      const filepath=join(dir,"synthetic-review.json");
      writeFileSync(filepath,JSON.stringify(payload),"utf8");
      const verify=spawnSync(process.execPath,["scripts/verify-review-export.mjs",filepath],{
        encoding:"utf8",timeout:5000
      });
      expect(verify.status).toBe(0);
      expect(verify.stdout).toContain("registros: 1");

      // Browser verifies exactly the same API envelope before making it downloadable.
      const browser=await loadVerifiedReviewReport(commissionId,async ()=>
        p.call(reviewer,reportPath));
      expect(browser.count).toBe(1);
      expect(browser.sha256).toMatch(/^[a-f0-9]{64}$/);

      // Only upload is persisted to mock R2, never served through review or report.
      expect(p.objects.size).toBe(1);
      expect(p.sqlite.prepare("SELECT extraction_status AS status FROM document_versions").get())
        .toMatchObject({status:"pending"});
      expect(p.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get())
        .toMatchObject({n:9});
    }finally{
      rmSync(dir,{recursive:true,force:true});
      p.close();
    }
  });

  it("revocation and commission isolation deny access immediately without corrupting audit or evidence",async()=>{
    const p=await pilot();
    try {
      const operator=await p.token("operator");
      const president=await p.token("president");
      const member=await p.token("member");
      const other=await p.token("other");
      const a=await p.typed<{id:string}>(await p.call(operator,"/api/commissions","POST",{
        name:"Comisión Sintética A",initialPresidentSubject:"president"
      },"commission-A-001"),201);
      const b=await p.typed<{id:string}>(await p.call(operator,"/api/commissions","POST",{
        name:"Comisión Sintética B",initialPresidentSubject:"other"
      },"commission-B-001"),201);
      const pathA=`/api/commissions/${a.id}`;
      await p.typed(await p.call(president,pathA+"/members","POST",{
        subject:"member",role:"member",expectedRevision:null
      },"member-lifecycle-001"),201);
      expect((await p.call(other,pathA+"/members")).status).toBe(404);
      expect((await p.call(member,`/api/commissions/${b.id}/summary`)).status).toBe(404);
      expect((await p.call(member,pathA+"/summary")).status).toBe(200);
      await p.typed(await p.call(president,pathA+"/members/revoke","POST",{
        subject:"member",expectedRevision:1
      },"member-revocation-001"),200);
      expect((await p.call(member,pathA+"/summary")).status).toBe(404);
      expect((await p.call(member,pathA+"/checklist")).status).toBe(404);
      expect((await p.call(member,pathA+"/observations/export")).status).toBe(404);
      expect((await p.call(member,pathA+"/members")).status).toBe(404);
      expect((await p.typed<Array<unknown>>(await p.call(member,"/api/commissions"),200)))
        .toEqual([]);
      expect(p.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get())
        .toMatchObject({n:4});
      expect(p.sqlite.prepare("SELECT count(*) AS n FROM commission_member_actions").get())
        .toMatchObject({n:2});
    }finally{p.close();}
  });
});
