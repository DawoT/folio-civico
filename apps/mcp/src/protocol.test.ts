import { describe, expect, it, vi, beforeEach } from "vitest";
import { handleMcpRequest } from "./index";
import { authenticateAccess } from "@folio/auth";
import { makeD1 } from "../../../tests/helpers/d1";

vi.mock("@folio/auth", () => ({ authenticateAccess: vi.fn() }));
const auth = vi.mocked(authenticateAccess);
const url = "https://mcp.test/mcp";
function rpc(id: number, method: string, params: object = {}) {
  const headers = new Headers({
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2026-07-28",
    "Mcp-Method": method
  });
  if (method === "tools/call" && "name" in params && typeof params.name === "string") {
    headers.set("Mcp-Name", params.name);
  }
  return new Request(url, {
    method: "POST", headers,
    body: JSON.stringify({
      jsonrpc: "2.0", id, method,
      params: {
        ...params,
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {}
        }
      }
    })
  });
}

describe("MCP protocol and tenant permissions", () => {
  beforeEach(()=>auth.mockReset());

  function fixture() {
    const f=makeD1();
    f.sqlite.exec(`
      INSERT INTO commissions(id,name) VALUES('c_a','Comisión A'),('c_b','Comisión B');
      INSERT INTO commission_members(commission_id,subject,role,active)
        VALUES('c_a','alice','member',1),('c_b','bob','member',1);
      INSERT INTO checklist_items(id,commission_id,area,expected_document)
        VALUES('item_a','c_a','works','Expediente de obra'),('item_b','c_b','procurement','Contrato reservado');
    `);
    return f;
  }

  it("denies browser origins rather than relying on permissive CORS", async () => {
    auth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const request=rpc(1,"tools/list");
      request.headers.set("Origin","https://attacker.test");
      const response=await handleMcpRequest(request,{DB:f.db},{} as never);
      expect(response.status).toBe(403);
      expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
    } finally {f.close();}
  });

  it("handles JSON-RPC tools/list and a scoped tool call without revealing other commissions", async () => {
    auth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const env={DB:f.db};
      const tools=await handleMcpRequest(rpc(1,"tools/list"),env,{} as never);
      expect(tools.status, await tools.clone().text()).toBe(200);
      const listBody=await tools.text();
      expect(listBody).toContain("get_commission_summary");
      expect(listBody).toContain("get_checklist_status");
      expect(listBody).toContain("list_my_commissions");
      expect(listBody).toContain("list_commission_batches");
      const myCommissions = await handleMcpRequest(
        rpc(4,"tools/call",{name:"list_my_commissions",arguments:{}}),env,{} as never);
      expect(myCommissions.status).toBe(200);
      const membership = await myCommissions.text();
      expect(membership).toContain("Comisión A");
      expect(membership).not.toContain("Comisión B");
      const allowed=await handleMcpRequest(
        rpc(2,"tools/call",{name:"get_commission_summary",arguments:{commissionId:"c_a"}}),env,{} as never);
      expect(allowed.status, await allowed.clone().text()).toBe(200);
      expect(await allowed.text()).toContain("Comisión A");
      const blocked=await handleMcpRequest(
        rpc(3,"tools/call",{name:"get_commission_summary",arguments:{commissionId:"c_b"}}),env,{} as never);
      expect(blocked.status).toBe(200);
      const payload=await blocked.text();
      expect(payload).toContain("Commission not found or inaccessible");
      expect(payload).not.toContain("Comisión B");

      const checklist = await handleMcpRequest(
        rpc(5,"tools/call",{name:"get_checklist_status",arguments:{commissionId:"c_a"}}),env,{} as never);
      expect(checklist.status).toBe(200);
      expect(await checklist.text()).toContain("Expediente de obra");
      const deniedChecklist = await handleMcpRequest(
        rpc(6,"tools/call",{name:"get_checklist_status",arguments:{commissionId:"c_b"}}),env,{} as never);
      expect(deniedChecklist.status).toBe(200);
      const deniedBody=await deniedChecklist.text();
      expect(deniedBody).toContain("Commission not found or inaccessible");
      expect(deniedBody).not.toContain("Contrato reservado");
    } finally {f.close();}
  });
});
