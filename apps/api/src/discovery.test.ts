import { beforeEach, describe, expect, it, vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleApiRequest } from "./index";
import { authenticateAccess } from "@folio/auth";

vi.mock("@folio/auth", () => ({ authenticateAccess: vi.fn() }));
const mockAuth = vi.mocked(authenticateAccess);

describe("API authenticated discovery", () => {
  beforeEach(() => mockAuth.mockReset());

  function fixture() {
    const f = makeD1();
    f.sqlite.exec(`
      INSERT INTO commissions(id,name) VALUES ('c_a','Comisión A'),('c_b','Comisión B');
      INSERT INTO commission_members(commission_id,subject,role,active)
        VALUES ('c_a','alice','member',1),('c_b','bob','member',1);
      INSERT INTO document_batches(id,commission_id,label)
        VALUES ('ba_1','c_a','Obras'),('bb_1','c_b','Contrataciones');
    `);
    return f;
  }

  it("does not expose commission discovery without identity", async () => {
    mockAuth.mockResolvedValue(null);
    const f=fixture();
    try {
      const response=await handleApiRequest(new Request("https://folio.test/api/commissions"),{ DB:f.db });
      expect(response.status).toBe(401);
    } finally {f.close();}
  });

  it("returns only commissions and batches assigned to the signed-in subject", async () => {
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const env={DB:f.db};
      const commissions=await handleApiRequest(new Request("https://folio.test/api/commissions"),env);
      expect(commissions.status).toBe(200);
      expect(await commissions.json()).toMatchObject([{id:"c_a"}]);
      const batches=await handleApiRequest(new Request("https://folio.test/api/commissions/c_a/batches"),env);
      expect(batches.status).toBe(200);
      expect(await batches.json()).toEqual([{id:"ba_1",label:"Obras"}]);
      const blocked=await handleApiRequest(new Request("https://folio.test/api/commissions/c_b/batches"),env);
      expect(blocked.status).toBe(404);
      expect(blocked.headers.get("Cache-Control")).toBe("no-store");
    } finally {f.close();}
  });

  it("denies bootstrap to ordinary signed members and rejects malformed discovery routes", async () => {
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const post=await handleApiRequest(new Request("https://folio.test/api/commissions",{method:"POST"}),{DB:f.db});
      expect(post.status).toBe(403); // No trusted operator binding: fail closed.
      const malformed=await handleApiRequest(new Request("https://folio.test/api/commissions/../batches"),{DB:f.db});
      expect(malformed.status).toBe(404);
    } finally {f.close();}
  });
});
