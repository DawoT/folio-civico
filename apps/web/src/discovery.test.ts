import { describe,expect,it,vi } from "vitest";
import { loadCommissions, loadCommissionBatches } from "./api";

describe("frontend commission discovery client", () => {
  it("never caches membership or batch discovery requests", async () => {
    const fetcher=vi.fn(async (_input: RequestInfo|URL,_options?: RequestInit)=>
      Response.json([{id:"c_a",name:"Comisión A",status:"active",role:"member"}]));
    const commissions=await loadCommissions(fetcher);
    expect(commissions).toHaveLength(1);
    expect(fetcher).toHaveBeenCalledWith("/api/commissions", expect.objectContaining({cache:"no-store",credentials:"same-origin"}));
  });

  it("encodes scoped batch lookup and refuses path traversal", async () => {
    const fetcher=vi.fn(async(_input:RequestInfo|URL,_options?:RequestInit)=>
      Response.json([{id:"ba_1",label:"Obras"}]));
    expect(await loadCommissionBatches("c_a",fetcher)).toEqual([{id:"ba_1",label:"Obras"}]);
    expect(fetcher).toHaveBeenCalledWith("/api/commissions/c_a/batches",expect.anything());
    await expect(loadCommissionBatches("../c_b",fetcher)).rejects.toThrow();
  });

  it("does not turn an access denial into an empty list", async () => {
    const denied=vi.fn(async()=>new Response(null,{status:401}));
    await expect(loadCommissions(denied)).rejects.toMatchObject({status:401});
  });
});
