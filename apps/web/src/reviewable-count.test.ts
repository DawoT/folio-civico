import { describe, expect, it, vi } from "vitest";
import { ApiError, loadReviewableCount } from "./api";

function json(data:unknown,status=200):Response {
  return Response.json(data,{status});
}

describe("FE-04 authorized reviewable count contract",()=>{
  it.each([0,1,31])("accepts a verified, commission-scoped count of %i (not a loaded history page)",async count=>{
    const fetcher=vi.fn(async()=>json({commissionId:"c_a",count}));
    expect(await loadReviewableCount("c_a",fetcher)).toEqual({commissionId:"c_a",count});
    expect(fetcher).toHaveBeenCalledWith(
      "/api/commissions/c_a/observations/reviewable-count",
      expect.objectContaining({credentials:"same-origin",cache:"no-store",
        signal:expect.any(AbortSignal)})
    );
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it.each([
    {commissionId:"c_other",count:31},
    {commissionId:"c_a",count:-1},
    {commissionId:"c_a",count:1.2},
    {commissionId:"c_a",count:"0"},
    {commissionId:"c_a",count:null},
    {commissionId:"c_a",count:Number.MAX_SAFE_INTEGER+1},
    {commissionId:"c_a"},
    [],
    null
  ])("rejects invalid or cross-commission count payloads (fail closed)",async payload=>{
    await expect(loadReviewableCount("c_a",async()=>json(payload)))
      .rejects.toMatchObject({name:"ApiError",status:502});
  });

  it.each([401,403,404,503])("never turns HTTP %i into a verified zero",async status=>{
    await expect(loadReviewableCount("c_a",async()=>json({count:0},status)))
      .rejects.toMatchObject({name:"ApiError",status});
  });

  it("bounds a stalled optional count request without turning timeout into zero",async()=>{
    const signal=new AbortController().signal;
    const timeout=vi.spyOn(AbortSignal,"timeout").mockReturnValue(signal);
    try {
      const fetcher=vi.fn(async(_url:RequestInfo|URL,options?:RequestInit)=>{
        expect(options?.signal).toBe(signal);
        throw new DOMException("The count request timed out","TimeoutError");
      });
      await expect(loadReviewableCount("c_a",fetcher))
        .rejects.toMatchObject({name:"TimeoutError"});
      expect(timeout).toHaveBeenCalledWith(10_000);
    }finally{ timeout.mockRestore(); }
  });

  it("validates the commission identifier before accessing the network",async()=>{
    const fetcher=vi.fn(async()=>json({commissionId:"bad",count:0}));
    await expect(loadReviewableCount("bad/commission",fetcher))
      .rejects.toBeInstanceOf(ApiError);
    expect(fetcher).not.toHaveBeenCalled();
  });
});
