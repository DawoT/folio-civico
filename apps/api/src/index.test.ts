import { describe, expect, it } from "vitest";
import { handleApiRequest } from "./index";

describe("API authorization boundary", () => {
  it("exposes only a non-sensitive health probe without authentication", async () => {
    const response = await handleApiRequest(new Request("https://api.test/health"), {} as never);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok" });
  });

  it("denies anonymous uploads even when a caller supplies a forged identity header", async () => {
    const response = await handleApiRequest(new Request(
      "https://api.test/api/commissions/c_a/batches/b_a/documents",
      { method: "POST", headers: { "Cf-Access-Authenticated-User-Email": "admin@example.test" }, body: "%PDF-1.7" }
    ), {} as never);
    expect(response.status).toBe(401);
  });

  it("recognizes the observation detail endpoint but rejects unauthenticated requests", async () => {
    const response=await handleApiRequest(new Request(
      "https://api.test/api/commissions/c_a/observations/obs_123"
    ),{} as never);
    expect(response.status).toBe(401);
  });

  it("denies unauthenticated commission requests", async () => {
    const response = await handleApiRequest(
      new Request("https://api.test/api/commissions/com_1/summary"),
      {} as never
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });
});
