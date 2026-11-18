import { describe, expect, it } from "vitest";
import { handleApiRequest } from "./index";

describe("API authorization boundary", () => {
  it("exposes only a non-sensitive health probe without authentication", async () => {
    const response = await handleApiRequest(new Request("https://api.test/health"), {} as never);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok" });
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
