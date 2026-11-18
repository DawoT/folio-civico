import { describe, expect, it } from "vitest";
import { handleMcpRequest } from "./index";

describe("MCP authorization boundary", () => {
  it("rejects anonymous MCP requests before invoking any tool", async () => {
    const response = await handleMcpRequest(
      new Request("https://mcp.test/mcp", { method: "POST" }),
      {} as never,
      {} as never
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("does not expose unrelated routes", async () => {
    const response = await handleMcpRequest(new Request("https://mcp.test/"), {} as never, {} as never);
    expect(response.status).toBe(404);
  });
});
