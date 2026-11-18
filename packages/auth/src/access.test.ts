import { describe, expect, it } from "vitest";
import { authenticateAccess } from "./access";

const environment = {
  ACCESS_TEAM_DOMAIN: "https://example.cloudflareaccess.com",
  ACCESS_AUD: "restricted-audience"
};

describe("Cloudflare Access gate", () => {
  it("denies requests without a signed assertion", async () => {
    await expect(authenticateAccess(new Request("https://app.example.test/api"), environment)).resolves.toBeNull();
  });

  it("fails closed when Access configuration is missing", async () => {
    await expect(authenticateAccess(
      new Request("https://app.example.test/api", { headers: { "Cf-Access-Jwt-Assertion": "test" } }),
      { ACCESS_TEAM_DOMAIN: "", ACCESS_AUD: "" }
    )).resolves.toBeNull();
  });

  it("ignores forged identity headers without a signed Access JWT", async () => {
    await expect(authenticateAccess(new Request("https://app.example.test/api", {
      headers: { "Cf-Access-Authenticated-User-Email": "admin@example.test" }
    }), environment)).resolves.toBeNull();
  });

  it("refuses tokens that are not signed JWTs", async () => {
    await expect(authenticateAccess(
      new Request("https://app.example.test/api", { headers: { "Cf-Access-Jwt-Assertion": "invalid" } }),
      environment
    )).resolves.toBeNull();
  });
});
