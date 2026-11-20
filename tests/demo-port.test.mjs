import { describe, expect, it } from "vitest";
import { resolveDemoPort } from "../apps/web/demo-port.mjs";

describe("isolated local demo port", () => {
  it("preserves the documented loopback default", () => {
    expect(resolveDemoPort(undefined)).toBe(4176);
  });

  it("supports independent, explicitly assigned local worktree ports", () => {
    expect(resolveDemoPort("4518")).toBe(4518);
    expect(resolveDemoPort("65535")).toBe(65535);
  });

  it.each(["", "0", "1023", "65536", "77777", "abc", "4176.0", "1e4", " 4176", "4176 ", "04176", "4176;exit"])(
    "rejects unsafe or malformed port %j before starting the demo",
    (value) => {
      expect(() => resolveDemoPort(value)).toThrow(/FOLIO_DEMO_PORT/);
    }
  );
});
