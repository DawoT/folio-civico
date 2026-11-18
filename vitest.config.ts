import { defineConfig } from "vitest/config";
export default defineConfig({
  test: { include: ["packages/**/*.test.ts", "apps/**/*.test.ts", "apps/**/*.test.tsx", "tests/**/*.test.ts"], exclude: ["**/node_modules/**", "**/.git/**", "tests/workers/**/*.workers.test.ts"] }
});
