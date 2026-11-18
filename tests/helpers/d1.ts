import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";

type Arg = string | number | bigint | null | Uint8Array;

export function makeD1(): { db: D1Database; sqlite: DatabaseSync; close(): void } {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(readFileSync(new URL("../../migrations/0001_initial.sql", import.meta.url), "utf8"));
  sqlite.exec(readFileSync(new URL("../../migrations/0002_upload_intake.sql", import.meta.url), "utf8"));

  class SqlStatement {
    constructor(readonly sql: string, readonly params: Arg[] = []) {}
    bind(...params: Arg[]): SqlStatement {
      return new SqlStatement(this.sql, params);
    }
    async first<T>(): Promise<T | null> {
      return (sqlite.prepare(this.sql).get(...this.params) as T | undefined) ?? null;
    }
    async all<T>(): Promise<{ success: boolean; results: T[] }> {
      return { success: true, results: sqlite.prepare(this.sql).all(...this.params) as T[] };
    }
    async run(): Promise<{ success: boolean; meta: { changes: number } }> {
      const info = sqlite.prepare(this.sql).run(...this.params);
      return { success: true, meta: { changes: Number(info.changes) } };
    }
  }

  const db = {
    prepare(sql: string) { return new SqlStatement(sql); },
    async batch(statements: SqlStatement[]) {
      sqlite.exec("BEGIN IMMEDIATE");
      try {
        const result = [];
        for (const stmt of statements) result.push(await stmt.run());
        sqlite.exec("COMMIT");
        return result;
      } catch (error) {
        sqlite.exec("ROLLBACK");
        throw error;
      }
    }
  } as unknown as D1Database;

  return { db, sqlite, close: () => sqlite.close() };
}
