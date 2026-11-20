/**
 * Deterministic D1 race injection for multi-query read contracts.
 * Delivers legitimate evidence rows, then changes live SQLite state before
 * the caller can construct its response. Never runs in production code.
 */
export function afterEvidenceRead(
  db: D1Database, updateMembershipOrCommission: () => void
): D1Database {
  let triggered = false;
  return {
    prepare(sql: string) {
      const statement = db.prepare(sql);
      if (!sql.includes("SELECT reference_json AS referenceJson FROM observation_evidence")) {
        return statement;
      }
      return {
        bind(...params: unknown[]) {
          const bound = statement.bind(...params);
          return {
            async all<T>() {
              const result = await bound.all<T>();
              if (!triggered) {
                triggered = true;
                updateMembershipOrCommission();
              }
              return result;
            }
          };
        }
      } as unknown as D1PreparedStatement;
    }
  } as D1Database;
}
