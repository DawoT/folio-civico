/**
 * Interleave a real SQLite state change after the selected D1 response.
 * Test-only adapter: the underlying query executes and returns unmodified rows.
 */
export function afterFirstRead(
  db:D1Database, sqlFragment:string, mutate:()=>void
):D1Database {
  let triggered=false;
  return {
    prepare(sql:string) {
      const statement=db.prepare(sql);
      if(!sql.includes(sqlFragment)) return statement;
      return {
        bind(...values:unknown[]) {
          const bound=statement.bind(...values);
          return {
            async first<T>() {
              const row=await bound.first<T>();
              if(!triggered) {
                triggered=true;
                mutate();
              }
              return row;
            }
          };
        }
      } as unknown as D1PreparedStatement;
    },
    batch:db.batch.bind(db)
  } as D1Database;
}

/** Insert a competing durable write or alter actor authority at the batch boundary. */
export function aroundBatch(
  db:D1Database, intercept:(statements:D1PreparedStatement[])=>Promise<D1Result<unknown>[]>
):D1Database {
  return {
    prepare:db.prepare.bind(db),
    batch:intercept
  } as D1Database;
}
