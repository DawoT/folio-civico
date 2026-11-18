import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function makeDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync(new URL("../migrations/0001_initial.sql", import.meta.url), "utf8"));
  return db;
}

describe("D1 SQLite migration invariants", () => {
  it("migrates with FTS5 and rejects cross-commission batch links", () => {
    const db = makeDb();
    try {
      db.exec("INSERT INTO commissions(id,name) VALUES ('com_a','A'),('com_b','B')");
      db.exec("INSERT INTO document_batches(id,commission_id,label) VALUES ('batch_a','com_a','Entrega A')");
      expect(() => db.exec(
        "INSERT INTO documents(id,commission_id,batch_id,filename) VALUES ('doc_x','com_b','batch_a','contrato.pdf')"
      )).toThrow(/FOREIGN KEY/);
    } finally { db.close(); }
  });

  it("indexes and searches native extracted page text", () => {
    const db = makeDb();
    try {
      db.exec("INSERT INTO commissions(id,name) VALUES ('com_a','A')");
      db.exec("INSERT INTO document_batches(id,commission_id,label) VALUES ('batch_a','com_a','Entrega')");
      db.exec("INSERT INTO documents(id,commission_id,batch_id,filename) VALUES ('doc_a','com_a','batch_a','contrato.pdf')");
      db.exec(`INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key,page_count)
        VALUES ('ver_a','doc_a',1,'${"f".repeat(64)}','quarantine/file',10)`);
      db.exec("INSERT INTO document_pages(document_version_id,page,extracted_text,extraction_status) VALUES ('ver_a',2,'Contrato de obra 2026','ready')");
      const result = db.prepare("SELECT extracted_text FROM document_pages_fts WHERE document_pages_fts MATCH 'Contrato'").get();
      expect(result).toMatchObject({ extracted_text: "Contrato de obra 2026" });
    } finally { db.close(); }
  });
});
