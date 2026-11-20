/**
 * Folio Cívico: isolated, loopback-only product demo with the production API
 * handler and a disposable D1/R2 stand-in. No Cloudflare account or actual
 * Access credentials, Queue, inspector, or institutional documents.
 *
 * Run: pnpm demo:local   (from the repository root)
 */
import { createServer as createHttpServer } from "node:http";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer as createViteServer } from "vite";

const HOST = "127.0.0.1";
const PORT = 4176;
const ORIGIN = `http://${HOST}:${PORT}`;
const ISSUER = "https://folio-demo-local.cloudflareaccess.com";
const AUDIENCE = "folio-civico-synthetic-demo";
const COOKIE_NAME = "folio_demo_role";
const ROLES = ["president", "author", "reviewer", "observer"];
const ROOT = dirname(fileURLToPath(import.meta.url));
const fromApi = createRequire(new URL("../api/package.json", import.meta.url));
const { exportJWK, generateKeyPair, SignJWT } = await import(fromApi.resolve("jose"));

function htmlEscape(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function parseRole(raw) {
  const value = raw?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(COOKIE_NAME + "="))?.slice(COOKIE_NAME.length + 1);
  return ROLES.includes(value) ? value : "president";
}

function renderGuide(role, scope) {
  const link = `/?commission=${encodeURIComponent(scope.commissionId)}&batch=${encodeURIComponent(scope.batchId)}`;
  const descriptions = {
    president: "Gestiona los miembros, lotes y el checklist. No valida automáticamente.",
    author: "Registra una búsqueda documental no ubicada y envíala a revisión.",
    reviewer: "Revisa una observación enviada por otra persona y justifica la decisión.",
    observer: "Consulta el historial y la evidencia sin controles de escritura."
  };
  const roles = ROLES.map((value) =>
    `<a class="role ${value === role ? "active" : ""}" href="/__demo/switch?as=${value}">${htmlEscape(value)} · ${htmlEscape(descriptions[value])}</a>`
  ).join("");
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Folio Cívico · Demo local</title>
<style>
body{font:16px system-ui,sans-serif;background:#f5f7f7;color:#173038;margin:0}
main{max-width:760px;margin:5vh auto;padding:26px}
h1{font-size:2rem;margin-bottom:.3rem}p{line-height:1.55}
small{color:#526269}.role{display:block;padding:13px 15px;margin:8px 0;border-radius:10px;border:1px solid #c7d4d4;background:#fff;color:#143d44;text-decoration:none}
.role.active{border:2px solid #145e59}
a.open{display:inline-block;background:#0b5851;color:white;padding:13px 18px;border-radius:9px;text-decoration:none;margin-top:14px}
.notice{border-left:4px solid #8b5b20;padding:12px 15px;background:#fffae9;margin:24px 0}
</style></head><body><main>
<small>ENTORNO LOCAL AISLADO · DATOS FICTICIOS · SIN CLOUDFLARE REMOTO</small>
<h1>Folio Cívico</h1><p>Evidencia para una transferencia ordenada.</p>
<p>Comisión y lote sintéticos precargados. Rol actual: <strong>${htmlEscape(role)}</strong>.</p>
<h2>Elegir rol de demostración</h2>${roles}
<a class="open" href="${link}">Abrir mesa documental</a>
<div class="notice"><strong>Alcance:</strong> la API y sus reglas de JWT/membresía son reales; D1 es SQLite desechable y R2 se simula en memoria. Los PDF quedan en cuarentena. OCR/antivirus, Queue, OAuth remoto y actas oficiales NO están activos.</div>
<p><strong>Guion sugerido:</strong> abre la mesa como autor, crea un borrador de búsqueda y envíalo. Vuelve aquí, cambia a revisor, valida la observación con una justificación y muestra el checklist y la exportación JSON verificable.</p>
<small>Cerrar el proceso elimina el estado local. No utilizar documentos ni credenciales reales.</small>
</main></body></html>`;
}

async function main() {
  const vite = await createViteServer({
    root: ROOT,
    server: { middlewareMode: true, hmr: false, host: HOST },
    appType: "spa",
    logLevel: "error"
  });
  let sqlite;
  let server;
  try {
    // Vite transforms the existing TypeScript handler; no parallel API
    // implementation or replacement of membership/permission logic is used.
    const { handleApiRequest } = await vite.ssrLoadModule("../api/src/index.ts");
    const { makeD1 } = await vite.ssrLoadModule("../../tests/helpers/d1.ts");
    sqlite = makeD1();
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(publicKey);
    publicJwk.kid = "synthetic-demo-key";
    const networkFetch = globalThis.fetch;
    globalThis.fetch = async (input) => {
      const target = input instanceof Request ? input.url : String(input);
      if (target === ISSUER + "/cdn-cgi/access/certs") {
        return Response.json({ keys: [publicJwk] }, { headers: { "Cache-Control": "no-store" } });
      }
      throw new Error("Network fetch disabled for local demo: " + new URL(target).origin);
    };
    const objects = new Map();
    const env = {
      ACCESS_TEAM_DOMAIN: ISSUER,
      ACCESS_AUD: AUDIENCE,
      COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT: "operator",
      DB: sqlite.db,
      DOCUMENTS: {
        async put(key, bytes) { objects.set(key, new Uint8Array(bytes)); return { key }; },
        async delete(key) { objects.delete(key); }
      }
    };
    async function jwt(subject) {
      return new SignJWT({ purpose: "local-demonstration-only" })
        .setProtectedHeader({ alg: "RS256", kid: publicJwk.kid })
        .setIssuer(ISSUER).setAudience(AUDIENCE).setSubject(subject)
        .setIssuedAt().setExpirationTime("15m").sign(privateKey);
    }
    async function api(subject, path, method = "GET", body, key) {
      const headers = new Headers({ "Cf-Access-Jwt-Assertion": await jwt(subject) });
      if (body !== undefined) {
        headers.set("Content-Type", body instanceof Uint8Array ? "application/pdf" : "application/json");
        if (body instanceof Uint8Array) headers.set("X-Document-Filename", "Expediente%20sintetico.pdf");
      }
      if (key) headers.set("Idempotency-Key", key);
      return handleApiRequest(new Request(ORIGIN + path, {
        method, headers, ...(body === undefined ? {} :
          { body: body instanceof Uint8Array ? body : JSON.stringify(body) })
      }), env);
    }
    async function seed(subject, path, method, data, key) {
      const response = await api(subject, path, method, data, key);
      if (!response.ok) throw new Error(`Synthetic seed ${method} ${path}: HTTP ${response.status} ${await response.text()}`);
      return response.json();
    }

    const commission = await seed("operator", "/api/commissions", "POST", {
      name: "Comisión Distrital de Ejemplo 2026",
      initialPresidentSubject: "president"
    }, "demo-commission-001");
    const prefix = `/api/commissions/${commission.id}`;
    for (const [subject, role] of [["author", "member"], ["reviewer", "member"], ["observer", "observer"]]) {
      await seed("president", prefix + "/members", "POST",
        { subject, role, expectedRevision: null }, `demo-member-${subject}-001`);
    }
    const batch = await seed("president", prefix + "/batches", "POST",
      { label: "Obras y contrataciones · Piloto sintético" }, "demo-batch-001");
    await seed("president", prefix + "/checklist/items", "POST",
      { area: "works", expectedDocument: "Expediente de contratación de obra" }, "demo-item-works-001");
    await seed("president", prefix + "/checklist/items", "POST",
      { area: "procurement", expectedDocument: "Acta de conformidad de servicio" }, "demo-item-proc-001");
    const samplePdf = new TextEncoder().encode(
      "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"
    );
    await seed("author", `${prefix}/batches/${batch.id}/documents`, "POST", samplePdf, "demo-pdf-001");
    const scope = { commissionId: commission.id, batchId: batch.id };

    const headers = {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Referrer-Policy": "no-referrer"
    };
    server = createHttpServer(async (req, res) => {
      try {
        // Prevent accidental access through wildcard hosts or DNS rebinding.
        if (req.headers.host !== HOST + ":" + PORT) {
          res.writeHead(400, headers).end("Demo only accepts the loopback host.");
          return;
        }
        const url = new URL(req.url || "/", ORIGIN);
        if (url.pathname === "/__demo" && req.method === "GET") {
          res.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" });
          res.end(renderGuide(parseRole(req.headers.cookie), scope));
          return;
        }
        if (url.pathname === "/__demo/switch" && req.method === "GET") {
          if (req.headers["sec-fetch-site"] === "cross-site") {
            res.writeHead(403, headers).end("Forbidden"); return;
          }
          const role = url.searchParams.get("as");
          if (!ROLES.includes(role)) {
            res.writeHead(400, headers).end("Unknown demo role"); return;
          }
          res.writeHead(303, {
            ...headers,
            Location: "/__demo",
            "Set-Cookie": `${COOKIE_NAME}=${role}; Path=/; HttpOnly; SameSite=Strict`
          }).end();
          return;
        }
        if (url.pathname.startsWith("/__demo/")) {
          res.writeHead(404, headers).end("Not found"); return;
        }
        if (url.pathname.startsWith("/api/") || url.pathname === "/health") {
          if (req.headers["sec-fetch-site"] === "cross-site") {
            res.writeHead(403, headers).end("Forbidden"); return;
          }
          const body = [];
          let size = 0;
          for await (const piece of req) {
            size += piece.byteLength;
            if (size > 8 * 1024 * 1024 + 4096) {
              res.writeHead(413, headers).end("Request body too large"); return;
            }
            body.push(piece);
          }
          const method = req.method ?? "GET";
          const requestHeaders = new Headers(req.headers);
          requestHeaders.delete("Cf-Access-Jwt-Assertion"); // never trust browser-supplied identity
          requestHeaders.set("Cf-Access-Jwt-Assertion", await jwt(parseRole(req.headers.cookie)));
          const request = new Request(ORIGIN + url.pathname + url.search, {
            method,
            headers: requestHeaders,
            ...(body.length ? { body: Buffer.concat(body) } : {})
          });
          const response = await handleApiRequest(request, env);
          res.writeHead(response.status, { ...headers, ...Object.fromEntries(response.headers) });
          res.end(Buffer.from(await response.arrayBuffer()));
          return;
        }
        vite.middlewares(req, res, (error) => {
          if (error) {
            console.error("Vite middleware failed", error);
            if (!res.headersSent) res.writeHead(500, headers);
            res.end("Frontend unavailable");
          } else {
            res.writeHead(404, headers).end("Not found");
          }
        });
      } catch (error) {
        console.error("Demo request failed:", error);
        if (!res.headersSent) res.writeHead(500, headers);
        res.end("Demo request failed");
      }
    });
    await new Promise((accept, reject) => {
      server.once("error", reject);
      server.listen(PORT, HOST, accept);
    });
    console.log("Folio Cívico: demo sintética en " + ORIGIN + "/__demo");
    console.log("API real + JWT RS256 + SQLite en memoria + R2 simulado; sin Cloudflare ni OCR.");
    const shutdown = async () => {
      await new Promise((resolveClose) => server.close(resolveClose));
      await vite.close();
      sqlite.close();
      globalThis.fetch = networkFetch;
    };
    process.once("SIGINT", () => { void shutdown().then(() => process.exit(0)); });
    process.once("SIGTERM", () => { void shutdown().then(() => process.exit(0)); });
  } catch (error) {
    console.error("Local demo failed to start:", error);
    if (server) server.close();
    sqlite?.close();
    await vite.close();
    process.exitCode = 1;
  }
}
await main();
