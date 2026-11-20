# R2.12b/P9 · Contrato mínimo de tamaño PDF entre ingreso y gateway

**Estado:** corrección acotada y exclusivamente local. No habilita Inspector Containers, Queue real, D1/R2 remotos, acceso institucional ni Preview. La imagen del inspector sigue sometida a su gate CVE independiente.

## Problema reproducido

`readPdfUpload` aceptaba un cuerpo de **8–11 bytes** que comenzara con una cabecera PDF admisible (por ejemplo `%PDF-1.7`). La API lo guardaba en R2 y registraba el outbox en D1. El gateway P8, en cambio, devolvía **400 sin veredicto** al recibir cualquier cuerpo de menos de 12 bytes, incluso cuando su SHA-256 coincidía. El consumidor consideraba ese error transitorio y reintentaba la entrega de Queue sin dejar el documento en `needs_review` ni admitir una inspección legítima.

Esta incompatibilidad podía producir reintentos estériles y diagnóstico de backlog sobre un archivo manifiestamente incompleto. No se debe usar el HTTP 400 de transporte como prueba de malware ni firmar un error cuyo hash no coincida.

## Corrección

- **Ingreso:** `packages/documents/src/pdf.ts` establece el mínimo de **12 bytes** antes del SHA y de la escritura de cuarentena. Para 1–11 bytes devuelve HTTP **422** por PDF truncado; la cabecera existente sigue verificándose después. El archivo no se almacena y no genera outbox/auditoría D1.
- **Gateway P8:** verifica primero la igualdad de SHA-256 del cuerpo recibido. Ante un objeto histórico de menos de 12 bytes con SHA correcto, emite un **422 firmado** ligado a versión, SHA y nonce fresco bajo `folio.inspection.unsafe.v1`, sin invocar el parser. Si el SHA es incorrecto, mantiene **400 vacío**, nunca un hallazgo.
- **Consumidor:** el contrato P8 permanece intacto: solo el 422 auténtico y firmado puede registrar `needs_review`. No se agregan bypasses de autorizaciones P5–P7, rutas, dependencias ni migraciones.

El umbral de 12 bytes no demuestra validez PDF ni ausencia de amenazas; la validación de sintaxis y contenido continúa exclusiva del inspector. El veredicto de un documento truncado significa **requiere revisión**, no diagnóstico específico de malware.

## Evidencia TDD local

- **Red**: cinco fallos reproducidos antes de corregir código (tres tamaños de cabecera, subida API que admitía un archivo corto y gateway que respondía 400 sin firma).
- **Green**: validación de tamaños 8, 9 y 11; API sin escritura R2, D1 ni outbox ante cabecera truncada; gateway 422 con firma HMAC verificable y ningún envío al parser, más SHA de transporte alterado rechazado con 400.
- **Integración histórica**: un registro de cuarentena creado directamente en el fixture con `%PDF-1.7` de 8 bytes alcanza `needs_review` mediante el **gateway y consumidor productivos**, sin invocar el parser y sin páginas o informe falsos. Se registra un solo evento de auditoría de rechazo.

```sh
pnpm exec vitest run packages/documents/src/pdf.test.ts \
  apps/api/src/document-routes.test.ts \
  apps/inspector-gateway/src/route.test.ts \
  apps/inspector-gateway/src/pipeline.integration.test.ts \
  apps/api/src/processing-pipeline.e2e.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42937 sh scripts/ci.sh
```

**Gate ejecutado:** `FOLIO_E2E_PORT=42937 sh scripts/ci.sh` terminó **exit 0** sobre `origin/main` `b461cf9`, con 476 Vitest + 199 Python inspector + 7 contratos CI + 33 UX5 esquema/privacidad + 5 workerd + 129 Chromium = **849/849**, typecheck, builds/dry-runs y 30 migraciones D1 **solo locales** (API/MCP/Processor). No se utilizó GitHub Actions como gate ni se ejecutó el gate CVE de la imagen del inspector.

**Límites:** E2E lógico local con R2/Queue/D1 simulados; no prueba un inspector real ni su seguridad, no repara registros históricos remotos por sí mismo, no representa autorización institucional y no dispone de reconciliación externa. La [issue #19](https://github.com/DawoT/folio-civico/issues/19) y el gate CVE permanecen bloqueantes.
