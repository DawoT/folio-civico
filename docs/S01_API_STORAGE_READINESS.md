# S01-03 · API storage readiness privada y fail-closed

**Corte:** 2026-11-20 · **Alcance:** API Worker solamente; cambios locales sin despliegue. **NO equivale a disponibilidad del producto ni del procesamiento documental.** Relación: `docs/AGENT_TDD_SPRINT_ROADMAP.md` S01, S02, G3.

## Diagnóstico verificado en código

`GET /health` en `apps/api/src/index.ts` es un **liveness** público (200 `{"status":"ok"}`) que no verifica D1, R2, Queue, cron, Inspector, Access/MFA ni OCR. Nunca debe usarse para concluir que un expediente puede procesarse.

## Cambio mínimo

Se introduce `GET /api/internal/readiness` en el mismo API Worker, sin rutas nuevas públicas por defecto. Se atiende únicamente tras comprobar un JWT válido de Cloudflare Access, un `sub` igual a la nueva configuración **`READINESS_OPERATOR_SUBJECT`**, y el origen si existe; el parámetro no está configurado en Wrangler activo. La identidad operadora de diagnóstico **es distinta y explícita**; no se infiere de ser miembro, presidente de comisión o del encabezado no firmado de un navegador.

Una sesión no autenticada obtiene `401`; un sujeto firmado diferente o falta de operador configurado obtiene `404`, sin consultar almacenamiento; método distinto de GET da `405`, Origin cruzado `403`.

Con sujeto autorizado, ejecuta dos comprobaciones **de solo lectura** y secuenciales:

1. D1: `SELECT 1 AS heartbeat`; exige el valor numérico exacto `1`.
2. R2: `DOCUMENTS.list({prefix:"quarantine/",limit:1})`; valida la forma de respuesta sin **devolver la lista ni rutas de objetos**.

Una dependencia ausente, error o respuesta malformada produce `503` con `{"status":"unavailable","scope":"api-storage"}`, sin secretos ni detalles. Ambas disponibles producen `200` con `{"status":"ready","scope":"api-storage","documentPipeline":"not_verified"}`. Todas las respuestas de verificación llevan `Cache-Control: private, no-store, max-age=0`, `X-Content-Type-Options: nosniff` y CSP restrictiva.

El estado `ready` se aplica **solo** a la comprobación de almacenamiento API. No verifica ni representa estado de Queue, DLQ, Gateway, Container, ClamAV, OCR, cron, identidad institucional, OAuth, integridad de documentos ni datos legales. No se envían trabajos de prueba a Queue ni se leen los bytes de los PDF.

## TDD y aceptación

- **RED observado:** con el endpoint ausente, 4/5 pruebas fallaron al recibir 404 frente a 401/200/503/403 esperados; el caso de denegación por sujeto no autorizado ya pasaba.
- **GREEN:** pruebas con JWT sintéticos RS256 y JWKS local, verificando liveness existente, ausencia de token, no-operador, falta de configuración, sesión autorizada, hash de la respuesta sin metadata R2, R2 ausente/fallido, D1 fallida, Origin cruzado y no mutación. `pnpm exec vitest run apps/api/src/readiness.test.ts apps/api/src/index.test.ts`.
- **Gates obligatorios antes de integrar:** typecheck, `sh scripts/ci.sh`, PR CI GitHub en SHA actualizado. No desplegar ni configurar `READINESS_OPERATOR_SUBJECT` sin consentimiento y revisión de amenazas; sin `READINESS_OPERATOR_SUBJECT`, el endpoint permanece denegado aunque otras variables Access estén configuradas.
- **E2E remoto por ejecutar (solo con aprobación de Preview):** host protegido, operador real con JWT Access/MFA, usuario externo 404, D1 suspendida 503, R2 suspendida 503, cabeceras CSP, no información de buckets/listados en logs, no lectura de originales.

## Rollback

Revertir el commit/PR; no existen migraciones, objetos ni cambios de datos, credenciales, Queue o Container. La configuración Wrangler activa permanece deshabilitada. En caso de incidencia, no utilizar `/health` como señal para desbloquear procesamiento de documentos.
