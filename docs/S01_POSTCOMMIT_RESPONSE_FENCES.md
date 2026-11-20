# S01-02 — Fence de respuesta posterior al commit de PDF y borradores

**Corte:** 2026-11-20. **Alcance:** cierre de dos carreras en el éxito inicial de un `POST` ya confirmado por D1; exclusivamente local. No habilita procesamiento PDF/inspector, Cloudflare Preview, producción ni datos institucionales.

## Problema (TDD Red)

Los reintentos idempotentes de carga y creación de borradores ya disponían de fences, pero **el primer éxito** continuaba respondiendo HTTP 201 justo después de que `D1.batch` confirmara una escritura. Si un operador revocaba la membresía, degradaba el rol o cerraba la comisión después del commit y antes de formar la respuesta, el servidor podía confirmar una operación al actor que acababa de perder autorización.

Además, el manejo de errores de PDF distinguía fallos de almacenamiento de R2 y transacción D1. Introducir un control de autorización **dentro** del `try` original habría sido peligroso: un error del último control podría activar la limpieza del objeto R2, aunque el registro del documento ya estuviera confirmado.

## Contrato implementado

- `apps/api/src/document-routes.ts`: el `try/catch` de persistencia y limpieza R2 cubre **solo** `persistDocumentUpload`. Después del commit, se llama a `finalAccessFence(...,"draft")` fuera del bloque que elimina el objeto perdedor. Una revocación responde **404**, cierre **409**, degradación a observador **403**. Si D1 no puede verificar permisos, el handler responde **503 genérico**, nunca 201.
- `packages/data/src/review.ts`: inmediatamente después del `D1.batch` de `persistDraftObservation`, se vuelve a comprobar `getCommissionSummary` para exigir membresía activa, comisión activa y rol escritor. En otro caso `ReviewAccessError`; el handler existente devuelve **403**. D1 no disponible en ese último control devuelve **503**, sin revelar datos.
- Ambos códigos conservan la autorización inicial y las condiciones de SQL, que bloquean escrituras no autorizadas **antes y durante** la transacción. El fence final impide solo que una respuesta de éxito salga con autoridad ya caducada.
- Sin modificaciones a la API pública, JSON, idempotencia, migraciones, Triggers, JWT, R2 keys, inspector o configuración de infraestructura.

## Invariante de durabilidad y reconciliación

**La revocación posterior al commit no deshace la transacción.** Los registros de documentos, versiones, outbox y auditoría en D1 y el objeto original en cuarentena R2 siguen presentes. Los borradores, sus evidencias y audit permanecen durables. No se intenta revertir un `D1.batch` exitoso mediante compensaciones de R2. El cliente no debe asumir que un HTTP 403/404/409/503 posterior a enviar un `POST` implica que nada se escribió: cuando recupere autorización, debe consultar el estado y reutilizar la **misma clave idempotente**, no crear una nueva para evitar el control.

El último control sucede después de los `await` necesarios y antes de la respuesta, pero **no es una transacción serializable que abarque toda la petición HTTP**. Una revocación posterior a la última comprobación requeriría controles adicionales fuera de este alcance.

## Evidencia

Las pruebas integran SQLite real y R2 simulado; el wrapper D1 devuelve los resultados auténticos de `batch` y solo entonces intercala revocación, cierre o degradación, sin sleeps ni falsificar resultados.

- **Red:** 8 casos nuevos devolvían 201 erróneamente: 3 por cambio de acceso PDF, 1 por D1 postcommit PDF, 3 por cambio de acceso de borrador y 1 por D1 postcommit de borrador.
- **Green:** `pnpm exec vitest run apps/api/src/document-routes.test.ts apps/api/src/review-routes.test.ts packages/data/src/review.test.ts` → **50/50** pruebas aprobadas, `pnpm typecheck` y `git diff --check` exit 0.
- En la carga PDF, los cuatro casos negativos también validan que **R2.delete nunca se llama** después de un commit confirmado y que `documents`, `document_versions`, `document_processing_outbox` y `audit_events` tienen una fila durable.
- En los borradores, se exige una observación, referencia de evidencia y evento de auditoría durables sin respuesta exitosa a un actor sin permisos.
- Gate de integración: `sh scripts/ci.sh` completo exit 0 contra la base actual. `GitHub Actions` no autoriza despliegues ni gates de seguridad del inspector.

**Coste:** una consulta D1 adicional en cada primer POST exitoso, además de los fences anteriores. No hay métricas ni facturación de D1 remoto; su medición real queda bloqueada hasta tener operador Preview configurado, Access/MFA, recursos dedicados y autorización de coste.

**Rollback:** revertir el PR, sin migraciones. Nunca eliminar documentos ya confirmados al revertir.
