# S01-02 — Fence de acceso en listados y reintentos de documentos

**Fecha:** 2026-11-20. **Estado:** `implemented_local` cuando termine el CI; no acredita autorización de Preview, D1/R2 remotos ni seguridad del inspector.

## Carrera reproducida

La ruta `GET /api/commissions/{commissionId}/batches/{batchId}/documents` comprobaba inicialmente el permiso y realizaba después una consulta de documentos con JOIN de membresía. Si la membresía se revocaba tras retornar las filas, el handler todavía respondía **200 con los documentos**.

La misma ruta en `POST` reconocía un `Idempotency-Key` existente y devolvía datos de un registro previo aun cuando la membresía se revocara, el rol pasara a observador o la comisión cerrara mientras se leía el resultado D1. Una ruta secundaria de concurrencia podía recuperar la carga ganadora y limpiar el objeto R2 perdedor antes de responder; esa secuencia también requiere revalidación después del último `await`.

## Solución y comportamiento esperado

`apps/api/src/document-routes.ts` añade `finalAccessFence`, reutilizando `getBatchAccess` y el guard de roles `assertMemberPermission`. El fence ocurre **después** de que se hayan obtenido las filas o completado la limpieza de R2 y justo antes de construir la respuesta de éxito o conflicto. No altera predicados SQL, payloads ni escritura transaccional.

- **GET:** revocación intercalada → **404 genérico**; una comisión cerrada sigue siendo consultable por un miembro activo.
- **POST repetido:** miembro revocado → **404**; rol degradado a observador → **403**; comisión cerrada → **409**. No se confirma una carga como exitosa bajo permisos ya perdidos.
- **Conflicto concurrente R2/D1:** primero se intenta limpiar el objeto R2 perdedor, luego se verifica nuevamente el permiso antes de devolver el resultado de la carga ganadora.
- **D1 indisponible en la última comprobación:** error genérico **503**, nunca reutilizar la autorización obsoleta. Las respuestas no contienen claves R2 ni identificadores internos adicionales.

## TDD y trazabilidad

- **Red:** cuatro casos nuevos devolvían HTTP 200 donde correspondían 404/403/409.
- **Green:** pruebas dirigidas de API y repositorio D1, incluida revocación concurrente durante limpieza R2 y degradación del último acceso.
- **Sin cambios de migraciones, esquema, permisos institucionales, API pública ni inspector.** Los fixtures son sintéticos y locales.
- Reproducción: `pnpm exec vitest run apps/api/src/document-routes.test.ts packages/data/src/documents.test.ts`, `pnpm typecheck` y `sh scripts/ci.sh`.

**Límites:** la comprobación final cierra la ventana entre la consulta original y la respuesta dentro de estos handlers. No es aislamiento serializable extremo a extremo; no garantiza la ausencia de otras carreras ni reemplaza JWT Access, permisos SQL, triggers y gates de Preview. Cada respuesta relevante añade una consulta de acceso D1; medir su latencia remota antes de fijar SLO.

**Rollback:** revertir el PR. No requiere revertir migraciones.
