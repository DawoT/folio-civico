# S01-02 — Commit D1 ambiguo y conservación de objetos R2

**Corte:** 2026-11-20. **Estado:** `implemented_local` solo tras superar CI. No autoriza Cloudflare Preview, R2 institucional ni activación del inspector.

## Defecto reproducido

Un `D1.batch` puede confirmar la transacción y perder su acuse de recibo antes de que el Worker obtenga el resultado. La ruta de carga PDF capturaba cualquier error del batch como si demostrara rollback, recuperaba una posible clave idempotente y **eliminaba el objeto R2 recién subido en todos los casos**, incluso cuando la fila confirmada en `document_versions.r2_object_key` lo referenciaba. Si la recuperación D1 fallaba o la membresía se revocaba después del commit, el objeto también se eliminaba sin una prueba de que la transacción había fallado.

Es distinto del fence **posterior a un commit reconocido** documentado en `S01_POSTCOMMIT_RESPONSE_FENCES.md`: aquí el resultado del `await db.batch()` es ambiguo.

## Corrección de compensación segura

`apps/api/src/document-routes.ts` mantiene la admisión R2 y la transacción D1 originales. Solo ajusta el tratamiento del error de `persistDocumentUpload`:

| Evidencia obtenida | Acción y respuesta |
| --- | --- |
| La clave idempotente apunta al **mismo** `documentId` y `versionId` generados para esta solicitud | **No borrar R2**; ejecutar el fence de autorización final y devolver el 201 original con `repeated:false`. Sin segundo `put`, documento, outbox ni auditoría |
| La clave está confirmada por un **documento distinto** | Es una carga competidora ganadora de la clave única. Borrar únicamente el **objeto R2 perdedor** recién creado; revalidar permisos y devolver 200 de replay o 409 de conflicto según el hash y lote |
| D1 devuelve una identidad propia con versión incoherente | **503**, conservar R2 y no confirmar un registro inconsistente |
| No se puede consultar D1 o no existe una fila accesible para la clave | **503**, conservar el objeto en cuarentena. Una fila ausente puede significar revocación entre lecturas, no necesariamente rollback |

**Política conservadora:** una excepción genérica de D1 no acredita que la transacción hizo rollback. El sistema prioriza no crear referencias durables rotas a cambio de poder conservar **objetos huérfanos de cuarentena** cuando el batch realmente se revirtió. Esta retención no es una aprobación para eliminar automáticamente objetos: `runQuarantineAudit` existe como auditoría de solo lectura, con política y futura revisión del operador. El scheduled Worker no está habilitado. El saneamiento/retención futura requiere reconciliación probada y autorización específica.

## TDD y regresión

Tres tests nuevos ejecutan una escritura D1.batch **real** contra SQLite y luego simulan la pérdida del acuse:

1. Commit confirmado con acuse perdido y recuperación de fila propia: conservar objeto, obtener 201 y mantener exactamente una versión/documento/outbox/auditoría.
2. Commit confirmado con recuperación D1 indisponible: devolver 503 sin borrar un R2 referenciado.
3. Commit confirmado seguido por revocación: la búsqueda con membresía activa no ve la fila, pero el objeto R2 permanece y se devuelve 503 sin revelar los metadatos.

- **Red:** los tres tests fallaban porque se eliminaba R2 o se emitía un replay incorrecto.
- **Green:** las tres carreras nuevas pasan. Se actualiza un contrato antiguo que asumía, sin prueba, que todo rechazo de `D1.batch` equivale a rollback y obligaba a eliminar R2. Ahora exige retención auditable en caso de resultado desconocido.
- Se preservan los tests existentes que demuestran la eliminación exclusiva del objeto **perdedor** en una competencia real y el fence 404/403/409 tras cambios de permisos.

## Operación, riesgos y límites

- **Sin cambios de migraciones, esquema, triggers, JWT/Access, API pública, semántica de claves idempotentes, inspector ni R2 remota.**
- **Disponibilidad:** el resultado no confirmable devuelve 503, **no** 201/200 especulativo. Al recuperar permiso y conexión, repetir con la **misma `Idempotency-Key`**, comprobando si el documento durable ya existe.
- **Coste/retención:** posibles objetos huérfanos sujetos a los controles de cuarentena y auditorías; no existe borrado automático con prueba de rollback para este flujo. El coste real de almacenamiento en Cloudflare no fue medido.
- El código no puede garantizar un resultado remoto serializable ni inferir fiablemente la confirmación desde un error de transporte. La prueba utiliza SQLite D1 local y bucket R2 simulado, no accesos reales a Cloudflare.

Comprobar antes de integrar: `pnpm exec vitest run apps/api/src/document-routes.test.ts packages/data/src/documents.test.ts`, `pnpm typecheck`, `git diff --check` y **`sh scripts/ci.sh` completo con exit 0 sobre la base de `main` actual**.

**Rollback:** revertir el PR, sin migraciones. No borrar datos/documentos ya comprometidos para compensar un 503.
