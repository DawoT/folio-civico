# ADR-005 · Idempotencia de borradores y revisión humana de dos personas

**Fecha:** 2026-11-18  
**Estado:** aceptada e implementada localmente; no habilitada para documentación institucional real.

## Problema

Una respuesta HTTP perdida podía hacer que un revisor reenviara un mismo borrador y generara duplicados. Además, un documento de constatación necesita una revisión interna explícita con trazabilidad, separación entre autor y revisor y prevención de cambios silenciosos.

## Decisión

1. El POST de borradores exige `Idempotency-Key` (8–96 caracteres seguros). La clave se acota a `commission_id + author_subject`, no se comparte entre usuarios. D1 impone índice único parcial y almacena SHA-256 de `[title.trim(), description.trim(), checklistItemId, batchId]`. Se excluyen fecha y hora emitidas por servidor.
2. Una misma clave con la misma carga devuelve la observación existente (`200`) sin generar nueva evidencia ni auditoría. El primer registro devuelve `201`. Contenido distinto con la misma clave devuelve `409`. Reintentos concurrentes resuelven la colisión por índice único D1.
3. La mesa web conserva en memoria la clave de cada intento fallido, asociada al contenido, y la reinicia después de la respuesta exitosa. No persiste credenciales ni documentos en el navegador.
4. Los estados permitidos son exclusivamente `draft → in_review → validated|dismissed`. No hay aprobación autónoma ni retorno automático a otro estado. Las ediciones se abordarán mediante un futuro flujo explícito de correcciones, sin mutar las evidencias anteriores.
5. Solo el **autor autenticado**, con rol de creación activo, puede enviar `draft → in_review`. Solo un **miembro o presidente activo distinto del autor** puede resolver `in_review → validated|dismissed`. Exige justificación humana de 15–1000 caracteres para la decisión final.
6. Cada transición se implementa mediante actualización condicionada al estado anterior. Triggers D1 vuelven a comprobar identidad, comisión activa, separación de personas, evidencia existente y, para validación, referencias aún vigentes. Otro trigger genera el evento de auditoría **en la misma transacción SQL**.
7. Las acciones requieren otra `Idempotency-Key`. Una repetición idéntica de la misma acción, revisor y justificación devuelve `200` sin una segunda auditoría. Cambios de contenido, otra clave o transición desde un estado incorrecto producen conflicto `409`.
8. El contrato de lectura de observaciones calcula capacidades `canSubmit` y `canReview` por comisión, rol, autor y estado. El frontend las utiliza para mostrar las acciones, pero la API y D1 autorizan de nuevo sin confiar en el navegador.

## Evidencia y protección

- Migración `0005_draft_idempotency.sql`: metadatos de idempotencia e índice único.
- Migración `0006_human_review_transitions.sql`: actor, marca temporal y justificación; transiciones permitidas; revalidación de evidencia; auditoría automática.
- Migración `0007_review_immutability.sql`: impide inserción inicial como validada, edición directa de firmas de revisión, cambios de payload y adición de evidencia tras el envío.
- Las migraciones son **aditivas y ordenadas**. No se reescriben migraciones ya aplicadas.
- El resultado `validated` indica aceptación **interna** de la comisión, no firma legal, reporte oficial de la Contraloría ni conclusión autónoma de IA.

## Pruebas y límites

Pruebas automatizadas de claves repetidas y concurrentes, conflicto por cambio de payload, aislamiento entre autores, roles, comisión cerrada, revisión por una segunda identidad firmada, prevención de autoaprobación, referencias vencidas, inmutabilidad SQL y ausencia de auditorías duplicadas. Las migraciones se comprueban con Wrangler **local**, sin recursos institucionales.

Pendiente antes de habilitar el piloto real: Preview aislado con D1/R2, identidad Access/MFA y OAuth MCP de verdad, pruebas E2E; inspección de PDF y visor seguro; aprovisionamiento institucional de checklist, política de privacidad, conservación, correcciones y firma del acta oficial en el canal que corresponda.

## Riesgos residuales

- Un usuario puede volver a generar una clave diferente y crear otro borrador similar. La idempotencia impide duplicados de **la misma operación reintentada**, no duplicados semánticos de casos distintos.
- Las claves temporales se conservan en memoria durante la sesión. Un navegador cerrado antes de recibir respuesta puede perder esa clave; la API seguirá deduplicando solicitudes que conozcan la clave original.
- La validación de evidencia D1 garantiza referencia y estados actuales, pero aún no verifica materialmente el contenido de PDF en cuarentena. El visor de originales continúa deshabilitado.
- La atribución a una persona depende de una sesión Access válida y de la política MFA que aún debe configurarse y probarse en Cloudflare real.

**Referencias:** [ADR-004](ADR-004-human-review.md), [evidencias](EVIDENCE.md), [roadmap](ROADMAP.md).
