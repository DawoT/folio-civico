# IA-001.2 — Resumen operativo verificado de comisión

**Fecha de implementación:** noviembre de 2026. **Estado:** incremento UX/frontend, aprobado solamente tras `sh scripts/ci.sh` sobre base actual de `origin/main`.

## Problema y resultado

La navegación IA-001.1 permite saltar entre tareas, pero no responde qué requiere atención inmediata. IA-001.2 agrega un resumen del **lote abierto** con contexto de comisión y enlaces de acción adecuados al rol. Evita dashboards estéticos con datos inventados.

El resumen se presenta después de la navegación y antes de documentos y administración. La navegación incluye un ancla `#resumen`; conserva los parámetros `commission` y `batch` existentes.

## Procedencia y límites de los indicadores

| Indicador | Fuente existente | Alcance exacto |
| --- | --- | --- |
| Documentos del lote | `loadDocuments(scope)` ejecutado por `App` | Lista autorizada del lote abierto |
| En cuarentena | Documentos del lote con `extractionStatus === "pending"` | Solo documentos que siguen en estado pendiente, sin implicar inspección real |
| Checklist pendiente | `loadChecklist(scope.commissionId)` ya ejecutado por `ReviewWorkspace` | Ítems cuyo `status === "pending"` en la comisión |
| Validación interna | La misma lista del checklist | Ítems con `statusSource === "validated_search"`, **no hallazgos oficiales** |
| Para tu revisión | Primera página de `loadObservationHistory` de `ReviewWorkspace` | Solo `status === "in_review"` y `canReview === true` en los **últimos 25 registros**, NO el total del historial |

**Importante:** no existe todavía un endpoint agregado ni un conteo global verificado de observaciones en el backend. Si el historial tiene más páginas, se indica expresamente. **Cero en la primera página no significa cero en el historial completo.** El panel no implementa una cola global de revisiones.

El componente se abastece del callback `onSummaryChange` del `ReviewWorkspace`; **no se ejecuta una segunda solicitud de checklist o historial para el resumen**. Tras una mutación que recarga el checklist, el resumen se actualiza junto con el flujo existente.

## Seguridad, cambios de alcance y estados de error

- Si no hay lote abierto, el resumen no se muestra.
- Una respuesta aún no recibida se representa con raya (—), **nunca como cero**.
- Si falla la carga documental, se presenta «No disponible».
- Cada snapshot contiene `commissionId:batchId`; se descartan snapshots de otro contexto. Cambiar comisión o abrir otro lote limpia/valida la procedencia del estado.
- Las acciones sugeridas dependen del rol y de `canReview` enviado por la API; el frontend **no** sustituye la comprobación de permisos del backend.
- La revisión humana mantiene doble identidad; no se renderiza el PDF original en cuarentena; la exportación JSON sigue siendo interna.
- Se evita mostrar estadísticas ficticias o porcentajes de cobertura.

## TDD y pruebas

1. **Red:** la suite de cinco contratos falló por falta de `CommissionOverview`.
2. **Green:** conteos con procedencia, límites por página, permisos, ausencia de datos, estado ajeno y acción contextual pasan.
3. **Refactor:** el primer E2E detectó una consulta ambigua en el test y una infracción axe `definition-list` en la semántica del componente. Los mensajes explicativos se incorporaron a sus `<dd>` y quedó validada la estructura.
4. **Red → Green adicional:** se exige el enlace `#resumen` en navegación, se incorpora y se comprueba.
5. **Gate de integración:** `sh scripts/ci.sh` con `FOLIO_E2E_PORT` aislado entre worktrees, sin GitHub Actions. Incluye pruebas unitarias, Python, TypeScript, build/dry-run, Workers, Chromium desktop/móvil/320, axe, migraciones D1 locales.

## Decisiones arquitectónicas

- Continúa React 19 + TypeScript + CSS custom properties, sin dependencias nuevas, router, backend ni cambios de esquema.
- `apps/web/src/layout/CommissionOverview.tsx` contiene la presentación y el cálculo puro, con pruebas directas.
- `ReviewWorkspace` publica un resumen **solo después** de la carga conjunta de checklist e historial, y lo invalida durante la actualización.
- `App` conserva su lista de documentos y su estado de carga: evita duplicar red y mezcla de lotes.
- El contexto visual usa el **lote realmente abierto**, no una selección de formulario que todavía no ha sido confirmada.

## Pendientes

- Un futuro backend agregado con autorización por comisión/usuario permitiría cifras reales para toda la bandeja, sin descargar todos los registros.
- IA-001 no sustituye la investigación con personal municipal. Antes de declararlo UX institucional listo, validar comprensión de "cuarentena", "validación interna" y "últimos 25".
- Siguiente fase del roadmap: UX-3 — flujos de evidencia y revisión en contexto, progresivamente y con el mismo gate local.
