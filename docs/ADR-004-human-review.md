# ADR-004 · Checklist y borradores de búsqueda con evidencia verificable

**Estado:** implementado y probado localmente; operación institucional pendiente.
**Fecha:** 2026-11-18

## Problema

La comisión necesita documentar qué requisito esperaba, qué lote revisó, quién realizó la búsqueda y qué encontró. Un PDF en cuarentena no puede justificar una observación citada por página; la ausencia de un documento tampoco acredita por sí sola una irregularidad.

## Decisión

- Los ítems del checklist se consultan por comisión y permanecen en su estado original cuando se crea un borrador. Para una búsqueda no ubicada solo se admiten ítems `pending` o `not_located`; `located` y `observed` requieren otro flujo de conciliación. La aplicación aún no modifica ni valida estados.
- El formulario **Registrar búsqueda** genera una observación `draft` con `SEARCH_SCOPE`. El revisor confirma expresamente haber realizado la búsqueda. El servidor inserta su `sub` verificado de Access y marca temporal ISO; nunca acepta estos campos del navegador.
- La API admite solamente los cuatro campos `title`, `description`, `checklistItemId` y `batchId`, con cuerpo JSON limitado a 16 KiB. Restringe escritura a presidentes, miembros y asesores de una comisión **activa**. Observadores son de solo lectura.
- D1 almacena observación, evidencias y evento de auditoría en una única transacción. Los triggers de las migraciones `0003` y `0004` garantizan pertenencia a la misma comisión, referencia a checklist/lote con estado compatible y autor identificado. Se conserva el historial de migraciones; la evidencia insertada es inmutable.
- `DOCUMENT_PAGE` solo se acepta en el dominio/repositorio si existen versión y página `ready`, coincide SHA-256 y el objeto ya no está bajo `quarantine/`. **La interfaz no lo crea todavía**: falta la inspección y extracción.
- `OFFICIAL_SOURCE` se rechaza en esta iteración. Requerirá una tabla de capturas de fuentes públicas con fecha de consulta, identidad verificable del registro y regla/fecha de corte.
- Los listados se limitan a 100 ítems del checklist y 50 observaciones, con todos sus registros de evidencia. No hay paginación aún.
- El MCP expone únicamente `get_checklist_status` para comisiones autorizadas. No habilita herramientas de escritura ni de aprobación.

## Invariantes y amenazas cubiertas

1. Otra comisión, usuario inactivo, observador o entidad cerrada no puede crear un borrador.
2. No se permiten lotes o ítems de otra comisión, ni revisor distinto del `sub` firmado.
3. Un borrador es propuesta humana, **no** una validación legal, una decisión de la Contraloría ni un cambio de estado del checklist.
4. Las evidencias guardadas no se editan ni borran mediante SQL ordinario; una política de retención futura deberá contemplar explícitamente la eliminación autorizada.
5. Ni el frontend ni el MCP entregan claves R2, PDF en cuarentena ni acceso directo a SQL.

## Validación ejecutada

- Pruebas SQLite reales de relaciones entre comisiones, triggers, inmutabilidad y referencias documentales pendientes.
- API y repositorio: permisos, tamaño y esquema del cuerpo, CSRF por Origin, secuencia de borrador/auditoría.
- Prueba extremo a extremo **local del handler API** con JWT firmado, JWKS de prueba, D1 SQLite real y evidencia persistida.
- React: clientes tipados, contenido accesible y aviso de no equivalencia con irregularidades.
- MCP: protocolo JSON-RPC, catálogo de herramientas, lectura autorizada y denegación cross-tenant.
- Compilación React, Workers en dry-run, D1 local y suite `workerd`.

## Riesgos y límites pendientes

- El formulario no implementa idempotencia de POST: reintentos ambiguos de red pueden generar borradores duplicados. Debe resolverse antes del piloto real.
- No hay flujo para aprovisionar/revisar administrativamente checklists ni emitir decisiones de validación. Las pruebas crean ítems sintéticos; la institución debe proporcionar su checklist.
- No existe inspección antimalware ni transformación segura de PDFs: el visor y la evidencia por página siguen deshabilitados.
- Falta entorno Cloudflare Preview configurado, Access/Managed OAuth/MFA reales y auditoría E2E institucional.
- La búsqueda documentada depende de la declaración humana: el producto registra el alcance pero no puede certificar automáticamente que se revisaron todas las fuentes.

## Política de cambio

Toda mutación de checklist o transición de observación requerirá una ADR posterior y pruebas específicas sobre roles, transiciones válidas, integridad, idempotencia y auditoría.
