# F2 · Historial paginado y navegación a evidencia inspeccionada

**Fecha de corte:** 2026-11-19 (America/Lima). **Alcance:** frontend React, API Worker y D1 local. No se han habilitado PDF de cuarentena ni recursos Cloudflare remotos.

## Problema funcional

El endpoint histórico `GET /api/commissions/{id}/observations` devolvía únicamente las 50 observaciones más recientes. La consulta individual por ID existía, pero el usuario no podía descubrir ni navegar registros antiguos desde la interfaz.

## Decisión

- Endpoint **aditivo** `GET /api/commissions/{id}/observations/history?limit=25&cursor=...`, sin alterar la respuesta de `/observations`. Acepta página de 1 a 50 registros (25 por defecto); rechaza parámetros inesperados, duplicados, cursores malformados y cambios de comisión.
- Paginación **keyset** por `created_at DESC,id DESC` con cursor versionado en Base64 URL-safe y enlace del identificador de comisión. Es un *marcador de posición*, **no un token de autorización ni una firma**. La API valida el JWT y revalida membresía activa en la consulta SQL.
- Una página se selecciona por **IDs de observación antes del LEFT JOIN de evidencias**; así, varias evidencias de un expediente no consumen páginas ni provocan duplicados. Se pide una observación adicional para emitir `nextCursor` únicamente si quedan registros.
- Nueva migración `0017_observation_history_keyset.sql` con índice `(commission_id,created_at DESC,id DESC)`. El test verifica con `EXPLAIN QUERY PLAN` que se utiliza el índice y que no aparece una clasificación temporal completa.
- La mesa muestra 25 registros iniciales y **Cargar observaciones anteriores**. Concatena páginas sin duplicar IDs; muestra errores recuperables, bloquea solicitudes simultáneas y descarta resultados anteriores al cambio de comisión o recarga. Un nuevo registro reciente requiere refrescar la vista, en vez de intercalarse de forma inestable durante la paginación.
- **Ver detalle** permite abrir una observación desde cualquier página y desde el checklist, con su revisión y sus referencias. Si existe evidencia `DOCUMENT_PAGE` con ID de versión, SHA-256 y página válidos, muestra **Ver página inspeccionada N**. Se reutiliza el lector de texto verificado `InspectedTextViewer`, limitado a la página indicada: comprueba versión, hash, cuenta de páginas y existencia de la página. **No** abre el PDF original ni genera una cita automáticamente.
- Los campos de observaciones son renderizados mediante texto React, no HTML interpretado; la exportación de decisiones finalizadas permanece independiente del historial y conserva su límite de 500.

## Pruebas y aceptación

TDD Red/Green y pruebas focalizadas de recorrido de 65 registros en 25/25/15, misma marca temporal, evidencias múltiples, nuevas entradas durante la navegación, rol observador, comisión cerrada, comisiones cruzadas, miembros revocados, límites/cursores malformados, no mutación de auditoría, firma de JWT Access en ruta completa, contrato del cliente, estados del botón y control de página inspeccionada. El gate de integración sigue siendo `sh scripts/ci.sh` con typecheck, build, Workers locales y migraciones locales.

## Límites conocidos

El listado es un recorrido estable de registros **anteriores al cursor**, no una instantánea transaccional congelada: cambios de estado posteriores pueden reflejarse al consultar páginas pendientes, y los nuevos registros recientes solo aparecen tras refrescar. En este dominio las observaciones son inmutables en cuanto a evidencia, pero su estado humano puede progresar. No se han implementado búsqueda textual o filtros, descarga de todo el historial superior al límite del exportador ni un visor de PDF sanitizado. El vínculo documental solo está disponible para páginas realmente inspeccionadas. El E2E con navegador e identidad Access real sigue pendiente.
