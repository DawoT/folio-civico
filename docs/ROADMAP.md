# Roadmap de ingeniería · Folio Cívico

Actualizado: 2026-11-18. Alcance de piloto: municipalidad distrital, obras y contrataciones, PDF nativo/escaneado.

| Fase | Resultado | Dependencias | Estado |
| --- | --- | --- | --- |
| P0 | Monorepo, TypeScript, vitest, CI y documentación | Acceso al repositorio | **Completado como fundación** |
| P1 | D1, autorización, evidencia, auditoría y contratos | P0; matriz de roles | **Parcial: evidencia persistente, auditoría, permisos y comprobaciones de procedencia SQL; validación pendiente** |
| P2 | Mesa React, PDF, R2 en cuarentena, checklist y borradores | P1 | **Parcial: mesa, carga, checklist de consulta y borradores humanos; visor y transición de estados pendientes** |
| P3 | Queues/Workflows, extracción, OCR por página e IA supervisada | P2; dataset anónimo | Pendiente |
| P4 | MCP OAuth y herramientas de lectura/escritura controladas | P1 y Cloudflare Access | **Parcial: servidor de lectura sin despliegue** |
| P5 | DOCX, E2E, seguridad, retención, medición del ahorro | P2–P4; aprobación legal | Pendiente |

## Método TDD

Cada incremento: (1) caso de aceptación y prueba fallida; (2) implementación mínima; (3) refactorización; (4) tests + typecheck + dry-run build; (5) registro de resultados y riesgos. Las migraciones se verifican en D1 local antes de cualquier aplicación remota.

## Entrega actual: P0/P1d + P2c + P4b

- [x] Tests que rechazan permisos entre comisiones, sujetos incorrectos e inactivos.
- [x] Dos clases de evidencia documental diferenciadas: página existente y alcance de búsqueda sin resultado; soporte para fuente oficial.
- [x] Borrador de observación sin autovalidación ni evidencia cruzada.
- [x] Repositorio D1 de resumen con condición de comisión y sujeto.
- [x] Verificación JWT de Cloudflare Access con firma, audiencia y emisor.
- [x] API protegida y MCP con una herramienta de solo lectura.
- [x] Migración inicial en D1 local.
- [x] Compilación de ambos Workers sin despliegue.
- [x] Recepción de PDF a R2 privado bajo `quarantine/`, límite 8 MiB, firma, hash y nombre saneado.
- [x] Claves de idempotencia por comisión; transacción D1 para documento/versión/auditoría y limpieza compensatoria de R2.
- [x] Listado autorizado de documentos del lote sin exponer las claves de objetos.
- [x] Mesa React inicial con consulta y carga, empaquetada como Static Assets del mismo Worker API.
- [x] Pruebas de roles, idempotencia y fallo de almacenamiento con SQLite real y R2 simulado.
- [x] Descubrimiento de comisiones y lotes filtrado por identidad y membresía activa, sin rutas de mutación.
- [x] Interfaz de selección de comisión/lote por listado autorizado; carga inhibida para rol observador/comisiones cerradas.
- [x] JWT firmado con JWKS simulado: emisor, audiencia y expiración; caché de claves por Worker.
- [x] MCP JSON-RPC moderno probado: `tools/list`, catálogo de comisiones, consulta autorizada y acceso cruzado rechazado; CORS deshabilitado y `Origin` bloqueado.
- [x] Herramientas MCP de solo lectura `list_my_commissions`, `list_commission_batches` y `get_commission_summary`.
- [x] Suite de integración con `@cloudflare/vitest-plugin` usando runtime workerd local, R2 y D1 locales.
- [x] Lectura del checklist y de observaciones vinculadas a una comisión, con estado y evidencia en JSON.
- [x] Registro humano de búsquedas no ubicadas como **borrador**, con marca temporal, sujeto firmado y alcance de búsqueda en lote.
- [x] Migraciones D1 `0003`/`0004` que rechazan referencias cruzadas, cambios a evidencias guardadas, páginas sin extraer, fuentes oficiales sin respaldo y búsquedas sobre ítems ya ubicados/observados.
- [x] Confirmación humana explícita de alcance en la pantalla React; estados del checklist siguen sin mutación automática.
- [x] MCP agrega `get_checklist_status` de solo lectura con pruebas de aislamiento.
- [ ] Validar protocolo MCP end-to-end con OAuth real en preview protegido.
- [ ] Probar D1/R2 con recursos de preview exclusivos y Access configurado (ningún recurso remoto creado todavía).
- [ ] Inspección/transformación segura de PDFs antes de habilitar visor, extracción o descargas.
- [ ] Reconciliación de objetos R2 huérfanos y política de retención/borrado.
- [x] Identificación guiada de comisiones y lotes mediante catálogo autenticado (provisionamiento administrativo de identidades y lotes todavía pendiente).
- [ ] Acordar entidad y checklist/anexo, con revisión normativa y de privacidad.
- [ ] Ensayar exportación DOCX y reapertura de referencias.

## Gates obligatorios para datos reales

1. Entidad responsable autoriza finalidad, almacenamiento, tratamiento por terceros, retención y borrado, incluida transferencia internacional si corresponde.
2. MFA y política Cloudflare Access probados, rutas no protegidas cerradas y acceso por comisión probado de extremo a extremo (web y MCP).
3. Se verifica identidad del revisor; no se permite introducir el subject de forma arbitraria.
4. 100 % de observaciones documentales exportadas tienen versión+SHA256+página localizable; ausencias tienen búsqueda+revisor+fecha.
5. La IA solo propone: un miembro de comisión confirma o descarta.
6. Documento de gestión de incidentes, backup, cierre y eliminación verificados.

## No objetivos de MVP

Chat libre, búsqueda vectorial, DOCX/XLSX como entrada, multi-comisión autoservicio, conectores automáticos a cuatro portales, reportes oficiales directos, decisiones autónomas de IA.
