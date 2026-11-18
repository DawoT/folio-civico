# Roadmap de ingeniería · Folio Cívico

Actualizado: 2026-11-18. Alcance de piloto: municipalidad distrital, obras y contrataciones, PDF nativo/escaneado.

| Fase | Resultado | Dependencias | Estado |
| --- | --- | --- | --- |
| P0 | Monorepo, TypeScript, vitest, CI y documentación | Acceso al repositorio | **En progreso** |
| P1 | D1, autorización, evidencia, auditoría y contratos | P0; matriz de roles | **Parcial: dominio, consulta, esquema** |
| P2 | Mesa React, PDF, R2 en cuarentena, checklist y borradores | P1 | Pendiente |
| P3 | Queues/Workflows, extracción, OCR por página e IA supervisada | P2; dataset anónimo | Pendiente |
| P4 | MCP OAuth y herramientas de lectura/escritura controladas | P1 y Cloudflare Access | **Parcial: servidor de lectura sin despliegue** |
| P5 | DOCX, E2E, seguridad, retención, medición del ahorro | P2–P4; aprobación legal | Pendiente |

## Método TDD

Cada incremento: (1) caso de aceptación y prueba fallida; (2) implementación mínima; (3) refactorización; (4) tests + typecheck + dry-run build; (5) registro de resultados y riesgos. Las migraciones se verifican en D1 local antes de cualquier aplicación remota.

## Entrega actual: P0/P1a

- [x] Tests que rechazan permisos entre comisiones, sujetos incorrectos e inactivos.
- [x] Dos clases de evidencia documental diferenciadas: página existente y alcance de búsqueda sin resultado; soporte para fuente oficial.
- [x] Borrador de observación sin autovalidación ni evidencia cruzada.
- [x] Repositorio D1 de resumen con condición de comisión y sujeto.
- [x] Verificación JWT de Cloudflare Access con firma, audiencia y emisor.
- [x] API protegida y MCP con una herramienta de solo lectura.
- [x] Migración inicial en D1 local.
- [x] Compilación de ambos Workers sin despliegue.
- [ ] Validar protocolo MCP end-to-end con OAuth real en preview protegido.
- [ ] Probar D1/R2 con recursos de preview exclusivos.
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
