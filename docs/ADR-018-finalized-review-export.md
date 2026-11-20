# ADR-018 · Exportación íntegra de decisiones humanas y verificación independiente

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementado y probado localmente. Sin infraestructura remota ni cambios en el inspector.

## Objetivo y alcance funcional

Permitir que un miembro activo de una comisión conserve **un expediente JSON de sus decisiones internas** con las evidencias que sustentaron cada una. El expediente no es un acta oficial, no tiene firma institucional y no incluye los PDF originales en cuarentena.

## Contrato

- Ruta: `GET /api/commissions/{commissionId}/observations/export`; requiere JWT verificado por el Worker y membresía activa en la comisión, incluido el rol de consulta. Las comisiones cerradas siguen pudiendo consultarse por miembros activos.
- Se incluyen **todas las observaciones finalizadas** (`validated` y `dismissed`), no únicamente las 50 recientes. Se excluyen `draft` e `in_review`. Cada entrada tiene ID, autor, título, descripción, estado, fecha, segundo revisor, nota de revisión y evidencias `SEARCH_SCOPE` o `DOCUMENT_PAGE` previamente persistidas.
- La consulta está acotada a **500 decisiones finalizadas** y la carga útil a **8 MiB**. Si excede cualquiera de los límites, **se rechaza** la exportación; nunca se descarga un fichero parcial marcado como completo. La paginación/exportación por lotes con manifiesto global sigue pendiente.
- La respuesta `application/json`, `Content-Disposition: attachment`, `Cache-Control: no-store` contiene `{format,sha256,payload}`. `payload` es **una cadena JSON exacta** que incorpora `schemaVersion`, `generatedAt`, `commission`, `completeness`, `observations` y advertencia de uso interno. `sha256` se calcula sobre los bytes UTF-8 exactos de esa cadena y se replica en `X-Report-SHA256`.
- La interfaz no descarga si falla la integridad, la versión del esquema, la identidad de comisión, el estado final de los registros o el indicador de integridad completa. Tras descargar expone el digest para que pueda conservarse por un canal independiente.
- Verificación fuera de línea: `node scripts/verify-review-export.mjs archivo.json` (exit **0** cuando coincide el hash y el formato; **2** si el fichero fue alterado o no cumple el contrato). No requiere cuenta Cloudflare.

## Límites de seguridad y semántica

**SHA-256 solo verifica integridad de bytes respecto de una huella conservada independientemente. No autentica al emisor ni sustituye firma digital, sello de tiempo, acta de Contraloría o prueba de que el documento subyacente existió.** Si alguien cambia el fichero y su SHA-256, un digest por sí solo no impide ese reemplazo. El piloto necesitará una cadena de custodia institucional y firmas aprobadas antes de usos formales.

Se protegen los datos a través de la misma identidad, membresía y aislamiento multicomisión de la API actual. [F3: revalidación tras consulta](F3_EXPORT_REVOCATION_FENCE.md) impide que una revocación intercalada durante la lectura de registros todavía produzca un archivo con metadatos de comisión o revisiones. Las respuestas no se cachean y no contienen claves de idempotencia, URLs R2, tokens, archivos PDF ni fuentes oficiales no habilitadas. No se crean eventos de auditoría falsos durante lecturas.

## Calidad verificada

TDD para estados finales versus borradores, justificaciones y evidencias exactas, comisiones ajenas, miembros revocados, límites sin truncamiento silencioso, no mutación de D1, huella SHA-256, alteración de un carácter, formato inválido y validación previa a descargar. `sh scripts/ci.sh` exige TypeScript/Python/workerd, typecheck, build y D1 local antes de integrar en `main`.

## Evolución deliberadamente pendiente

DOCX/PDF legibles con plantilla institucional autorizada; exportación de más de 500 registros por lotes con manifiesto íntegro verificable; firma digital aprobada; administración de comisiones y controles de retención. La edición del checklist institucional y la inspección de originales en cuarentena permanecen independientes.
