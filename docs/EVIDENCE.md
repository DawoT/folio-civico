# Contrato de evidencias

## Tipos

- `DOCUMENT_PAGE`: identificador de versión, SHA-256 y página. El repositorio D1 exige versión y página en estado `ready`, hash coincidente, página dentro del rango y objeto fuera de cuarentena. La interfaz aún no permite crear estas citas porque no existe procesamiento seguro.
- `SEARCH_SCOPE`: ítem esperado de checklist, lote, revisor y fecha. Ya se puede guardar como borrador humano: el servidor fija revisor y hora, comprueba pertenencia del ítem/lote a la misma comisión y no modifica el checklist. **No equivale a afirmar una irregularidad.**
- `OFFICIAL_SOURCE`: especificación de fuente pública, identificador de registro y fechas de consulta/corte. **No se puede persistir todavía**: falta un almacén de capturas oficiales verificadas con fuente y versión de regla.

## Estados

`draft` es una propuesta sin validar; el autor puede enviarla a `in_review`. Otro miembro o presidente de la comisión, distinto del autor, puede registrar una decisión `validated` o `dismissed` con justificación. La decisión es **interna**, auditada e idempotente; no constituye firma ni acta oficial. Para `validated`, D1 vuelve a comprobar que las referencias de checklist y páginas no se han vuelto inválidas.

## Cuarentena documental

Una carga PDF solo prueba recepción e integridad del original. El estado de extracción permanece `pending`: no se genera evidencia por página hasta procesar e inspeccionar el archivo. Los usuarios no pueden descargar desde el bucket mediante la API inicial.

## Controles ya implementados

Las migraciones `0003_review_evidence.sql` y `0004_review_status_guard.sql` impiden referencias a otra comisión, búsqueda con ítem/lote/revisor ajenos, fuentes oficiales no verificadas y citas a páginas aún no extraídas. Las evidencias insertadas son inmutables y se crea un evento de auditoría junto con la observación en una sola transacción D1.

## Controles aún pendientes

- Verificar la huella física reabriendo el objeto R2 una vez autorizado el procesamiento (hoy solo se valida el hash registrado en D1).
- Habilitar extracción/OCR seguro y visor para comprobar folios y páginas.
- Para fuentes oficiales, conservar captura, fecha de obtención, fecha de corte y versión de regla aplicada.
- Definir política de retención y destrucción compatible con la inmutabilidad actual del registro.
- Diseñar enmiendas de propuestas y reconsideración de decisiones sin sobrescribir el historial de auditoría ya inmutable.
