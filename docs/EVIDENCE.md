# Contrato de evidencias

## Tipos

- `DOCUMENT_PAGE`: documento, versión exacta, SHA-256 de la versión y página (folio si existe como metadato adicional). Requiere existencia real en R2/D1 antes de crear observaciones persistentes.
- `SEARCH_SCOPE`: ítem esperado de checklist, lote, revisor y fecha de consulta. No equivale a afirmar una irregularidad.
- `OFFICIAL_SOURCE`: fuente pública, identificador de registro, fecha consultada y fecha de corte. Debe conservarse fuente y versión de regla si se compara.

## Estados

`draft` es una propuesta sin validar. La transición a `validated` solo se habilitará mediante servicio y pantalla de revisión con membresía y permiso `validate`, registro de auditoría y evidencias reabiertas.

## Reglas de validación futuras

- Verificar que la versión del documento y su comisión coincidan con la evidencia.
- Comparar la huella almacenada con la carga íntegra en R2.
- Rechazar páginas fuera del rango `1..page_count`.
- Para faltantes, verificar lote/checklist dentro de la misma comisión y vinculación del revisor.
- Para fuente oficial, conservar fecha de obtención, fecha de corte y versión de la regla aplicada.
- Guardar historial inmutable de cambios de estado y autor de cada transición.
