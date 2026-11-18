# ADR-002 · Recepción PDF en cuarentena con R2 privado y D1

**Estado:** aceptada para el MVP técnico, no aprobada para expedientes reales.
**Fecha:** 2026-11-18
**Alcance:** municipalidad distrital, obras y contrataciones, carga de PDF nativo o escaneado.

## Decisión

La mesa React se distribuye como **Static Assets en el Worker API**. El navegador usa rutas `/api/*` del mismo origen; el MCP es otro Worker con su propio control de entrada. El Worker comprueba el JWT firmado de Cloudflare Access y la membresía activa antes de acceder a cualquier lote.

La recepción es `POST /api/commissions/{id}/batches/{batchId}/documents`. Por ahora se eligió un **proxy de carga a través del Worker**, con un máximo deliberado de **8 MiB** y lectura acotada de la solicitud. Es una decisión de simplicidad para el piloto: evita otorgar URL firmadas reutilizables antes de disponer del servicio de confirmación de carga. Para archivos mayores se reevaluará la carga directa y la verificación posterior, sin desactivar autorización.

### Pasos

1. Verificar comisión, lote, estado activo y permiso de escritura.
2. Comprobar mismo origen en solicitudes del navegador, nombre del PDF, `Content-Type`, longitud declarada y límite real durante streaming.
3. Validar la cabecera `%PDF-` y calcular SHA-256. **No equivale a malware scanning ni garantiza que el PDF sea legible.**
4. Consultar la clave de idempotencia por comisión. Si ya existe con el mismo hash **y lote**, devolver el documento existente; si difiere, rechazar con 409.
5. Escribir objeto en R2 privado con nombre aleatorio bajo `quarantine/`, con disposición de descarga adjunta.
6. Insertar documento, versión y evento de auditoría en una única transacción de D1. El SQL vuelve a comprobar membresía autorizada y comisión activa.
7. En fallo de D1, intentar eliminar solo el objeto nuevo. En reintento concurrente, devolver el documento previo si coincide hash, comisión y lote.

### Reglas de seguridad

- Nunca enviar al navegador claves R2, URL pública de originales ni contenido de documentos en respuesta.
- La lista de documentos requiere identidad autorizada y solo devuelve metadatos.
- El esquema mantiene una clave de idempotencia única por `(commission_id, upload_request_key)`.
- Una comisión cerrada permite lectura autorizada, pero no nuevas cargas.
- No se habilitan extracción, vista previa, anotación ni descarga de cuarentena antes de crear el paso de inspección y la política de seguridad.
- No registrar contenido PDF, nombres institucionales ni tokens en logs.
- El servicio de limpieza de objetos huérfanos y la política de retención deben implementarse y ensayarse antes del piloto con documentación real.
- Las claves de idempotencia son una garantía de duplicación lógica, **no una garantía de transacción distribuida** entre D1 y R2.

## Limitaciones que bloquean producción

- Faltan Cloudflare Access/Managed OAuth reales, MFA y pruebas E2E contra un entorno protegido.
- El bucket R2 y la base D1 configurados en Wrangler son referencias de preview aún no creadas.
- Los originales pueden contener PDF malicioso; la aceptación sintáctica es insuficiente. Se requiere inspección o una política de aislamiento y una transformación segura antes de ofrecer visor o descargas.
- No hay reconciliación ni eliminación automática de objetos huérfanos o expirados.
- Tampoco se ha validado residencia de datos, acuerdos de tratamiento ni condiciones de conservación/destrucción.

## Pruebas

Pruebas de firma/tamaño/nombre/encabezados, D1 SQLite real con dos comisiones y roles, clave repetida, escritura y rollback, R2 simulado y ausencia de claves privadas en la respuesta. Se ejecuta además `wrangler deploy --dry-run` para verificar las vinculaciones del Worker. Estas verificaciones **no sustituyen** pruebas con recursos R2/D1 remotos.

## Referencias

- https://developers.cloudflare.com/r2/api/workers/workers-api-usage/
- https://developers.cloudflare.com/d1/worker-api/d1-database/
- https://developers.cloudflare.com/workers/static-assets/binding/
