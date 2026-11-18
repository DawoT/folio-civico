# ADR-003 · Autenticación, descubrimiento y MCP sin CORS

**Estado:** implementación local validada; activación remota bloqueada.
**Fecha:** 2026-11-18

## Objetivo

Evitar que un usuario necesite conocer identificadores de otra comisión para consultar su trabajo y que los agentes MCP tengan un recorrido seguro de descubrimiento. No se cambia el criterio de autorización: **la identidad sale del JWT firmado de Cloudflare Access; la membresía activa se comprueba en D1 por operación**.

## Cambios adoptados

1. `GET /api/commissions` consulta únicamente las comisiones asignadas al `sub` firmado, con roles y estado, y límite de 50.
2. `GET /api/commissions/{commissionId}/batches` exige membresía activa en la comisión antes de devolver lotes, con límite de 100. Para una comisión inaccesible responde 404, sin revelar su existencia.
3. React obtiene listas autorizadas y usa controles `select`; no confía en los IDs del navegador como permiso. Observadores y comisiones cerradas tienen la carga deshabilitada en UI, pero la API/D1 aplican el control definitivo.
4. MCP añade `list_my_commissions` y `list_commission_batches`, conserva `get_commission_summary`. Las herramientas no exponen R2, SQL, aprobación, firma ni eliminación.
5. MCP usa el formato stateless moderno de SDK v2, deshabilita CORS y rechaza toda solicitud con cabecera `Origin`. Se documenta la exclusión deliberada de clientes MCP antiguos y de navegadores.
6. La verificación JWT comprueba firma, emisor `cloudflareaccess.com`, audiencia y expiración. Reutiliza el conjunto remoto de claves dentro de cada aislamiento de Worker; `jose` gestiona la actualización de las claves.
7. CI ejecuta pruebas normales, typecheck, build y `@cloudflare/vitest-plugin` con Workers/D1/R2 **locales**.

## Límites y riesgos residuales

- Los tests de firma usan claves efímeras y un endpoint JWKS simulado; las pruebas MCP de protocolo inyectan identidad de prueba. **No hay prueba de un flujo Access ni OAuth remoto verdadero**.
- El operador MCP no tiene Cloudflare Preview configurado. No se ha creado base, bucket, Access ni Worker remoto para este proyecto; los valores de Wrangler siguen siendo placeholders.
- Cloudflare Access/Managed OAuth, MFA, control de rutas y autorización contractual de datos reales siguen bloqueando despliegues.
- El catálogo solo consulta comisiones y lotes existentes; faltan aprovisionamiento administrativo, invitaciones y revocación probada contra Access real.
- Se limitan los listados; aún no hay paginación para volúmenes mayores.
- La caché de JWKS es por aislamiento de Worker; no persiste entre despliegues y los fallos de su obtención deniegan acceso.
- Bloquear todos los Origins imposibilita usar directamente un cliente MCP desde navegador; el diseño del piloto es **servidor a servidor**.

## Evidencia de pruebas

- JWT positivo, audiencia errónea, emisor erróneo, expiración y caché de claves.
- D1 real bajo SQLite: membresía activa, otra comisión, membresía revocada, lotes filtrados.
- API: rutas con JWT simulado, acceso cruzado denegado y métodos de mutación no disponibles.
- MCP JSON-RPC moderno: `tools/list`, `tools/call`, cuerpo/envelope/headers, rechazo cross-tenant.
- `workerd` local mediante `@cloudflare/vitest-plugin`: rechazo anónimo, R2 y D1 vinculados.

## Recursos

- https://developers.cloudflare.com/workers/testing/vitest-integration/
- https://developers.cloudflare.com/agents/model-context-protocol/apis/handler-api/
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
