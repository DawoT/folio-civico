# ADR-009 · Gateway privado Cloudflare Containers y custodia de la firma

**Fecha:** 2026-11-18  
**Estado:** gateway implementado y probado con dobles de Container/Queues; **no desplegado**. ClamAV/OCR reales ya se validaron en smoke **local independiente**, no en Cloudflare Containers (ADR-010).

## Decisión de arquitectura

Cloudflare recomienda la API de Containers en Durable Objects y ha deprecado el adaptador `@cloudflare/containers`. Se implementa `apps/inspector-gateway` usando directamente `DurableObject` de `cloudflare:workers` y `ctx.container`, sin incorporar la dependencia deprecada.

El gateway es un **Worker privado**, consumido exclusivamente por el Service Binding `INSPECTOR` del Worker `apps/processor`. Su único método aceptado es `POST /inspect`; no tiene interfaz de usuario, ruta pública, `workers.dev` ni URL de Preview.

### Cadena de confianza

1. El consumidor de Queues verifica D1, pertenencia a la comisión y SHA-256 de R2. Llama al Service Binding `INSPECTOR` con el PDF y un token de servicio de la organización, no con una URL elegida por el cliente.
2. El gateway comprueba método, ruta, token, ausencia de `Origin`, versión, SHA-256 y `Content-Type`. Lee como máximo **8 MiB**, recalcula el SHA-256 y **no reenvía encabezados arbitrarios**.
3. El Durable Object `InspectorContainer` utiliza la política `durable_object`, inicia la imagen configurada con `enableInternet:false`, espera `GET /health` y accede al puerto privado 8789 mediante `getTcpPort(8789).fetch()`. Tiene un solo nombre de instancia `folio-private-inspector-singleton`. Un documento no se envía si el contenedor no confirma que está listo.
4. El inspector Python recibe **solo** `FOLIO_INSPECTOR_SERVICE_TOKEN` y `FOLIO_INSPECTOR_OUTPUT_MODE=unsigned`; nunca se le transmite la clave HMAC del Worker. Revisa malware/estructura y extrae texto bajo los límites de ADR-008.
5. En modo `unsigned`, Python devuelve únicamente `{"manifest":{...}}`. El gateway rechaza respuestas de más de **2 MiB**, campos imprevistos, veredictos no limpios y diferencias de versión o hash. Valida todas las páginas mediante `serializeInspectionManifest` y solo entonces produce una **firma HMAC-SHA256 dentro del Worker gateway**, con `INSPECTOR_HMAC_KEY`.
6. El consumidor verifica de nuevo esa firma al invocar `publishInspectedText`, que además reabre el original privado R2, recalcula su SHA-256 y admite páginas y auditoría en una transacción D1.
7. El código mantiene `422` para rechazo documental y `503` para fallos de servicio, mientras que errores de respuesta/contrato inesperados se rechazan y nunca generan páginas `ready`.

**Esta separación protege la clave HMAC de la ejecución de analizadores PDF en un contenedor de menor confianza.** Una vulnerabilidad del parser todavía podría producir un manifiesto falso durante la propia inspección; una firma demuestra la procedencia a través del gateway, **no** que un antivirus sea infalible ni que el OCR sea correcto.

El modo `signed` de Python permanece para pruebas locales independientes y despliegues que usen otra arquitectura autorizada, pero **no** se utiliza en la integración Cloudflare Containers propuesta.

## Configuración y límites operativos

- `apps/inspector-gateway/wrangler.jsonc` es la **configuración activa inerte**: `workers_dev:false`, `preview_urls:false`, sin Durable Objects ni Containers ni rutas. El Worker responde `503` si está desprovisto del binding. `pnpm build` usa `wrangler deploy --dry-run` y no crea nada.
- `apps/inspector-gateway/wrangler.container.example.jsonc` muestra el binding `INSPECTOR_CONTAINER`, la clase `InspectorContainer`, el Dockerfile `../inspector/Dockerfile`, un contexto de build correcto y almacenamiento DO SQLite. **No es la configuración de despliegue activa.**
- El Dockerfile instala ClamAV, qpdf, Poppler y Tesseract, y **exige ejecutar `freshclam` durante la construcción**. Si fallan la descarga de firmas o el build, no debe desplegarse. Con Internet deshabilitado al ejecutar, las definiciones antivirus pueden superar el umbral de 72 horas: es obligatorio **reconstruir y sustituir la imagen antes del vencimiento**, y alertar si `/health` responde `503`.
- El Durable Object usa `standard-1`, comprueba disponibilidad antes de traficar y mantiene inactividad acotada. El coste, límites y concurrencia deben aprobarse con la cuenta real. El inspector HTTP de Python es secuencial; hay que ensayar 1 documento por vez y dimensionar/revisar reintentos antes del piloto.
- `INSPECTOR_SERVICE_TOKEN` debe existir como secreto del Processor y gateway. `INSPECTOR_HMAC_KEY` debe existir como secreto del Processor y gateway. Ambos se inyectan desde la cuenta, no se escriben en `vars`, archivos versionados ni logs. El token también se pasa al contenedor para autenticar solicitudes; la clave HMAC **no**.
- El operador debe configurar `INSPECTOR` como Service Binding desde el Processor hacia `folio-civico-inspector-gateway`, y aprovisionar Queue, DLQ y cron en cuenta exclusiva; esos elementos siguen deliberadamente ausentes de las configuraciones activas.

**Ninguna operación de despliegue, creación de recursos o instalación remota se realizó.** Cloudflare Preview del operador MCP continúa sin estar configurado.

## Pruebas y evidencias

- Pruebas de ruta del gateway: autorización, forma y límites, SHA-256, respuesta limpia, firma HMAC en Worker, contrato JSON, rechazos, falta de secretos y datos privados no reflejados.
- Integración local sintética `Queue consumer → gateway → manifiesto HMAC → persistencia D1` con objeto R2 simulado, reintento cerrado ante hash forjado y auditoría inmutable.
- Tests HTTP Python del modo `unsigned`, arranque sin clave HMAC, autenticación, disponibilidad de herramientas y caducidad de firmas; motores aún simulados.
- Pruebas de gate sobre Wrangler: configuración activa sin Containers/Queues, plantilla privada con build context existente y **ninguna clave HMAC pasada a `ctx.container.start`**.
- `pnpm check`, `pnpm test:workers` y comprobaciones de seguridad locales.

### Lo que aún no está probado

**Se construyó una imagen local con `freshclam` y se completaron 6/6 pruebas de motores reales con PDFs sintéticos (ADR-010)**. Sin embargo, no hay claves de servicio reales, instancias Cloudflare Container, Queues/Access/MFA ni pruebas E2E remotas del flujo de documentos. Un Dockerfile y una clase Durable Object **no constituyen por sí mismos** un servicio operativo. La verificación completa debe realizarse solo en Preview con recursos dedicados, autorización del operador y documentos exclusivamente ficticios.

## Referencias

[ADR-007](ADR-007-inspected-text-gate.md) · [ADR-008](ADR-008-isolated-inspector-queues.md) · [ADR-010](ADR-010-real-inspector-smoke-gates.md) · [Guía de Preview](PREVIEW_CHECKLIST.md)

Documentación oficial consultada el 18-11-2026: [Migración a Durable Object Container API](https://developers.cloudflare.com/containers/guides/migrate-to-durable-object-container-api/), [Ejemplo de instancias stateless](https://developers.cloudflare.com/containers/examples/stateless/), [Configuración Wrangler](https://developers.cloudflare.com/containers/configuration/wrangler/) y [API de Container](https://developers.cloudflare.com/containers/api/durable-object-container/).
