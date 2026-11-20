# R2.12b/P8 · Rechazo de inspección 422 firmado y vinculado a la petición

**Estado:** contrato de gateway/consumidor con pruebas locales sintéticas; no existe autorización para desplegar la imagen de inspector, Containers, Queue, D1 remota, secretos o Preview. El gate CVE del inspector y la puerta institucional [#19](https://github.com/DawoT/folio-civico/issues/19) siguen abiertos.

## Causa raíz (Red)

El resultado limpio viaja con un manifiesto HMAC firmado por el gateway, pero el consumidor interpretaba **cualquier HTTP 422** del binding de inspección como evidencia terminante de malware, PDF cifrado o entrada no compatible: actualizaba `document_versions` a `needs_review` y auditaba el rechazo **sin firma, versión, huella ni prueba de frescura de la respuesta**. Un 422 erróneo de transporte, interposición o emisor no autorizado podía inmovilizar un documento sano. El test Red demostró que una respuesta 422 sin cuerpo se aceptaba como `needs_review`.

## Contrato

1. El consumidor genera, justo antes del POST, un **nonce CSPRNG de 128 bits** (hexadecimal de 32 caracteres) y lo envía únicamente en `X-Folio-Inspection-Nonce`. No llega al parser/Container.
2. El gateway autentica el token de servicio, verifica método, origen, tamaño, versión y SHA-256 del original y valida sintácticamente el nonce. La discrepancia de SHA-256 del transporte genera **400**, nunca un rechazo del PDF. Un original con cabecera PDF inválida pero hash válido, o un `422` del parser aislado, produce un único veredicto firmable.
3. El gateway **no transmite claves HMAC al parser**. Firma con HMAC-SHA256 la serialización canónica JSON UTF-8, campos en el orden exacto:

```json
{"kind":"folio.inspection.unsafe.v1","documentVersionId":"version_01","sourceSha256":"<sha256-hex>","requestNonce":"<128-bit-hex>"}
```

4. Devuelve `422 application/json` con **solo** `{"verdict":{...},"signature":"<hmac-hex>"}`. Se descartan el cuerpo de error del parser y cabeceras privadas. La respuesta tiene `Cache-Control: private, no-store`.
5. El consumidor limita el tamaño del JSON, rechaza campos inesperados, verificaciones fallidas, versión/SHA/nonce ajenos, firma falsa y formatos incorrectos. **Nunca** actualiza D1 por solo ver el status HTTP. La verificación precede a las relecturas D1 de P5–P7 y al batch atómico de `needs_review`/auditoría. Un 422 no autenticado genera error/retry para Queue; la aprobación de contenido limpio mantiene su manifiesto HMAC anterior.

## Pruebas

- TDD Red: un 422 vacío se convertía en revisión terminante; Green: se rechaza sin cambios D1 y se reintenta.
- Gateway: firma verificable de 422, bind de ID, SHA y nonce; el parser no recibe el secreto ni nonce; no se devuelve contenido privado; ausencia de nonce denegada. Cabecera PDF inválida con SHA correcto obtiene veredicto firmado; desajuste SHA de transporte no genera un 422.
- Consumidor: 422 sin firma, HMAC falso, nonce de otra petición, ID y SHA distintos fallan sin producir hallazgos o auditoría. El 422 válido de gateway sigue registrando el rechazo humano sin páginas de texto.
- E2E local: el transporte altera la firma de un 422 legítimo después del gateway; Queue solicita retry y el documento queda `pending`. Un segundo veredicto auténtico produce `needs_review` una sola vez.
- Regresiones P5–P7: invalidación, revocación, cierre de comisión y carreras D1 con 422 auténtico permanecen operativas.

## Límites y contratos externos

**La firma acredita que el gateway emitió el veredicto vinculado a la petición; no acredita por sí sola el origen humano o exactitud científica del diagnóstico del motor.** Un parser aislado comprometido todavía puede emitir falsos 422 que el gateway firme. El resultado `needs_review` nunca autoriza texto como limpio; una institución deberá revisar todo rechazo. La firma no se persiste en D1: P8 garantiza verificación de admisión, no cadena de custodia ni trazabilidad institucional de veredictos. Ese diseño requiere política de retención y un sistema de evidencias autorizado.

El nonce mitiga la reutilización de un veredicto de otra solicitud, pero **no** establece identidad IdP/MFA, permisos D1 mínimos ni transacción distribuida con Queue. El gateway/inspector siguen sin desplegarse; la imagen queda bloqueada por el gate CVE independiente. No se modifica el esquema D1 ni el formato de mensajes Queue.

## Verificación local

```sh
pnpm exec vitest run apps/processor/src/consumer.test.ts apps/processor/src/manual-redrive-fence.test.ts apps/inspector-gateway/src/route.test.ts apps/inspector-gateway/src/pipeline.integration.test.ts apps/api/src/processing-pipeline.e2e.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42935 sh scripts/ci.sh
```

**Cierre:** únicamente código local, contrato y regresiones verificables; no se infiere cumplimiento institucional ni autorización Preview. [Issue institucional #19](https://github.com/DawoT/folio-civico/issues/19).
