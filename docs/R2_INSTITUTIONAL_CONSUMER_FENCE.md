# R2.12b/P5 · Barrera de invalidación en el consumidor documental (local)

**Estado:** código de Processor, esquema D1 y pruebas locales **sintéticas**. **No** se ha autorizado, configurado ni desplegado una Queue, un Worker operador, un servicio institucional o un inspector real. La [issue #19](https://github.com/DawoT/folio-civico/issues/19) y el gate CVE/Preview siguen abiertos.

## Riesgo mitigado

Hasta P4, el operador podía detectar que una invalidación había llegado durante o después de `Queue.send` y registrar `uncertain`; pero **el consumidor no sabía si el mensaje provenía de un redrive manual**. Solo veía `kind`, `versionId` y `sourceSha256`. Por tanto, un mensaje ya aceptado podía llegar al Processor tras la invalidación y continuar hacia R2, inspector y admisión D1.

P5 añade procedencia y controles negativos en el **consumidor**, no solamente en el emisor:

1. Los mensajes originales del outbox conservan exactamente sus tres campos. Los mensajes de redrive incluyen `manualRedriveId` (UUID opaco de la reserva D1 ya existente). No transportan JWT/JWS, identidades, referencias de incidente, claves R2, texto ni datos del PDF.
2. `apps/processor/src/consumer.ts` valida estrictamente el mensaje (solo tres o cuatro claves exactas, UUID canónico para redrive). `isProcessingRedriveAuthorized` lee D1 y exige coincidencia de reserva/versión/SHA, estado `reserved|sent|uncertain`, aprobación vigente cuando es asíncrona, recibo institucional cuando es obligatorio, ausencia de invalidación y de revocaciones R2.7 de operador, aprobador, referencia, attestación, imagen y claves.
3. Si una versión **ya tiene reserva manual**, un mensaje sin `manualRedriveId` o con uno diferente **no puede degradarse** a mensaje de outbox ordinario. Un mensaje ordinario sin reserva manual conserva la compatibilidad existente.
4. El consumidor consulta D1 antes de buscar el original, después de la lectura y SHA-256 del original pero **antes de entregar bytes al inspector**, y después del inspector pero **antes de persistir resultado**. Cancelación observada → `stale` y ack sin nuevo acceso R2/inspección/publicación; error de lectura D1 → excepción y política normal de retry, nunca aprobación por defecto.
5. La migración aditiva `0028_institutional_redrive_consumer_fence.sql` introduce dos triggers `BEFORE` sobre `document_processing_reports` y `document_versions.extraction_status`: si existe una invalidación institucional para la reserva manual de esa versión, aborta la inserción de informe o la transición a `ready/needs_review` con `INSTITUTIONAL_REDRIVE_INVALIDATED`. Es la barrera transaccional frente a la carrera entre la última consulta y `D1.batch`. Cuando se detecta una cancelación concurrente, el consumidor la clasifica como `stale` sin dejar páginas, reporte o estado parciales.

## Límites de seguridad

- No existe transacción distribuida entre la institución, Queue, R2, inspector y D1. Si una invalidación llega **después de confirmar el informe de inspección**, no deshace contenidos admitidos. Los controles de la institución, permisos de escritura D1 y recuperación de efectos ya ocurridos requieren un proceso autorizado.
- Si un PDF **ya fue enviado al inspector** antes de la invalidación, P5 no retira los bytes de esa sesión. La nueva comprobación evita envíos posteriores cuando detecta una cancelación tras el fetch R2.
- El ID opaco de redrive en Queue **no es un secreto ni una prueba de autorización**: siempre se contrasta con D1. Una política de orígenes de Queue, credenciales y permisos sigue siendo responsabilidad de Preview. La consulta contra el ledger de revocaciones es fail-closed frente a fallos de lectura.
- El trigger cancela cualquier escritura nueva de inspección para una versión vinculada a una reserva institucional invalidada, **también si proviene de un mensaje normal rezagado**. Es una decisión conservadora: evitar procesar una versión sobre la que ya existe una invalidación.
- El esquema es solo aditivo y se aplica únicamente en D1 local. No se permite interpretar pruebas JWT sintéticas como MFA/IdP real ni esta integración como superación del gate CVE. No se activó R2, Queue o Cloudflare remoto.

## Verificación

Se construyó primero `apps/processor/src/manual-redrive-fence.test.ts` (Red): el parser rechazaba cuatro campos, un mensaje sin tag podía procesarse y D1 admitía informes tras invalidación. Green comprueba mensajes válidos y falsificados, protección contra eliminación de tag, `halted`, revisión y aprobación, invalidación antes de R2, durante R2, durante inspección, durante `D1.batch`, rechazo de informe/estado `needs_review`, no publicación de páginas, ruta positiva con manifiesto real HMAC sintético y compatibilidad con outbox, DLQ y redrive R2.11.

```sh
pnpm exec vitest run apps/processor/src/manual-redrive-fence.test.ts apps/processor/src/consumer.test.ts apps/processor/src/dlq-triage.test.ts apps/operator/src/async-redrive.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42928 sh scripts/ci.sh
```

**Condición de cierre externo:** conector de incidencia e IdP auditado, control de facultades D1, autoridad de invalidación, consumidor y Queue autorizados, política de retención y cadena de custodia, gate CVE y aprobación expresa Preview. [Issue #19](https://github.com/DawoT/folio-civico/issues/19).
