# R2.11 · Redrive con aprobación asíncrona y ejecución de un solo envío

**Corte:** 2026-11-19 (America/Lima). **Estado:** capacidad probada solo con JWT/JWS sintéticos, D1 local y Queue simulada. **Sin endpoint productivo, Worker desplegable, autoridad institucional ni infraestructura Cloudflare activada.**

## Problema y decisión

R2.9 podía ejecutar un redrive en una sola petición del operador con constancias firmadas, pero no ofrecía un protocolo explícito para registrar la decisión de **otra persona** ni para separar su sesión Access de la ejecución. R2.11 establece **tres operaciones privadas independientes**, cada una con un único token Access del sujeto correspondiente:

1. **Solicitud del operador**, `POST https://operator.local/internal/operations/redrive-proposals`: presenta solo **su propio** `Cf-Access-Jwt-Assertion` y `{commissionId,reviewId,requestKey,approvalRef}`. Se comprueba identidad de operador explícitamente configurada, comisión activa, revisión institucional previamente avalada, separación respecto a los miembros y ausencia de revocación del operador. D1 crea una solicitud `pending` de **24 horas**, idempotente por operador y clave.
2. **Aprobación independiente**, `POST .../redrive-approvals`: otra persona presenta solo **su token Access**, un `X-Folio-Redrive-Approval-Jws` de una autoridad de aprobación separada y `{requestId}`. La firma RS256 vincula propósito `folio.manual-redrive.approval.v1`, `proposalId`, operador, aprobador, comisión, revisión, referencia, clave idempotente, decisión `approved`, MFA declarada reciente y `sub` del aprobador. D1 guarda el **SHA-256 del JWS**, la huella de clave y la identidad opaca del aprobador, sin JWT ni JWS. Una transacción registra la constancia y cambia `pending→approved`. Nunca se envía Queue en este paso.
3. **Ejecución por el operador**, `POST .../redrive-executions`: con **su propio JWT Access**, el **mismo JWS de aprobación** y la constancia JWS independiente del release del inspector, más `{requestId}`. R2.6 vuelve a comprobar Access y las dos firmas. Solo si el digest de aprobación coincide con el inmutable en D1, el aprobador sigue habilitado, la solicitud está vigente y el digest del inspector coincide con el runtime de confianza se delega en `executeOneShotManualRedrive` de R2.5. La reserva escribe `async_request_id` y `async_approval_sha256` y pasa por un trigger SQL que requiere aprobación correcta antes de Queue. Se vuelve a comprobar la revocación **justo antes del envío**.

**Ninguno de los tres pasos recibe un JWT Access ajeno.** El JWS de aprobación sí deberá quedar disponible para el operador mediante un sistema de incidencias autorizado e independiente; distribuir esa constancia **no** equivale a distribuir el JWT Access personal del aprobador. Esta distribución todavía no está implementada.

La antigua ruta directa `POST .../redrives` se desactiva por defecto (404). `allowLegacyDirectRedrives:true` existe **solo para tests legados**, al igual que la compatibilidad de revocaciones R2.9. El origen `operator.local` no está desplegado ni es una ruta pública.

## Persistencia e invariantes

La migración **`0024_async_manual_redrive_approvals.sql`** introduce `processing_async_redrive_requests` y `processing_async_redrive_approvals`. Las solicitudes son inmutables, salvo una transición comprobada a `approved` y el acortamiento irreversible de caducidad. Los triggers impiden actualizar identidad, comisión, caso, clave, referencia, aprobación o borrar el diario. Un `UPDATE` SQL aislado no puede simular una aprobación: requiere la constancia correspondiente.

El ledger `processing_manual_redrives` de R2.5 conserva sus garantías de unicidad por revisión y clave idempotente. La migración añade dos campos **inmutables** para vincular la reserva al `requestId` y al digest exacto del JWS. Un trigger **`BEFORE INSERT`** verifica que la propuesta esté aprobada, sin caducar, coincida con operador/comisión/revisión/clave/referencia y no tenga al aprobador revocado. La revocación de operador, imagen, referencia, constancias o claves del inspector sigue cubierta por R2.7.

La respuesta ambigua de Queue produce `uncertain` sin reintento automático. Si la revocación de la autorización ocurre después de reservar pero antes de enviar, R2.5 marca `halted` sin encolar. Un fallo durante la reserva conserva la consistencia transaccional de D1. Como no existe transacción distribuida D1–Queue, **una revocación posterior a la aceptación en Queue no puede cancelar retroactivamente el envío**.

Una propuesta queda `approved` aunque su único redrive termine `sent`, `uncertain` o `halted`; el estado de envío pertenece al ledger R2.5. No se introduce una segunda máquina de estados de mensajería.

## Pruebas y restricciones de seguridad

```sh
pnpm exec vitest run apps/operator/src/async-redrive.test.ts
pnpm exec vitest run packages/data/src/manual-redrive.test.ts
pnpm typecheck
# En worktrees concurrentes, evitar colisiones de Chromium:
FOLIO_E2E_PORT=42791 sh scripts/ci.sh
```

Los casos prueban: tres sesiones autenticadas independientes; JWS por propuesta; firma y MFA incorrectas; otra comisión o revisión no avalada; duplicados idempotentes; no sustitución del JWS aprobado; triggers SQL contra modificación directa; caducidad; colisiones de decisiones; fallo del batch de aprobación o de reserva; estado Queue `uncertain` sin reenvío; revocación de imagen o aprobador antes de reservar y del aprobador después de reservar; y preservación del outbox original de diez intentos.

**Limitaciones explícitas:** un JWS válido solo acredita lo que su autoridad firmante afirma. No demuestra revisión humana, MFA efectivamente ejecutada, CVE remediados ni exactitud de las firmas de ClamAV. El firmante y el gate real siguen pendientes de aprobación. Un administrador con acceso de escritura directa a D1 podría falsificar diarios y estados a pesar de los triggers; el aislamiento de privilegios es condición externa obligatoria.

**Bloqueo de publicación operacional:** política real Access/MFA; separación de roles y revocación de permisos; servicio independiente de incidentes que custodie el JWS; evidencias de escaneo real de imagen, SBOM y firmas; aislamiento/rotación de claves D1 y emisores; observabilidad y conciliación de `reserved/uncertain`; pruebas sobre Preview autorizado y aprobación explícita de infraestructura/costos. No se han efectuado dichas operaciones.

**R2.11 es una integración verificable de código, no una aprobación de seguridad ni un despliegue.**
