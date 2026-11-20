# R2.12b/P4 · Conciliación de invalidaciones después de Queue (solo local)

**Estado:** módulo interno, pruebas sintéticas y CI local. No existe conector institucional, consumidor operacional de conciliación, monitorización activa ni Worker desplegado. Esta entrega **no** cierra la [issue #19](https://github.com/DawoT/folio-civico/issues/19) y no levanta el gate CVE/Preview.

## Problema

R2.12b/P3 consulta el ledger de invalidaciones antes de la reserva y de `Queue.send`. **Queue y D1 no comparten una transacción.** Una invalidación puede entrar **mientras el envío está en curso** o después de recibir su confirmación. El estado local `sent` indica que `send` resolvió sin excepción; **no demuestra** que el mensaje no haya sido revocado, que el consumidor lo haya detenido ni que no existan efectos posteriores.

## Cambio técnico

En `packages/data/src/manual-redrive.ts`, después de que `QUEUE.send` resuelva satisfactoriamente, el flujo asíncrono R2.11 vuelve a consultar la invalidación D1 asociada **antes de cerrar la reserva**. Si existe invalidación o la lectura D1 falla, registra `state="uncertain"` y un `audit_events` de resultado, con el mismo ID de redrive. `Queue.send` **ya pudo haber aceptado** el mensaje: por tanto no se marca `halted` ni se intenta cancelar o reenviar. La operación permanece de **un solo intento**, y el replay consulta la autorización de forma independiente. Si `send` falla, continúa el mismo tratamiento `uncertain` de R2.5. El comportamiento previo de los casos sintéticos no invalidados se conserva.

El nuevo módulo `packages/data/src/institutional-redrive-reconciliation.ts` exporta exclusivamente `listInstitutionalRedriveReconciliation(db, {limit, afterRequestId})`. Es una lectura D1 con `LEFT JOIN` del ledger append-only `processing_institutional_approval_invalidations` y el redrive `processing_manual_redrives`, con filtro por propósito `redrive`, orden por solicitud, límite **1–100** (50 por defecto) y cursor opaco validado. Solo muestra identificadores de solicitud/redrive, revisión, marca temporal, motivo tipado y estado del diario local, sin JWT, JWS, claves privadas, sujetos humanos, SHA de documentos ni ruta R2. `D1` no disponible o una página inválida provoca error; nunca devuelve una lista vacía como falsa tranquilidad.

## Interpretación operacional (sin automatismos)

| Estado del diario | Lectura posible | Acción humana pendiente |
| --- | --- | --- |
| `not_reserved` | No consta reserva de redrive vinculada | Verificar que nunca hubo envío por otra vía |
| `halted` | Reserva detenida antes de enviar | Comprobar auditoría y eventual efecto externo no correlacionado |
| `reserved` | Reserva durable sin desenlace persistido | Investigar proceso interrumpido; **no reintentar automáticamente** |
| `uncertain` | Queue pudo aceptar el envío; confirmación o vigencia dudosas | Conciliar mensaje y resultado del consumidor; no inferir entrega |
| `sent` | El adaptador recibió respuesta satisfactoria de Queue **antes de la invalidación detectada posteriormente** | Investigar procesamiento ya iniciado, efecto persistido y necesidad de respuesta institucional |

Esta lectura **no inicia acciones**, no confirma entrega, no consulta Queue, no invalida trabajo del consumidor y no expone endpoints. Un operador externo futuro requerirá autorización, políticas de acceso y un procedimiento de conciliación aprobado. Se deben correlacionar de forma segura constancias y resultados sin revelar documentación original.

## Límites y riesgos residuales

1. La invalidación puede ocurrir **después de la última consulta**, incluso después de `finalize`. Un ledger `sent` puede verse marcado con invalidación posteriormente; la lectura de conciliación muestra ese caso sin alterar el histórico. No hay linealizabilidad D1/Queue.
2. Un mensaje enviado no puede retirarse mediante esta API. Harían falta controles de consumo y respuestas institucionales firmadas, tras autorización de infraestructura y custodia.
3. Si D1 se vuelve inaccesible tras `Queue.send`, se intenta persistir `uncertain`; si falla también la escritura final, permanece la reserva `reserved` para conciliación manual. No se permite reenvío automático.
4. La clasificación de los estados está restringida a datos **sintéticos**. No existe proveedor institucional real, IdP/MFA auditado, proceso humano acreditado, permisos D1 de mínimo privilegio, monitor externo ni aprobación Preview.

## Pruebas

- TDD Red→Green: con invalidación insertada **durante** `Queue.send`, antes de P4 el resultado era `sent` (HTTP 200); P4 produce `uncertain` (HTTP 202), un solo envío y un asiento de auditoría.
- Si la lectura D1 deja de responder **después** de la confirmación de Queue, el resultado persistido también es `uncertain`, sin reenvío.
- Si una invalidación aparece después de que el redrive ya haya quedado `sent`, la consulta interna detecta y clasifica ese caso; el histórico no se reescribe.
- Keyset sobre múltiples solicitudes; rechazo de paginación inválida, fallo de D1, exclusión de tokens y datos del documento. No se añade migración SQL.

```sh
pnpm exec vitest run apps/operator/src/async-redrive.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42924 sh scripts/ci.sh
```

**Condición de cierre institucional:** completar los requisitos reales de la [issue #19](https://github.com/DawoT/folio-civico/issues/19) y el gate CVE independiente; CI sintético no sustituye la aprobación de publicación.
