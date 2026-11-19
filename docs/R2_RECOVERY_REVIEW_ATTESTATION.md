# R2.4 · Conformidad de dos personas para recuperación documental agotada

**Fecha:** 2026-11-19 (America/Lima). **Alcance:** registro y revisión **internos en D1 local**; sin ruta pública, sin consumidor DLQ, sin Queue ni Cloudflare remoto.

## Objetivo y autoridad

El triaje R2.3 puede detectar `manual_review_exhausted` cuando el documento sigue pendiente, pero se agotaron las 10 reservas D1. Antes de considerar cualquier acción operativa debe existir un expediente interno que permita **responsabilizar a dos personas diferentes** y conservar una referencia de incidente.

R2.4 implementa la **conformidad de revisión** en `packages/data/src/recovery-review.ts`, no una autorización de despliegue o *redrive*.

- Un **presidente activo** de la comisión solicita revisión de un documento cuyo outbox esté `sent`, tenga exactamente **10 intentos**, permanezca en `pending`, coincida con el SHA-256 registrado y no tenga informe de inspección.
- Un miembro o presidente **activo y distinto del solicitante** puede `endorse` (estado `endorsed_for_operator_review`) o `dismiss` (estado `dismissed`).
- Si cambió la membresía del revisor **o la del presidente solicitante**, se cerró la comisión, el expediente se rechazó, se publicó un informe o ya no corresponde al estado agotado, la conformidad queda bloqueada. **Rechazar** un caso puede cerrar un expediente de revisión obsoleto, pero no altera el estado documental original.
- La conformidad **solo habilita que el operador externo evalúe el incidente**. Ni la conformidad ni el diario crean una Queue, reducen los intentos, autorizan un reenvío, descargan archivos, hacen `ack` en la DLQ ni promueven un PDF a `ready`.

Las funciones de datos **reciben los sujetos de los participantes** y comprueban los roles/membresías en D1, pero **no verifican JWT por sí mismas**. Están deliberadamente desconectadas de las rutas de API/MCP y de los Workers activos. Una integración futura debe suministrar sujetos verificados por Access, validar al operador independiente y pasar nuevamente un review de amenazas antes de usarlas sobre D1 remota.

## Persistencia y seguridad

Migración **`0018_recovery_review_attestations.sql`**:

- `processing_recovery_reviews`: un caso por versión documental, vinculada a comisión, SHA-256 esperado y referencia de ticket opaca (8–64 caracteres seguros); estado `in_review`, `endorsed_for_operator_review` o `dismissed`; actor solicitante y segundo revisor.
- `processing_recovery_actions`: historial de solicitudes idempotentes con clave por comisión/actor, huella SHA-256 del contenido y estado resultante. Triggers rechazan `UPDATE` y `DELETE`, así como inserciones cuyo actor, comisión, acción o resultado no correspondan exactamente al caso.
- Triggers de `processing_recovery_reviews`: impiden inserciones sin presidencia o sin agotamiento real; la única transición es de `in_review` a un estado terminal con persona distinta y membresía vigente. Los campos identificadores son inmutables; no se pueden borrar casos.
- Cada apertura y decisión utiliza una **transacción D1 `batch` de tres operaciones**: transición CAS, diario de solicitud y `audit_events`. Si alguna no afecta exactamente una fila, la transacción falla. Las claves repetidas del mismo payload devuelven la respuesta registrada; un cambio de payload causa conflicto.
- El detalle de la justificación (24–600 caracteres) se digiere mediante SHA-256 sobre el UTF-8 de `JSON.stringify(rationale.trim())`; el texto no se persiste ni aparece en logs. El sistema de incidentes externo debe custodiar el contenido, de manera que ese resumen pueda comprobarse contra la evidencia original. No introduce datos personales en el registro del caso.

El outbox, sus diez intentos, los informes inspeccionados y los objetos R2 permanecen **sin modificar** durante ambas decisiones.

## Verificación

```sh
pnpm exec vitest run packages/data/src/recovery-review.test.ts
pnpm typecheck
sh scripts/ci.sh
```

Los casos de TDD cubren recuperación legítima, dos personas distintas, idempotencia, claves reutilizadas, errores de formato, comisiones ajenas, observadores/asesores/revocados, agotamiento insuficiente, fuente incompatible, estado rechazado, clausura de comisión, rechazo conservador, race de decisiones contradictorias, activación/desactivación de miembros y bloqueos SQL incluso ante accesos directos de D1.

## Límites y aprobación separada

El resultado `endorsed_for_operator_review` **no permite enviar un mensaje ni levantar el bloqueo del inspector**. Es un requisito documental interno para un futuro procedimiento humano, no un permiso técnico. Para recuperar realmente se requieren por separado: habilitación autorizada de Cloudflare Preview, identidad del operador con MFA, prueba de escáner/aplicabilidad de CVE y firmas, redrive individual diseñado con nuevo límite de intentos y evidencia indeleble de aprobación externa, control del lease DLQ, verificación de origen R2/sha256 y ensayo E2E en Queue física. No se ha desplegado ni creado un recurso remoto.

**Reversión:** la migración añade tablas y triggers sin alterar tablas existentes ni introducir cambios de runtime. No borrar registros auditables como parte de un rollback; cualquier reversión necesita plan de retención autorizado.
