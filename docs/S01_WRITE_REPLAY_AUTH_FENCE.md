# S01-02 — Revalidación de autoridad en reintentos de escritura

**Fecha:** 2026-11-20. **Estado:** `implemented_local` después de CI verde, no `verified_preview`, `security_approved` ni `released`.

## Problema reproducido

Las operaciones de membresía y provisión verificaban al actor al principio de la petición, pero podían consultar después una clave idempotente guardada, recuperar el recurso de una transacción concurrente o terminar un `D1.batch`. Si la presidencia se revocaba, degradaba o la comisión cerraba **después** de la comprobación inicial, devolvían respuestas de éxito con datos de un acto ya no autorizado para ese actor.

No es una falla en los predicados de escritura: los `INSERT/UPDATE` siguen protegidos por condiciones SQL y `D1.batch`. El defecto era **confirmar éxito o devolver registros a quien perdió autoridad antes de responder**.

## Cambios

**Membresía** (`packages/data/src/membership.ts`): se invoca nuevamente `authorize` después de recuperar una acción del diario, tras leer el registro vencedor de una colisión de idempotencia y después del retorno exitoso de `D1.batch`. El error existente de la API es **403** por pérdida de presidencia y **409** por cierre de comisión.

**Provisión** (`packages/data/src/provisioning.ts`): se centraliza `authorizeProvisioning` y se usa en el acceso inicial y en `authorizedResource` después de recuperar un lote o ítem de checklist. Aplica al replay normal, a una transacción concurrente ganadora y a una transacción recién confirmada. La API conserva los contratos: **403** sin presidencia; **409** si la comisión está cerrada.

**Bootstrap**: no se cambia su código productivo. `handleBootstrapRequest` exige antes del diario que el sujeto validado por Access coincida con el vínculo de operador no vacío y explícito del Worker; esa autoridad no es una membresía mutable en D1. Una prueba adicional verifica que, tras cerrar la comisión, **solo el operador configurado** puede consultar el recibo idempotente previo; los demás reciben **403**. El recibo histórico no da permiso de escritura sobre la comisión cerrada. Alterar esa semántica exigiría una decisión explícita de producto/seguridad, no un cambio incidental.

## TDD y pruebas de carrera

El helper **solo de tests** `tests/helpers/d1-write-replay-race.ts` obtiene filas reales de SQLite y realiza cambios de autoridad exactamente después del `first()` objetivo o después del resultado del `batch()`. No altera resultados para simular la decisión del servidor, ni introduce sleeps.

- **Red:** 11 defectos reproducidos: cinco en membresía y seis en provisión, donde se devolvía un éxito bajo autoridad perdida. Un error de tipado en el fixture bootstrap se corrigió antes de Green; no fue un defecto del código productivo.
- **Green:** revocación, degradación, cierre, colisión de clave, respuesta tras commit, preservación de diario inmutable y de auditoría; más contratos positivos.
- **API:** se prueba que una repetición de membresía revocada responde **403** y una de provisión tras cierre **409**, ambas sin duplicar mutaciones.
- El resultado de una transacción **que ya se confirmó en D1 no se revierte** por una pérdida de autoridad que ocurra después del commit. El fence impide solamente **confirmar éxito al actor**, conserva los datos/journal/audit durables. El cliente deberá reconciliar la operación cuando vuelva a disponer de autorización, sin reejecutar con otra clave para sortear el control.
- Si la última lectura D1 falla, no se devuelve un éxito: error genérico según el handler existente. Las comparaciones de idempotencia, límites y segregación de funciones no cambian.

## Alcance, coste y límites

Se añade **una lectura de autoridad D1 en la respuesta exitosa** de estas operaciones. Es independiente de la medición de laboratorio para lecturas de datos en [S01_MULTIREAD_AUTH_FENCE_AUDIT](S01_MULTIREAD_AUTH_FENCE_AUDIT.md), sin extrapolar a p95 ni facturación Cloudflare. El corte de autoridad sucede antes de componer la respuesta HTTP, pero **no es una transacción serializable a través de todo el request** y no garantiza protección contra revocación posterior al último `await`.

No hay cambios de esquema/migraciones, API pública, JSON, JWT, bindings, imagen del inspector, R2, Queue ni acceso institucional. El entorno Cloudflare Preview **no está configurado por el operador**; la validación remota de Access/MFA/D1, presupuesto y autorizaciones permanece pendiente. Integrar código en `main` no habilita despliegue.

## Reproducir

```sh
pnpm exec vitest run packages/data/src/membership.test.ts packages/data/src/provisioning.test.ts apps/api/src/member-routes.test.ts apps/api/src/provisioning-routes.test.ts apps/api/src/bootstrap-routes.test.ts
pnpm typecheck
git diff --check
sh scripts/ci.sh
```

Rollback: revertir el PR sin migraciones; preservar los registros ya confirmados en D1.
