# R2.12b/P10 · Auditoría de inspección vinculada a la transición D1

**Estado:** corrección local del consumidor y de la admisión de texto; no modifica Queue, esquema D1, secrets ni recursos Cloudflare. [Issue institucional #19](https://github.com/DawoT/folio-civico/issues/19) y el gate CVE del inspector siguen abiertos.

## Defecto demostrado

Los flujos limpio y de rechazo firmado `422` ya usan batches D1, pero ambos separaban una transición de estado (`UPDATE extraction_status`) y el registro de `audit_events` (`INSERT … SELECT … WHERE status='ready'|'needs_review'`). Dos consumidores pueden superar la comprobación previa mientras la versión sigue `pending`. Si el primero confirma y el segundo ejecuta su batch después, el `UPDATE` del segundo afecta **cero filas**, pero su `INSERT` veía el estado final escrito por el primero y añadía otro evento. El resultado era una **doble auditoría para una sola transición real**, incluso cuando el consumidor perdedor devolvía `stale` o `repeated`.

TDD Red: **2 pruebas adversariales fallaban** con recuento de auditorías `2` frente a `1`; una para un manifiesto limpio y otra para un rechazo `422` HMAC. Una tercera prueba de conflicto entre manifiestos distintos comprueba que el perdedor tampoco inserta auditoría al lanzar un error por distinta inspección.

## Corrección mínima

Los dos `INSERT INTO audit_events … SELECT …` incorporan `AND changes()=1`. En SQLite `changes()` devuelve el número de filas afectadas por la sentencia DML **inmediatamente anterior en la misma conexión**. `D1.batch` ejecuta estas sentencias en orden y dentro de la misma transacción. Así, el evento se inserta únicamente cuando el `UPDATE` del mismo batch efectivamente promovió la versión a `ready` o `needs_review`.

- Un ganador produce **una** transición y **un** evento.
- Un competidor tardío ejecuta `UPDATE` de 0 filas y no añade evento; conserva la semántica existente: `repeated` para un manifiesto idéntico, `stale` para un 422 ya resuelto o error para un manifiesto contradictorio.
- El manifiesto firmado, el nonce P8, las barreras institucionales P5–P7 y el control de comisión P7 no cambian.
- No se modifica la tabla de auditoría ni se introduce una nueva migración. No hay cambios en la API pública.

Las pruebas intercalan **una segunda ejecución real del consumidor o publicador**, no un contador artificial, exactamente entre la comprobación de estado y el `D1.batch` del primer intento.

## Límites

Esta capa evita eventos duplicados generados por estas dos rutas, pero **no elimina registros duplicados históricos** ni sustituye restricciones y permisos del plano de administración D1. Se apoya en la semántica de `changes()` de SQLite dentro de `D1.batch` y en una serialización transaccional. Se requiere validación específica en el D1/Worker real previo al despliegue. No acredita cadena de custodia institucional, IdP/MFA, autoridad humana ni el gate de seguridad de la imagen del inspector.

## Gate local

```sh
pnpm exec vitest run packages/data/src/inspected-text.test.ts apps/processor/src/consumer.test.ts apps/processor/src/manual-redrive-fence.test.ts apps/api/src/processing-pipeline.e2e.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42938 sh scripts/ci.sh
```

La activación institucional y el gate CVE/Preview permanecen bloqueados.
