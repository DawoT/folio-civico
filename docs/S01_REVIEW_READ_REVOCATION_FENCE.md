# S01-02 — Fence de membresía en lecturas de revisión

**Fecha:** 2026-11-20. **Estado:** `implemented_local` al integrar con CI verde; nunca `verified_preview` ni `released`.
**Alcance:** dos consultas del flujo de revisión que leen una fila D1 y, posteriormente, sus referencias de evidencia en una segunda operación asíncrona.

## Carrera y contrato

1. `getObservationForMember` primero lee una decisión accesible al sujeto, luego sus referencias. Si la membresía se revoca **después de la primera consulta** y antes de terminar la segunda, previamente podía producir HTTP 200 con una observación que el usuario ya no puede consultar. El nuevo fence realiza una **última consulta de membresía activa** después de leer la evidencia y antes de construir la respuesta. Cuando hay revocación, `GET /api/commissions/{commissionId}/observations/{id}` responde 404 genérico, sin datos, con `Cache-Control: no-store`.
2. `findIdempotentDraft` reconstruye un borrador previo para reintentos. Antes podía devolver HTTP 200 aunque el autor perdiera acceso, se degradara a observador o la comisión cerrara mientras se leían las evidencias. El fence final exige **miembro activo con capacidad de escribir y comisión activa**; de lo contrario el replay no es válido y el handler existente retorna 403. Las garantías de unicidad de `Idempotency-Key`, los triggers y las escrituras D1 no cambian.

El helper de test `tests/helpers/d1-revocation-race.ts` devuelve las filas reales de SQLite antes de intercalar una revocación, cambio de rol o cierre. Esto reproduce el instante crítico sin hilos ni sleeps, sin datos institucionales ni deshabilitar los predicados SQL. Es explícitamente **solo de pruebas**.

## Límites y comportamiento preservado

- **Lectura histórica:** una comisión cerrada sigue siendo consultable por miembros **activos**; solo el replay de escritura queda bloqueado.
- **Error de D1:** cualquier fallo de la última comprobación impide entregar el dato; se mantiene el error genérico del endpoint, no se expone SQL ni identidad.
- **Ventana final:** el fence sucede después de todos los `await` necesarios para obtener la evidencia. No constituye una transacción serializable sobre todo el ciclo HTTP, ni sustituye el JWT/MFA de Access o los controles de la base.
- **Cobertura acotada:** se corrigen detalle individual y replay idempotente de borrador. **No se afirma** que otras rutas de lectura multiconsulta estén formalmente libres de carreras, ni que se probó Cloudflare remoto.
- **Costo:** se añade una lectura D1 de membresía por resultado exitoso; medir coste/p95 remoto antes de fijar objetivos de latencia.

## Reproducir

```sh
pnpm exec vitest run apps/api/src/observation-detail.test.ts apps/api/src/review-routes.test.ts packages/data/src/review.test.ts
pnpm typecheck
sh scripts/ci.sh
```

La fase Red dejó 3 casos reproduciendo HTTP 200 donde se requerían 404/403. La fase Green conserva los casos positivos, aislamiento entre comisiones, exactitud de evidencia y ausencia de mutaciones adicionales. CI local **no** habilita Preview ni producción. Rollback: revertir el PR, sin cambios de esquema ni migraciones.
