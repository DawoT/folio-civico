# S01-02 — Revalidación final de autoridad en transiciones de revisión humana

**Fecha:** 2026-11-20. **Estado previsto:** `implemented_local` después del CI completo; `verified_preview`, `security_approved` y `released` siguen pendientes.

## Defecto reproducido (Red)

`transitionObservation` comprueba la autoridad del actor y usa triggers D1 para validar cambios de estado de observaciones. Sin embargo, la respuesta de éxito podía quedar obsoleta después de otros `await`:
- **Primer envío, validación o descarte:** `UPDATE observations` ya ha confirmado el nuevo estado y su auditoría, pero la membresía, rol o comisión cambian antes de la respuesta.
- **Replay idempotente:** la consulta de observación y evidencias se completó con permisos válidos, pero la membresía se revoca inmediatamente después de devolver su última fila autorizada.
- **Competencia:** otra petición gana la transición; la rama de recuperación encuentra un replay válido aunque el revisor ya perdió su rol antes del reconocimiento.

Los triggers de `migrations/0006_human_review_transitions.sql` ya verifican comisión activa, evidencia, separación de autor y revisor y roles **en el instante SQL**. No se modifican. El defecto afectaba a la confirmación bajo autoridad caducada, no a la habilitación directa de una escritura sin permisos.

## Corrección

`packages/data/src/transitions.ts` introduce `assertCurrentTransitionAuthority(db,input)`, que exige:
- Membresía activa y comisión con estado `active`.
- Para `submit`: cualquier rol escritor (president, member, advisor), nunca `observer`.
- Para `validate` y `dismiss`: solo `member` o `president`.

El mismo control se ejecuta al principio de la función y **otra vez justo antes de todas las respuestas exitosas**: replay inicial, recuperación de replay concurrente y transición nueva ya persistida. Si perdió autoridad, se rechaza mediante el `ReviewAccessError` existente (la API devuelve **403 genérico**); si falla el último D1, **503 genérico**. La API conserva su validación inicial, semántica de 409 cuando detecta comisión cerrada en preflight, `Cache-Control: no-store`, idempotencia y los nombres de sus campos JSON.

## TDD y evidencia

Los tests usan el adaptador real SQLite de D1 con intercalaciones deterministas tras `first()` de membresía o `run()` de estado:
- **Red:** **8 fallos reales**, 3 tras commit de envío/validación/descarte con degradación, 3 replays tras revocación de membresía, 1 recuperación concurrente tras degradación y 1 cierre de comisión tras submit durable. Los cinco tests preexistentes del repositorio permanecieron verdes.
- **Green:** estas ocho carreras dejan de confirmar éxito. Dos contratos HTTP adicionales comprueban respuesta 403, `no-store`, falta de divulgación de decisión y auditoría sin duplicados. Un tercero inyecta caída del último D1 y verifica 503 genérico.
- `pnpm exec vitest run packages/data/src/transitions.test.ts apps/api/src/transition-routes.test.ts` → **20/20**. `pnpm typecheck` y `git diff --check` exit 0.
- **Garantía de durabilidad:** cuando D1 ya confirmó una transición, el estado y el trigger de auditoría siguen durables aunque el actor reciba 403/503. No existe rollback HTTP ni se debe emitir un segundo evento para compensar un resultado no comunicado. La reconciliación debe realizarse con la misma `Idempotency-Key` cuando se restituya la autoridad.
- No hay cambios de migraciones, triggers, contrato JSON, JWS/Access, R2, Queue, inspector, Workers remotos ni configuración.

## Alcance y riesgos

Este fence cierra una ventana después de los `await` conocidos, no constituye una transacción serializable de toda la petición ni garantiza que no ocurra una revocación **posterior** a la última lectura. Añade una consulta D1 por respuesta exitosa, sin métricas de latencia remota ni SLO. Para probar Cloudflare Access y D1 reales sigue siendo necesario Preview exclusivo configurado, identidad/MFA, presupuesto y autorización institucional. Una integración local en `main` no activa procesamiento de documentos ni el inspector.

## Reproducir

```sh
pnpm exec vitest run packages/data/src/transitions.test.ts apps/api/src/transition-routes.test.ts
pnpm typecheck
git diff --check
sh scripts/ci.sh
```

**Rollback:** revertir el PR; no hay migraciones a revertir y no se deben borrar las decisiones ni auditorías ya confirmadas.
