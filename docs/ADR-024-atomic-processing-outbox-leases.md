# ADR-024 · Reserva atómica y reenvío recuperable del outbox D1

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementado, probado localmente; no desplegado.

## Problema demostrado por TDD

El despachador previo realizaba `SELECT` del trabajo, luego `await queue.send(...)` y **solo después** ejecutaba `UPDATE outbox SET state='sent'`. Dos ejecuciones `scheduled` concurrentes podían leer `pending` antes de que el primer envío resolviese y publicar dos mensajes idénticos. La idempotencia del Processor evitaba duplicar resultados, pero no evitaba trabajo extra ni el consumo innecesario de recursos del inspector.

Una prueba con `queue.send` retenido detectó el error en fase **Red**: mientras el primer Worker esperaba la red, D1 seguía en `pending/attempts=0`. La implementación **Green** registra una reserva en D1 antes de `queue.send`.

## Decisión técnica: claim D1 con compare-and-swap

El despachador sigue seleccionando **máximo 10 candidatos** por llamada, pero para cada uno:

1. Ejecuta una **única sentencia SQL UPDATE condicional y atómica** que compara `document_version_id`, `state`, `attempts`, `last_sent_at` y comprueba de nuevo que la versión documental esté `pending` y su comisión `active`.
2. Solo el proceso que obtiene `meta.changes===1` reserva el trabajo: escribe `sent`, incrementa `attempts` y establece `last_sent_at` al reloj de ese despachador **antes** de llamar a Queue. Los procesos que pierden la carrera no llaman a Queue. Errores anómalos del claim se propagan, sin presentar éxito ficticio.
3. Si `queue.send` confirma la entrega, el trabajo conserva la reserva; **no se ejecuta un segundo UPDATE**.
4. Si `queue.send` rechaza, se revierte condicionalmente a su estado, contador y fecha previos **solo si la versión continúa pendiente y la reserva todavía pertenece al mismo intento**. Si otro proceso concluyó/rechazó el expediente o D1 falla, no se reabre un trabajo completado ni se sobrescribe la nueva reserva.
5. Si el Worker termina/crashea **entre reservar y enviar**, el trabajo queda en `sent` provisional y su lease de **15 minutos** habilita el siguiente intento. El límite de **10 intentos** evita reenvíos indefinidos y el diagnóstico de backlog registra agotamiento.

No se añade una tabla de locks, infraestructura, migración ni transacción de larga duración: D1 y Queue son servicios distintos y no existe una transacción distribuida entre ambos. El diseño sigue proporcionando **at-least-once**, no exactly-once: la entrega puede duplicarse por cortes ambiguos de red, un Worker cuya operación se prolongue más que el lease o la propia Queue. La admisión firmada e idempotente de texto continúa siendo obligatoria.

## Condiciones de rechazo y observabilidad

- Se descartan de la selección filas `pending` que no tengan `attempts=0,last_sent_at=NULL` y filas `sent` con `attempts<1`, por considerarse inconsistentes. El diagnóstico de backlog las reporta sin mutar.
- Si una comisión se cierra o la versión deja de estar pendiente antes del claim, no se encola. El consumidor vuelve a verificar estas condiciones cuando recibe el mensaje.
- No se registran ni transmiten nombre de archivo, ruta R2, identidad, PDF ni contenido OCR en los mensajes. La señal agregada `{selected,sent,failed}` mantiene su contrato.
- Una excepción del API de D1 al reservar falla de manera explícita; no llama a Queue. Si falla D1 después de un rechazo de Queue, queda la reserva temporal para recuperación posterior.

## Verificación reproducible

```sh
pnpm exec vitest run packages/data/src/processing-outbox.test.ts
pnpm exec vitest run apps/api/src/processing-pipeline.e2e.test.ts
sh scripts/ci.sh
```

Casos nuevos: dos despachadores solapados con `Queue.send` pendiente, reversión y recuperación inmediata tras 503 de Queue, lease de un proceso caído sin `send`, cierre/rechazo concurrente sin reabrir el estado y descarte de filas inconsistentes. Las pruebas del E2E R2.1 siguen verificando inspección sintética, pérdidas, reentregas, límites y HMAC.

## Límites operativos

La prueba de concurrencia ejecuta operaciones asincrónicas y el wrapper D1 SQLite en memoria; **no certifica concurrencia distribuida entre distintas réplicas de Cloudflare Workers**. Antes de activar Preview es necesario probar cron superpuesto, reinicio y duración del lease con D1/Queues reales, tasas de fallos y una DLQ configurada; además deben aprobarse las auditorías de seguridad del inspector. La fusión en `main` no habilita recursos ni implica autorización de despliegue.

**Rollback:** revertir el commit de código restablecería el contrato anterior sin necesidad de revertir migraciones; operativamente no recomendado porque reintroduciría la carrera documentada.
