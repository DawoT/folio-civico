# R2.3 · Triaje de DLQ y recuperación manual controlada

**Fecha:** 2026-11-19 (America/Lima). **Estado:** código y pruebas locales; **Queue, DLQ, cron, credenciales e inspector remoto sin configurar ni desplegar**.

## Objetivo

Preparar una recuperación operativa **conservadora** para mensajes PDF que Cloudflare Queues no puede consumir normalmente. La DLQ no es un mecanismo de aprobación, no acredita limpieza antimalware y **no autoriza por sí misma a reintroducir documentos en la cola principal**.

Este incremento entrega:

- `apps/processor/src/dlq-triage.ts`, función `triageDeadLetterMessages(db,messages)` de **solo lectura**, para un máximo de 50 payloads sintéticos o autorizados por llamada. Consulta D1 y devuelve únicamente la clasificación en orden de entrada y recuentos, sin ID de expediente, hash, ruta R2, texto, nombre de archivo, sujeto Access ni carga original.
- `apps/processor/wrangler.queues.example.jsonc`, **ejemplo inactivo** de consumidor de `folio-civico-pdf-pending`: lote de cinco, tres reintentos, 60 segundos entre reintentos y DLQ `folio-civico-pdf-dead-letter`.
- Pruebas que aseguran la ausencia de mutaciones y el rechazo de una DLQ por el procesador normal; el `apps/processor/wrangler.jsonc` **activo sigue sin `queues` ni `triggers`**.
- Procedimiento de intervención y umbrales de escalado, sin CLI de redrive ni ruta administrativa de escritura.

## Distinción que evita reprocesamientos duplicados

Hay **dos contadores independientes**:

1. **Cloudflare Queue:** `max_retries=3` en el ejemplo aplica a entregas fallidas al Worker consumidor. Al alcanzarlo, Cloudflare envía el mensaje a su DLQ. Sin DLQ, el proveedor descarta el mensaje.
2. **Outbox D1:** `attempts` registra las reservas de despacho desde D1 hacia Queue, máximo **10**, con lease de **15 minutos**. Un mensaje que llegó a DLQ **puede tener aún intentos de outbox disponibles** y estar a punto de reenviarse automáticamente.

Por tanto, **la llegada a DLQ nunca debe ejecutar por sí sola un `send`, restablecer `attempts`, poner un documento en `ready`, borrar una entrada ni confirmar su consumo**.

La DLQ debe usar la misma jurisdicción que la cola origen. Cloudflare puede crear automáticamente la DLQ especificada si aún no existe; esto constituye creación de recurso y exige autorización del titular. Una DLQ sin consumidor conserva los mensajes **cuatro días**, luego los elimina. Por tanto, configurar monitoreo y un plazo interno de primera respuesta inferior a 24 horas antes de habilitarla.

Referencias del proveedor: [DLQ](https://developers.cloudflare.com/queues/configuration/dead-letter-queues/), [reintentos](https://developers.cloudflare.com/queues/configuration/batching-retries/) y [pull/ack](https://developers.cloudflare.com/queues/configuration/pull-consumers/).

## Matriz de clasificación

| Resultado del triaje | Causa probable | Acción segura |
| --- | --- | --- |
| `automatic_retry_pending` | PDF pendiente y fila outbox válida, con intentos de D1 aún disponibles | **No redrive manual**; vigilar el lease, el outbox y la disponibilidad del inspector |
| `manual_review_exhausted` | PDF pendiente, comisión activa y diez reservas D1 agotadas | Escalar a operador autorizado; analizar causa, auditoría, versión, integridad y aprobación humana antes de diseñar nuevo intento |
| `completed` | Documento `ready`, informe firmado persistido y outbox `completed` | No reprocesar; investigar por qué llegó un mensaje anterior a DLQ |
| `rejected` | `needs_review` o `failed` | **No** redrive; el rechazo antimalware/inspector requiere análisis separado |
| `paused` | Comisión cerrada o no activa | No reprocesar, no cambiar membresías ni estado institucional |
| `source_mismatch` | SHA-256 del mensaje distinto del hash D1 | Aislar incidente de integridad; no leer R2 ni publicar texto |
| `invalid_message` / `not_found` / `missing_outbox` / `inconsistent` | Mensaje malformado, versión inexistente, outbox ausente o estado incoherente | Registrar incidente agregado y revisar trazabilidad. No realizar escrituras automáticas |

La salida lista `position` y `disposition`, nunca datos del expediente. Una clasificación `manual_review_exhausted` **no equivale a autorización técnica ni legal** para reenviar.

## Procedimiento operativo (solo tras autorización de Preview)

1. **Abrir incidente.** Confirmar cuenta Cloudflare, entorno, jurisdicción, identidad operadora MFA, presupuesto, nombre exclusivo de la cola y estado de los gates CVE/firmas. Si no están aprobados, mantener el pipeline **apagado**.
2. **Contener y preservar.** Registrar en el sistema de incidentes un identificador opaco, hora UTC, responsable, ticket, motivos de fallo y contadores agregados. Evitar registrar cuerpos de Queue, texto o documentos. Confirmar el tiempo restante de retención en DLQ.
3. **Verificar D1 y Queue.** Usar `auditProcessingBacklog` para obtener contadores `exhausted`, `retryDue`, `rejected`, `inconsistent` y `complete`. Si `complete=false`, el diagnóstico está truncado; no asumir que no quedan casos.
4. **Inspección restringida.** Solo un operador expresamente autorizado puede obtener una muestra delimitada de mensajes de la DLQ mediante un mecanismo de *pull* privado. Consultar `triageDeadLetterMessages` con un D1 autorizado y esos mensajes dentro de un entorno aislado; **no existe aún una herramienta remota conectada a esta función**.
5. **Tomar decisión.** Si hay reintento automático pendiente, observar; si hay discrepancia, rechazo o comisión cerrada, bloquear. Si el outbox está agotado, el [registro de revisión R2.4](R2_RECOVERY_REVIEW_ATTESTATION.md) permite una solicitud por presidencia y conformidad de otra persona, con D1 y auditoría inmutables. Esta conformidad **no autoriza el redrive**; la decisión y las operaciones de infraestructura siguen siendo externas y requieren autorización expresa.
6. **Cambios futuros por separado.** Reprocesar, cambiar intentos/estado, crear un consumidor DLQ, confirmar o descartar mensajes, modificar políticas de retención y eliminar objetos son **operaciones fuera del alcance** de R2.3. Requieren autorización, diseño de idempotencia/auditoría y nueva validación independiente.

**Importante:** un *pull* de Cloudflare entrega una concesión temporal (*lease*) y las llamadas de `ack` o `retry` cambian su destino. No automatizar `ack` de mensajes de DLQ ni consumirlos con el Worker principal. El código del Processor rechaza explícitamente un lote cuyo nombre de cola no sea `folio-civico-pdf-pending`.

## Verificación reproducible

```sh
pnpm exec vitest run apps/processor/src/dlq-triage.test.ts
pnpm typecheck
pnpm exec wrangler deploy --dry-run --config apps/processor/wrangler.queues.example.jsonc --outdir dist/dlq-example
sh scripts/ci.sh
```

El `--dry-run` **no crea Queue, DLQ ni Worker remoto**; el ejemplo conserva el identificador D1 ficticio de todo ceros y no contiene credenciales. El CI habitual usa `apps/processor/wrangler.jsonc`, **que permanece sin bindings de Queue**. El test también valida que no hay consumidor DLQ activo y que la evaluación de mensajes no escribe en D1 ni altera auditoría.

## Límites pendientes

R2.3 **no cierra la operación real de DLQ**: siguen pendientes creación autorizada de recursos, cuenta/jurisdicción, políticas de acceso de operador, alerta y supervisión, pruebas con Queue real y recuperación tras reinicio, procedimiento aprobado de redrive manual, retención y evidencia de cierre del incidente. El inspector y sus dependencias mantienen su gate de seguridad independiente y bloqueante.
