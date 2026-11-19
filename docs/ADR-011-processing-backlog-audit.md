# ADR-011 · Diagnóstico interno del procesamiento documental (sin redrive automático)

**Fecha:** 2026-11-18  
**Estado:** implementado y probado localmente; **sin cron, Queue ni Cloudflare Preview habilitados**.

## Problema

La entrega en Cloudflare Queues es **al menos una vez**, no exactamente una vez. La publicación del outbox solo se confirma después de enviar el mensaje y puede repetirse tras 15 minutos. Como máximo se registran 10 envíos del outbox; al agotarlos, el Worker deja de reenviar sin realizar una reparación automática. Un resultado explícito de inspección `422` lleva la versión a `needs_review`, pero el estado histórico del outbox puede permanecer en `sent` (representa la entrega, no una aprobación documental).

Sin una vista operativa, esos casos quedarían ocultos o podrían interpretarse equivocadamente como trabajo completado. La creación de un endpoint de administración público o una recuperación automática de documentos privados aumentaría el riesgo.

## Decisión

Implementar `auditProcessingBacklog(db, options)` en `packages/data`, una función **estrictamente de lectura** con selección máxima de 1 000 filas (configurable de 1 a 2 000) y una comprobación agregada de versiones pendientes sin registro en el outbox.

El informe devuelve **solo cantidades y señales agregadas**, nunca IDs de documento/versión, claves de R2, SHA-256, usuarios, nombres de archivos, contenido PDF ni texto extraído. Las categorías son excluyentes sobre las filas inspeccionadas:

| Campo | Condición |
| --- | --- |
| `pendingFresh` | Trabajo activo `pending` sin envío, menos de 30 min de antigüedad |
| `pendingOverdue` | Trabajo activo `pending` sin envío y antigüedad ≥30 min |
| `inFlight` | Trabajo activo `sent` con último envío hace menos de 15 min |
| `retryDue` | Trabajo activo `sent`, último envío ≥15 min y aún con reintentos disponibles |
| `exhausted` | Trabajo activo pendiente, con 10 intentos de despacho |
| `rejected` | Versión `needs_review` o `failed`; **no** representa documento aprobado |
| `paused` | Comisión cerrada con versión documental `pending` |
| `completed` | Versión `ready`, informe persistido y outbox `completed` |
| `inconsistent` | Estado/contador/fecha/procedencia incompatible, incluido dato temporal corrupto o futuro |
| `untrackedPending` | Conteo separado de versiones pendientes de comisiones activas sin fila de outbox |

La salida incluye `scanned`, `complete` y `needsAttention`. Si hay más de `maxRows` registros, `complete=false`; los conteos por estado son **parciales** y nunca deben interpretarse como totales del sistema. `untrackedPending` procede de una consulta agregada aparte. El informe es una fotografía de consultas D1, **no una transacción de snapshot atómico**, y puede reflejar estados de segundos diferentes si existe procesamiento concurrente.

Los umbrales de 15 y 30 minutos son valores **operativos iniciales**, no tiempos legales de respuesta ni métricas contractuales. Las fechas SQLite UTC y las ISO-8601 se validan; fechas inválidas o posteriores al reloj local generan `inconsistent`, sin clasificarse como «en proceso» legítimo.

La migración local `0013_processing_audit_index.sql` añade un índice sobre fecha e identificador del outbox para consultas cronológicas. No cambia registros ni estados existentes.

## Ejecución y garantías

`runProcessingAudit` en `apps/api/src/maintenance.ts` publica exactamente el objeto de métricas con `kind:"folio.processing.audit"`. El manejador `scheduled` del API registra ese resumen junto al diagnóstico no destructivo R2–D1. **Ningún cron está definido** en la configuración activa, por lo que no se ejecutan auditorías periódicas remotas.

El proceso es solo lectura: no envía mensajes, no modifica D1, no borra documentos, no modifica estados, no altera la DLQ y no ofrece un endpoint HTTP o MCP. El despacho existente `dispatchProcessingOutbox` continúa siendo una acción **separada** y opcional, solo si un operador configura expresamente un Queue binding.

## Política de intervención futura

Una alerta de `exhausted`, `retryDue`, `inconsistent` o `untrackedPending` exige **evaluación del operador** antes de cualquier redrive; no autoriza automáticamente reenviar documentos ni manipular datos de auditoría. Antes de corregir, se debe identificar la causa raíz del fallo, revisar la DLQ, la disponibilidad del inspector, la firma, la comisión y los límites de reintentos, y conservar evidencia sin exponer originales a terceros. Se necesita runbook de retención, incidentes, control de acceso y aprobación administrativa para cambios remotos.

Un `422` puede implicar malware, contenido cifrado, adjuntos, PDF inválido o insuficiencia del OCR; `needs_review` requiere clasificación humana. Nunca convertir automáticamente `needs_review` en `ready` ni repetir indefinidamente un documento rechazado.

## Pruebas

- SQLite real en memoria: categorías por estado, rechazo, agotamiento, comisión cerrada, falta de outbox, corrupción de fechas y límites `maxRows`.
- Emisión programada de métricas sin identificadores, hash ni ruta de cuarentena.
- Sin modificaciones de D1/R2 y sin acceso HTTP al auditor.
- CI: TypeScript/Vitest, Python, `workerd`, compilación `dry-run` y migración D1 local.
- **No constituye validación del escáner real ni de la recuperación DLQ remota.**

## Pendientes

1. Validar el motor ClamAV/Poppler/Tesseract con datos sintéticos en un host aislado que supere el gate de la [ADR-010](ADR-010-real-inspector-smoke-gates.md).
2. Aprovisionar Cloudflare Preview autorizado con Container, Service Binding, Queue, DLQ y cron, manteniendo separación de proyectos y límite de costos.
3. Configurar observabilidad con acceso restringido, umbrales y alertas, y ensayar un procedimiento de recuperación reversible sin borrar originales ni perder auditoría.
4. Revisar paginación y estrategia de diagnóstico a escala si el número de versiones supera de manera habitual las 2 000 filas.

**Referencias:** [ADR-008](ADR-008-isolated-inspector-queues.md) · [ADR-009](ADR-009-private-container-gateway.md) · [ADR-010](ADR-010-real-inspector-smoke-gates.md) · [Checklist Preview](PREVIEW_CHECKLIST.md).
