# R2.12b/P7 · Cierre de comisión durante inspección y admisión documental

**Estado:** corrección del consumidor y migración D1 **solo local y sintética**. La integración de autoridad institucional, CVE y Preview permanece bloqueada. No se añade Worker, endpoint, recurso Cloudflare, credencial, Queue ni autorización remota.

## Causa raíz

El consumidor comprobaba `commissions.status='active'` cuando leía el documento, pero después de operaciones asíncronas de R2 y del inspector podía estar usando una decisión obsoleta:

- Con un resultado limpio, `publishInspectedText` ya verificaba comisión activa, pero la cancelación durante la inspección se convertía en un error/retry en vez de un `stale` definitivo.
- Con resultado de inspección `422`, `recordUnsafeInspection` actualizaba `document_versions.extraction_status='needs_review'` sin comprobar el cierre. **Podía persistir un estado y una auditoría de rechazo después del cierre**.
- Incluso si la transición se bloqueaba en SQL, un `UPDATE` sin filas afectadas podía permitir que el `INSERT` de auditoría posterior se ejecutara sobre un `needs_review` ya existente.

## Corrección

1. `apps/processor/src/consumer.ts` añade `isActivePendingVersion`: lectura D1 de versión, SHA-256, estado `pending` y comisión `active`. Se ejecuta **después de leer el original y antes de entregar sus bytes al inspector**, y antes de procesar el resultado limpio o `422`. Al detectar un cierre devuelve `stale`, no reencola y no publica. Si D1 no puede consultarse, el error se propaga y conserva el retry fail-closed.
2. Tanto la consulta `UPDATE` como la inserción de auditoría de la vía `422` están ligadas explícitamente al mismo `documents.commission_id` y a comisión activa. La auditoría no se añade si la comisión se cerró, aunque otra transacción hubiera dejado `needs_review`.
3. La migración aditiva `0030_processing_commission_closure_guard.sql` introduce dos triggers SQL de tipo `BEFORE`: rechaza la inserción de `document_processing_reports` y cualquier intento de escritura a `ready/needs_review` sobre un documento de comisión cerrada. Se comprueba también una asignación repetida de `needs_review`, para impedir una auditoría tardía después de un `UPDATE` que no encontró filas. Error D1 `PROCESSING_COMMISSION_CLOSED`.

## Evidencia adversarial

TDD Red inicial: **6 pruebas fallaban** antes de la corrección y demostraron escritura `422` indebida, rechazo limpio tratado como error, envío del PDF al inspector tras cierre observado durante R2, guardias SQL ausentes y carreras previas a `db.batch`. Un séptimo caso Red mostró la auditoría falsa cuando una versión ya estaba `needs_review` y la comisión se cerró antes del batch. Green: las siete pruebas pasan; la regresión cubre también un redrive R2.11 y el procesamiento normal, la ausencia de informe/páginas/auditoría adicional y el typecheck.

## Límites

- No hay transacción global entre el registro del cierre, R2, Queue, inspector y D1. Si el original ya llegó al inspector **antes** de un cierre tardío, esta corrección no retira los bytes; si un informe se admitió antes de cerrar, no lo deshace. La consulta reduce la ventana de envío y los triggers bloquean admisiones posteriores en D1.
- La señal local `closed` procede de la tabla `commissions`, no del IdP ni del proveedor institucional. La segregación de permisos administrativos D1 sigue pendiente.
- Cualquier consulta D1 fallida antes de inspeccionar **no** concede acceso. No se trata de un protocolo de revocación remoto ni de autorización de infraestructura.
- El flujo normal sin cierre conserva el resultado de inspección `needs_review` y su auditoría en un único batch; las pruebas existentes deben mantenerse verdes. [P10](R2_ATOMIC_INSPECTION_AUDIT.md) añade la condición de `changes()=1` en el `INSERT` de auditoría para impedir eventos duplicados si otra transacción confirma antes del batch, aunque la comisión siga activa.

## Comprobación

```sh
pnpm exec vitest run apps/processor/src/consumer.test.ts apps/processor/src/manual-redrive-fence.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42934 sh scripts/ci.sh
```

**Resultado verificado en la base UX5:** `FOLIO_E2E_PORT=42934 sh scripts/ci.sh`, **exit 0**, 466 Vitest + 181 Python inspector + 7 contratos CI + 13 pruebas UX5 privacidad + 5 workerd + 129 Chromium = **801/801**, typecheck, builds/dry-runs y 30 migraciones D1 **exclusivamente locales**. La primera pasada (`42932`) tuvo un fallo E2E UX4 de arranque en 320 px y un error temporal de proxy API; el escenario pasó 6 veces aislado y 129/129 en la segunda pasada completa. No se atribuye una causa definitiva a ese fallo inicial ni se usó GitHub Actions como gate.

**Gate de publicación externo:** [issue institucional #19](https://github.com/DawoT/folio-civico/issues/19), CVE/VEX, IdP/MFA y autorización explícita Preview continúan sin cumplirse.
