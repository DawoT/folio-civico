# ADR-006 · Conciliación privada y no destructiva de cuarentena R2–D1

**Fecha:** 2026-11-18  
**Estado:** implementado y probado localmente; tarea programada desactivada y Preview remoto pendiente.

## Contexto

La recepción de un PDF usa un `put` en R2 y una transacción D1 posterior. Las dos operaciones no comparten una transacción distribuida. Si la persistencia falla y también falla la eliminación compensatoria, puede quedar un objeto privado sin referencia. También puede existir la situación inversa: una versión documental sigue registrada, pero el objeto R2 desaparece.

El sistema debe detectar anomalías sin eliminar automáticamente evidencia, exponer claves R2 ni afirmar que se comprobó el contenido del PDF.

## Decisión

Se implementa `auditQuarantine(db,bucket,options)` en `packages/data/src/quarantine-audit.ts`. Se ejecuta **solo como diagnóstico interno**:

- Consulta referencias D1 de versiones con claves `quarantine/` y usa `R2.head` para detectar objetos ausentes.
- Lista objetos R2 bajo el prefijo `quarantine/` usando `list({ prefix, limit, cursor, include: ["customMetadata"] })`, siguiendo el cursor solo hasta el límite autorizado. Por cada objeto consulta si existe una versión D1 que lo referencia.
- Marca como **candidato a huérfano** un objeto sin referencia con al menos **48 horas de antigüedad**. Los recientes o de edad desconocida no son candidatos.
- Detecta diferencias entre el SHA-256 registrado en D1 y el SHA-256 de **metadatos** R2, sin leer ni ejecutar los bytes del PDF.
- Entrega conteos, estado de completitud y hallazgos identificados solo por una huella SHA-256 truncada de 96 bits calculada a partir de la clave con prefijo de dominio. **Jamás devuelve la clave R2 original**. Los detalles se limitan a 25 hallazgos, con bandera `findingsTruncated`.
- Los límites configurables nunca exceden **5 páginas R2, 100 objetos por página ni 250 referencias D1**. Por defecto: 3 páginas, 50 objetos/página y 100 referencias. Si se alcanza algún límite con trabajo pendiente, `complete=false`.
- Si D1 o R2 fallan, la operación falla sin producir un informe falsamente completo.

Para evitar asociar un mismo objeto físico a varias versiones, la migración `0008_unique_r2_object_keys.sql` crea un índice único sobre `document_versions.r2_object_key`.

## Operación y exposición

El Worker API incorpora un manejador `scheduled` que invoca `runQuarantineAudit`. Solo emite métricas agregadas al log, sin claves ni huellas de objetos. **No hay un `cron` configurado en Wrangler:** nada se ejecuta de forma recurrente ni se habilita automáticamente al desplegar el código. Tampoco se agrega un endpoint HTTP, herramienta MCP ni botón de usuario para esta auditoría.

Habilitar un disparador `cron` queda sujeto a un Preview dedicado, autorización de la cuenta, permisos mínimos, control de costos y aceptación del operador. Los escaneos completos a mayor escala necesitarán paginación persistida y un plan de observabilidad seguro.

## Por qué no hay eliminación automática

Un objeto aparentemente huérfano puede ser resultado de una carga concurrente, consistencia temporal o recuperación en proceso. Un informe completo de un momento dado **no constituye autorización para borrarlo**.

Cualquier futuro eliminador deberá comprobar de nuevo D1, la antigüedad, la política institucional de retención, eventos de auditoría, litigio/conservación y aprobación expresa del operador. Será una operación distinta con pruebas y un modo de simulación. En esta entrega no existe ninguna llamada `R2.delete` en el código de auditoría.

## Limitaciones explícitas

- `snapshotAtomic=false`: D1 y R2 no proporcionan una instantánea transaccional conjunta.
- `integrityVerified=false`: un hash en los metadatos **no** prueba que los bytes originales coincidan. El escaneo no llama `R2.get`, no analiza antimalware y no transforma PDFs.
- El informe puede ser parcial por topes de exploración; no se usa para tomar acciones destructivas.
- La autenticación Cloudflare Access/Managed OAuth, MFA y el entorno Preview reales siguen pendientes por configuración del operador.
- No incluye conservación, caducidad, restauración, tratamiento jurídico de evidencias ni borrado; esas políticas deberán acordarse con la institución.

## Verificación

Se prueban: objetos referenciados, candidatos antiguos y recientes, ausencias R2, discrepancias de metadatos, paginación por cursor y límites, informes parciales, fallos D1/R2, ocultamiento de claves, ausencia de borrados y salida agregada. La suite `workerd` ejecuta `LIST` y `HEAD` reales sobre R2 **local** y elimina únicamente su propio fixture al terminar la prueba.

Fuentes: [R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/), [D1 Workers API](https://developers.cloudflare.com/d1/worker-api/d1-database/), [ADR-002](ADR-002-r2-intake.md).
