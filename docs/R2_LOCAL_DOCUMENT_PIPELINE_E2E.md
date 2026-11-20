# R2.1 · Ensayo integrado local de la cadena documental

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementación de prueba E2E lógica local; ningún servicio remoto activado.

## Propósito

Demostrar con una **misma ejecución reproducible** que la recepción PDF autenticada mediante JWT Cloudflare Access, la cuarentena de objetos R2, el registro de outbox D1, el envío a una Queue simulada, el consumidor, el gateway que firma HMAC y la publicación D1 de texto verificado mantienen sus garantías de integridad, idempotencia, segregación y fallo seguro.

El código productivo de ingesta, outbox, consumidor y gateway se ejecuta sin reemplazarse; las dependencias externas se simulan con controles verificables:

- **D1:** SQLite en memoria con las migraciones reales vigentes del repositorio, transacciones y triggers; no se usa D1 remota.
- **Autenticación:** JWT RS256 firmados con clave temporal común y JWKS de prueba; emisor, audiencia, firma y `sub` se validan con `handleApiRequest`.
- **R2:** bucket privado simulado en memoria con operaciones `put/get/head/list/delete`, bytes PDF sintéticos y metadatos SHA-256. No se utiliza un bucket real.
- **Queue:** `send` capturado y mensajes con `ack/retry` reales del contrato de consumidor, simulando entregas, caída y redelivery.
- **Gateway:** `handleInspectorGatewayRequest` productivo que comprueba bytes y SHA-256, canoniza el manifiesto y firma HMAC fuera del parser.
- **Parser/escáner:** **doble sintético explícito**; produce un manifiesto de dos páginas y *no ejecuta ClamAV, qpdf, Poppler ni OCR*. Por tanto, **no valida la seguridad del scanner ni la imagen Container**.

## Ejecución

```sh
pnpm exec vitest run apps/api/src/processing-pipeline.e2e.test.ts
sh scripts/ci.sh
```

Archivo: `apps/api/src/processing-pipeline.e2e.test.ts`. No requiere red Cloudflare, credenciales, datos institucionales ni contenedores.

## Criterios cubiertos

| Escenario | Resultado esperado |
| --- | --- |
| Flujo completo, incluido JWT real | Alta PDF produce una sola versión y clave privada en R2; D1 outbox `pending`; Queue no recibe nombres ni claves; Processor lee y rehash; Gateway firma resultado; D1 registra dos páginas `ready`; API solo sirve texto a miembros autorizados |
| Idempotencia triple | Repetir carga devuelve el mismo ID; reentregar mensaje completado no llama otra vez al scanner ni duplica informe/páginas/auditoría; outbox no reenvía completados |
| Fallo de Queue y error 503 | Un envío rechazado deja `pending/0`; reenvío posterior marca `sent`; 503 obliga a `retry` sin publicar; envío antes de 15 minutos se bloquea y después del lease se permite; posterior recuperación completa una vez |
| 422 y mensajes malformados | Mensaje inválido se confirma sin leer R2; únicamente un **422 HMAC del gateway vinculado al ID/SHA/nonce de la petición** mueve a `needs_review`, no produce páginas y deja estadística `rejected`. Un 422 vacío, manipulado o de otra petición provoca retry sin alterar D1 ([P8](R2_SIGNED_UNSAFE_INSPECTION_VERDICT.md)) |
| HMAC manipulado y original alterado | Firma modificada provoca retry sin páginas; bytes de R2 que no coinciden con la huella frenan procesamiento antes del gateway; la conciliación R2/D1 **no** afirma integridad de bytes |
| Comisión cerrada | No se despacha si está cerrada; si se cerró después de publicar en Queue, el consumidor confirma el mensaje obsoleto **sin leer R2 ni contactar al inspector** |
| Intentos agotados | Tras 10 despachos sin consumo, no se envían más; el diagnóstico expone `exhausted:1` sin borrar objetos ni fingir un resultado `completed` |

Se utilizan identidades de prueba distintas para autor, miembro autorizado, identidad revocada y comisión ajena. El resultado autenticado nunca expone rutas `quarantine/*` ni PDF original. El reporte de `auditQuarantine` conserva `integrityVerified:false` y `snapshotAtomic:false` porque no puede certificar integridad total del R2.

## Límites y bloqueos

Este es un **E2E de contratos de software en el mismo proceso Vitest**, no una prueba E2E con red real, Queue física, Durable Object Container, escaneo antimalware auténtico, OCR ni Cloudflare Access remoto. Los errores y reintentos se simulan intencionalmente; los parámetros operativos como DLQ, retención, alarmas, escalado y rotación de credenciales siguen pendientes de pruebas reales en un Preview autorizado. `needs_review` es rechazo conservador, nunca aprobación automática. **El gate CVE del inspector sigue siendo independiente y bloqueante para habilitar runtime.**

Para avanzar a R2 completo faltan: inspección real por toda la cadena con la imagen finalmente aprobada; fallos de motor y agotamiento DLQ en un entorno de Queue/Containers real; recuperación tras reinicio, concurrencia entre Workers y pruebas con acceso de red aislado. No se han creado recursos ni realizado despliegues.
