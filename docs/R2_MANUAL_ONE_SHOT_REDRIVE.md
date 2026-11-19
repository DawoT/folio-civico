# R2.5 · Redrive manual individual, de un solo intento

**Fecha:** 2026-11-19 (America/Lima). **Estado:** contrato de código **aislado y verificado localmente**; sin endpoint, sin conexión a Queue ni inspector reales, sin activación de recursos remotos.

## Decisión y límites de autorización

Una **conformidad R2.4** es una recomendación interna, no autorización automática para reenviar el documento. R2.5 define `executeOneShotManualRedrive`, que **solo podrá** ser llamado en el futuro por un host operador privado, después de resolver tres condiciones independientes:

1. Revisión R2.4 vigente, confirmada por un presidente y otro revisor activos, con documento `pending`, comisión `active`, outbox `sent/10`, SHA-256 coincidente y **sin** informe del inspector.
2. Identidad de **operador distinta** de ambos participantes de la comisión, confirmada mediante JWT firmado de Cloudflare Access, emisor/audiencia/JWKS y coincidencia exacta con el operador configurado.
3. **R2.6 exige una capacidad efímera sellada** generada exclusivamente por un preflight que comprueba dos declaraciones independientes RS256: una aprobación humana vinculada a la operación y con afirmación MFA reciente, y un release del inspector de imagen/digest fijados por el host. El contrato previo `inspectorReleaseApproved: true` fue eliminado. La firma criptográfica verifica la procedencia de estas afirmaciones, **no acredita por sí misma** una auditoría CVE ni MFA efectivamente realizada. Véase [R2.6](R2_OPERATOR_SIGNED_AUTHORIZATION.md).

No existe actualmente host que satisfaga estas condiciones: el módulo **no está conectado** a `apps/api`, `apps/mcp`, el cron, el consumer ni las configuraciones Wrangler activas. No procesamos documentos reales ni tocamos Cloudflare.

## Garantía de entrega con fallo seguro

Se introducen las migraciones **`0019_manual_redrive_one_shot.sql`** y **`0020_redrive_signed_attestation_digest.sql`** con el diario `processing_manual_redrives` y la huella inmutable de las constancias firmadas: una fila única por **versión** y por **revisión R2.4**, más una clave idempotente única por operador. Las referencias de comisión, versión, SHA-256, operador y autorización permanecen inmutables; los triggers prohíben borrado, autoaprobación y transiciones de estados terminales.

Flujo de la función aislada:

1. Exige la capacidad verificada R2.6, el digest de inspector configurado y formato de solicitud; consulta D1 para validar conformidad/roles/estado actual.
2. Reserva un **único intento en una transacción D1** y escribe `audit_events` con `processing.manual_redrive_reserved`. Si otro operador o proceso reservó ya la versión, se rechaza el segundo envío. La misma clave/payload devuelve el estado existente sin repetir Queue.
3. Reconsulta elegibilidad y **caducidad de la capacidad firmada** antes de enviar. Si cambió el estado institucional, expiró la firma o cambió el digest del inspector, marca `halted` y **no envía**.
4. Envía solo el mensaje mínimo `{kind,versionId,sourceSha256}` al **puerto Queue inyectado**. No pasa claves R2, nombre de archivo, sujeto, incidente, actas ni texto de OCR.
5. Si Queue resuelve, marca `sent`. Si Queue **rechaza**, la entrega pudo haber ocurrido antes de perderse la respuesta: marca `uncertain`, **sin reintento automático**. Un fallo de D1 tras un envío deja `reserved`, también sujeto a conciliación manual. Cada transición escribe su evento de auditoría en D1.

**Importante:** no hay transacción distribuida D1–Queue. Un cierre institucional entre la última consulta y el `send` puede producir una entrega con datos ya obsoletos; el consumidor vuelve a comprobar comisión y documento antes de leer R2. Los mensajes pueden repetirse por semántica de proveedor, aunque **el componente de redrive nunca invoca un segundo `send` para la misma versión**.

El outbox original conserva **10 intentos**, `last_sent_at` y estado; no se reinician contadores ni se desbloquea la cola cron. Una reserva en estado `reserved` tras reinicio, `uncertain` o `halted` **nunca se reintenta automáticamente**. Otro intento para la misma versión requeriría **un diseño nuevo con autorización, migración y pruebas específicas**, no una edición de contador.

## Verificación reproducible

```sh
pnpm exec vitest run packages/data/src/manual-redrive.test.ts
pnpm exec vitest run apps/api/src/processing-pipeline.e2e.test.ts
pnpm typecheck
sh scripts/ci.sh
```

Los tests usan D1/SQLite migrado, dos identidades de comisión, un operador externo ficticio, Queue **completamente simulada**, el contrato del consumidor existente y fallos inyectados. Cobertura: éxito con diario y mensaje mínimo, replay, carreras mientras `send` no resuelve, denegaciones de identidad, release gate, revisión obsoleta, comisión cerrada, revocaciones, outbox no agotado, estado rechazado, SHA/tenancy, firma de referencia inválida, SQL forzado, rechazo ambiguo de Queue, revocación después de reservar y pérdida de D1 después del envío.

## Lo que todavía **no** está autorizado ni probado

- La conexión a un host privado y la auditoría de sus autoridades firmantes: R2.6 ya comprueba Access JWT y dos JWS independientes, pero aún no existe **un emisor real aprobado** que certifique MFA efectiva, decisiones humanas y el gate Trivy/firmas/artefacto ejecutado.
- Validez **externa** de la autorización `OPR_...` (referencia opaca, no permiso criptográfico), revisión de controles de separación de personas y procedimientos de aprobación institucional.
- Configuración y provisión autorizada de Queue/DLQ, acceso a D1 y R2, billing y observabilidad sin PII.
- E2E con Queue real, concurrencia inter-regional, desconexión después de publicar, recuperación de mensajes retenidos, auditoría de infraestructura y pruebas del inspector real.

**No se debe conectar este módulo al runtime ni emitir o confiar en constancias de release sin autorización expresa y verificación independiente del gate de seguridad.** El desarrollo local no autoriza Preview o producción. La función aún no puede ejecutarse por un usuario final.
