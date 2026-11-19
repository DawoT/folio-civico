# R2.8 · Registro privado, firmado y auditable de revocaciones

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementación y pruebas locales; **sin endpoint público/privado conectado, identidad real, secrets ni despliegue remoto**.

## Objetivo

R2.7 introdujo una denegatoria inmutable para bloquear inmediatamente operadores, aprobaciones, constancias, imágenes y claves de redrive. Faltaba un mecanismo controlado y reproducible para **insertar** una revocación sin permitir que cualquier caller escribiese en D1.

R2.8 añade dos módulos aislados:

- `packages/auth/src/revocation-authorization.ts`: `verifyRevocationAuthorization`, un preflight que exige **dos JWT Cloudflare Access** válidos de personas distintas (actor de incidentes y aprobador), ambas explícitamente configuradas; más una **constancia JWS RS256 de autoridad de incidentes independiente** con `decision=approved`, `mfa=verified` y MFA de los últimos cinco minutos.
- `packages/data/src/revocation-registration.ts`: `registerRedriveRevocation`, que **solo acepta la capacidad efímera sellada** por el módulo anterior, revalida su alcance y caducidad y escribe el evento global de auditoría y la denegatoria **en una única transacción D1**.

No hay ruta de redrive ni revocación, API pública, interfaz, cron, comando remoto o configuración Wrangler que invoque estas funciones. La revocación global puede afectar varias comisiones, por lo que **no** se inserta en `audit_events` (cuya clave `commission_id` es obligatoria).

## Separación de funciones y contenido firmado

La aprobación independiente vincula por firma: `purpose=folio.redrive.revocation.approval.v1`, `kind`, SHA-256 del tipo y objetivo canónicos, SHA-256 del motivo normalizado, `incidentRef`, `requestKey`, sujeto Access del actor y del aprobador, `decision=approved`, `mfa=verified`, `mfaAt`, expiración y `sub` del aprobador.

Ambos sujetos tienen JWT Access verificados mediante JWKS y se comparan con dos sujetos distintos de una **configuración operativa de confianza**. La autoridad JWS de incidentes requiere clave pública RSA, issuer HTTPS diferente al Access issuer y audiencia fijada; los campos de clave privada se rechazan. La constancia debe estar vigente y su tiempo de vida no puede exceder cinco minutos.

La capacidad tiene marca privada `Symbol` y `WeakSet`: copiarla, serializarla o construir un objeto con las mismas propiedades no concede permisos. El registrador vuelve a comprobarla antes de iniciar la transacción, después de la consulta idempotente.

**Un token firmado no demuestra por sí solo MFA real ni que un ticket haya sido aprobado:** el emisor de incidentes deberá autenticar al aprobador, comprobar sus facultades, verificar la evidencia y el ticket en una plataforma privada y auditar esas acciones antes de firmar. R2.8 todavía no implementa ni provisiona ese emisor.

## Persistencia y concurrencia

Migración **`0022_revocation_registration_journal.sql`**:

- Nueva tabla global `processing_redrive_revocation_actions`, con `(actor_subject,request_key)` como clave primaria y `(kind,target)` como único. Guarda actor, aprobador, ticket de incidente, huellas del objetivo, motivo, JWS, clave firmante y payload; **no almacena el texto del motivo, JWT, datos OCR ni secretos**.
- Triggers `BEFORE UPDATE` y `BEFORE DELETE` protegen el diario.
- Un nuevo trigger `BEFORE INSERT` de `processing_redrive_revocations` **rechaza inserciones sin una fila correspondiente en el diario**. El registrador usa `db.batch` de dos sentencias (`INSERT action` y `INSERT revocation ... WHERE changes()=1`): la transacción D1 completa ambos registros o revierte ambos.
- El segundo envío concurrente del mismo objetivo pierde por el índice único. Repetir la **misma solicitud firmada** devuelve `replayed=true` solamente si existen **tanto** el diario como la revocación correspondiente. Reutilizar la clave con otro payload o el objetivo con otro incidente genera conflicto. Un diario huérfano no cuenta como éxito.
- Los registros siguen siendo **permanentes**; no se ha implementado eliminación, reversión, redrive ni ninguna acción sobre Queue/R2.

**Límite de confianza:** un administrador con acceso directo de escritura a D1 podría insertar filas falsas en ambas tablas sin demostrar la firma en SQL. Los triggers defienden la ruta normal y los errores de una sola inserción, pero **no sustituyen** la autenticación del host, la separación de privilegios y la auditoría administrativa del acceso D1. La tabla no debe exponerse a usuarios finales ni a un conector con permisos generales.

## Verificación con datos sintéticos

```sh
pnpm exec vitest run packages/auth/src/revocation-authorization.test.ts
pnpm exec vitest run packages/data/src/revocation-registration.test.ts
pnpm exec vitest run packages/data/src/manual-redrive.test.ts
pnpm typecheck
sh scripts/ci.sh
```

Incluye TDD Red/Green de firmas incorrectas, dos identidades diferentes, allowlist ausente, aprobación autoemitida, MFA desactualizada, firmas por la autoridad equivocada, revocación de otro objetivo o motivo, entrada SQL sin diario, competencia de dos solicitudes, fallo de D1, diario huérfano, expiración entre consulta y escritura, idempotencia y efecto inmediato sobre `isManualRedriveRevoked`.

## Condiciones para operación real

Se requiere, **antes de activar**: autorización explícita de recursos Cloudflare; aprobación jurídica/operativa del entorno; política Access/MFA y dos identidades distintas; autoridad JWS de incidentes auditada con su clave privada fuera del código; protocolo de respuesta a incidentes/rotación; revisión de mínimos privilegios en D1 remoto; monitoreo y retención; y ensayo con casos falsos en Preview una vez que se superen los gates de CVE del inspector. Una revocación posterior a un `Queue.send` aceptado no puede retirarlo retroactivamente.

**R2.8 es un contrato de software aislado, no una activación de recuperación o revocaciones institucionales.** El [adaptador R2.9](R2_ISOLATED_OPERATOR_HOST.md) comprueba la conexión de los verificadores en pruebas locales de Request/Response; sigue sin existir host deployado, identidad institucional ni mecanismo de aprobación humana remoto.
