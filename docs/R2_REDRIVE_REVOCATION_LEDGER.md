# R2.7 · Revocación de constancias y claves de redrive (D1 privada)

**Fecha:** 2026-11-19 (America/Lima). **Estado:** código y pruebas locales. Sin API de revocación, sin conexión a Queue/Cloudflare remota, sin operadores ni claves reales provisionadas.

## Riesgo atendido

Una constancia R2.6 puede estar correctamente firmada, pero su operador, autorización individual, imagen del inspector o clave firmante puede ser revocada **antes de su fecha de caducidad**. La verificación RSA original no consulta un sistema de revocación. R2.7 introduce una lista **denegatoria, permanente e inmutable** en D1 que prevalece sobre la validez criptográfica temporal.

El rechazo puede activarse por seis objetivos:

| Tipo | Objetivo registrado | Uso |
| --- | --- | --- |
| `operator` | Sujeto Access opaco | Revocación del operador |
| `approval_ref` | Referencia `OPR_...` | Incidente o aprobación retirada |
| `attestation` | SHA-256 del par de constancias firmado | Revocación de una operación concreta |
| `image` | Digest `sha256:...` del inspector | Retirada de imagen con hallazgo de seguridad |
| `approval_key` | JWK thumbprint SHA-256 Base64URL | Clave de aprobación comprometida |
| `release_key` | JWK thumbprint SHA-256 Base64URL | Clave del emisor de release comprometida |

El contenido firmado no se persiste en la tabla de revocaciones. El sujeto Access y la referencia operativa son valores internos de D1, **no** se muestran en respuestas públicas.

## Diseño de seguridad

La migración **`0021_redrive_revocation_ledger.sql`** añade `processing_redrive_revocations(kind,target,incident_ref,created_at)` con clave primaria `(kind,target)` y triggers que rechazan cualquier `UPDATE` y `DELETE`. Las incidencias requieren una referencia opaca y la tabla impide tipos de destino desconocidos.

La misma migración añade a `processing_manual_redrives` el digest de imagen y las dos huellas de clave, con campos inmutables. Un trigger **`BEFORE INSERT`**:

1. Rechaza reservas que no incluyan procedencia completa.
2. Rechaza una reserva si cualquiera de los seis valores está revocado, incluso cuando la revocación se insertó después de la consulta previa de la aplicación y antes de iniciar la transacción.

El ejecutor R2.5 consulta la lista **antes de cualquier replay o reserva** y **de nuevo inmediatamente antes de Queue.send**. Si hay revocación posterior a la reserva, se marca `halted` y no se envía. Si D1 deja de responder, la operación se bloquea: sin reserva nueva o, si ya existía, conservando `reserved` para conciliación humana sin reenvío automático.

Los registros de revocación son **denegaciones**, no autorizaciones; no alteran R2, documentos, informes ni el outbox de diez intentos.

## Procedimiento futuro (no automatizado)

La tabla **no tiene ruta HTTP, MCP, cron ni botón**, ni se ha añadido una función para insertar revocaciones desde un caller sin autenticación. Una operación real deberá usar un proceso privado y autorizado de respuesta a incidentes que autentique al responsable, verifique evidencia, ticket y alcance de la revocación, inserte una sola fila en D1 y preserve un registro del actor y su aprobación fuera de esta tabla. El campo `incident_ref` **no prueba** por sí mismo la identidad ni la aprobación.

La revocación es deliberadamente irreversible mediante SQL ordinario. Falsos positivos requieren un procedimiento explícito de revisión, no eliminar silenciosamente la fila. Una clave rotada puede bloquearse por su huella sin desautorizar automáticamente otras claves de distinto thumbprint.

No existe transacción distribuida D1–Queue: **una revocación que ocurra después de la segunda consulta, mientras Queue.send está ejecutándose, podría no impedir ese envío**. El consumidor debe volver a verificar el estado del documento y la comisión; la revocación de un token no permite inferir el estado final del mensaje ya entregado. Pruebas con infraestructura real y conciliación siguen pendientes.

## Verificación

```sh
pnpm exec vitest run packages/data/src/manual-redrive.test.ts packages/auth/src/manual-redrive-authorization.test.ts
pnpm typecheck
sh scripts/ci.sh
```

Los escenarios nuevos prueban los seis tipos, revocación después de reservar, revocación entre lectura y reserva (guard SQL), caída D1 antes y después de reservar, duplicidad, inmutabilidad y prohibición del segundo envío. Los fixtures usan D1 SQLite y tres firmantes sintéticos.

**Bloqueo de release:** continúan pendientes los emisores reales auditados, Identity/Access/MFA, el gate CVE completo del inspector, aprobación explícita y activación remota autorizada. Una base D1 local con revocaciones sintéticas no constituye un sistema operativo de revocación.
