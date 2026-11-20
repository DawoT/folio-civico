# R2.12a · Retirada efectiva de facultades en operaciones asíncronas

**Alcance:** endurecimiento local de R2.10 (revocación) y R2.11 (redrive).
No configura una autoridad real de incidencias, no concede permisos de escritura
D1, no crea endpoints, no despliega Worker y no habilita Queue ni Cloudflare.

## Problema corregido

Una constancia JWS válida y un JWT de Access aún válido no acreditan que la
persona conserve **facultades** para actuar. La lista inmutable R2.7 de
`processing_redrive_revocations(kind='operator',target=subject)` ya existía,
pero algunas operaciones asíncronas podían registrar solicitudes, aprobar
pendientes o devolver replays aunque el actor o el aprobador estuvieran
revocados. La aprobación del redrive comprobaba revocación del aprobador en D1,
pero no del solicitante en el mismo punto.

## Contrato implementado

- **Consulta vigente antes de la operación:** solicitud y aprobación de
  revocación, solicitud y aprobación de redrive consultan el ledger D1.
  Una facultad revocada deniega la operación incluso si el JWT Access y JWS
  criptográficamente siguen siendo válidos. Un error de D1 **no** equivale a
  «facultad activa»: se propaga como indisponibilidad.
- **Protección transaccional ante carreras:** `0025_async_operator_authority_revocation.sql`
  añade cuatro triggers para impedir propuestas R2.10 de actores revocados,
  transición a aprobado de R2.10 con actor o aprobador revocado,
  inserción de la constancia R2.11 si el operador ha perdido facultades,
  y transición de aprobación R2.11 con cualquiera de los dos revocado.
  Complementa, no reemplaza, los triggers, el journaling y la idempotencia
  anteriores. El chequeo SQL se evalúa en la misma escritura de D1.
- **Replay de solo lectura:** cuando se ha revocado una de las facultades,
  no se presenta como una nueva autorización activa la repetición de una
  propuesta o decisión previa. Las filas aprobadas ya registradas no se
  eliminan ni reescriben, preservando evidencia histórica.
- **Redrive:** siguen en vigor el único envío, el estado `uncertain`, la
  revocación antes de Queue y las autorizaciones del inspector de R2.5–R2.11.
  No se introduce un redrive automático.

La semántica de concurrencia es serializable **solo respecto de las escrituras
en D1**. Una revocación registrada *después* de una aprobación no deshace
retroactivamente aquella transacción ni cancela un mensaje ya aceptado por Queue.

## Verificación local

Casos TDD Red/Green: permiso retirado tras solicitud pendiente en cada rol;
denegación de propuestas nuevas y de replay; rechazo SQL directo sin pasar
por el código TypeScript; rechazo de aprobación de redrive cuando el operador
o aprobador fue revocado; no retorno de aprobaciones previas como autoridad
nueva y no envío a Queue. Las pruebas adversariales inyectan además una
revocación **después del preflight y antes del batch**, y comprueban el
rechazo SQL sin persistencia parcial de la decisión.

Comandos:

```sh
pnpm exec vitest run apps/operator/src/async-approval.test.ts apps/operator/src/async-redrive.test.ts
pnpm typecheck
sh scripts/ci.sh
```

**Evidencia local verificada en esta rama:** TDD Red (5 fallos
reproducidos) → Green (32/32 en las dos suites focalizadas); `pnpm typecheck`
exit 0; `sh scripts/ci.sh` exit 0: 7 tests de contrato local,
362 Vitest, 147 Python, 5 workerd y 36 Chromium (**557 pruebas en total**),
compilación web, dry-runs de Workers y migraciones hasta `0025` aplicadas
en D1 **local** de API/MCP/Processor. No se ejecutó la auditoría de imagen
CVE ni el smoke Docker del inspector; su gate sigue bloqueante.

La integración con un sistema de tickets institucional **no está implementada**.
Para completar el procedimiento humano se requiere seleccionar y auditar el
sistema autorizado, verificar estado/versión de la incidencia y actor aprobador
mediante credenciales de servicio aisladas, constancia de MFA en el IdP real,
revisión del motivo en el sistema de origen, facultades revocables, separación
de permisos de lectura/escritura D1 y evidencia de retención/consulta/auditoría.
Un JWT o JWS que declare `mfa=verified` sigue siendo una afirmación del
emisor hasta validar sus procesos. Ningún gate CVE de inspector se relaja.

**Condición de publicación:** CI local aprobado es necesario pero nunca
suficiente para desplegar. Preview/producción, rotación de claves, IdP,
costos e infraestructura requieren autorización separada.
