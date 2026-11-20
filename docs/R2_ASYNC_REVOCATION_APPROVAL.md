# R2.10 · Aprobación asíncrona independiente de revocaciones

**Corte:** 2026-11-19 (America/Lima). **Estado:** código probado con JWT firmados sintéticos y D1 SQLite local. **No hay Worker público o privado desplegado, host operativo, IdP institucional ni claves reales configuradas.**

## Problema resuelto

R2.8/R2.9 verificaban dos identidades Cloudflare Access distintas, pero la ruta sintética inicial requería presentar **los JWT de actor y aprobador en la misma petición**. La criptografía no resolvía la custodia ni independencia temporal de las credenciales. R2.10 añade un procedimiento de **dos solicitudes diferentes**, sin que una persona maneje el token Access de la otra.

Ambas rutas son únicamente métodos lógicos del adaptador `Request/Response` de `apps/operator/src/isolated-host.ts`, restringido a `https://operator.local` y `mode:"synthetic-offline-only"`. No hay `ExportedHandler` ni binding Wrangler.

## Contrato de operaciones

**1. Solicitud del actor**, con **solo su JWT Access**:

```http
POST /internal/operations/revocation-proposals
Cf-Access-Jwt-Assertion: <JWT del actor>
Content-Type: application/json
```

El JSON contiene exactamente `{kind,target,incidentRef,requestKey,reason}`. Se verifica Access, la identidad configurada del actor y el formato del objetivo. La respuesta `202` contiene `{id,status:"pending",replayed:false}`. Se almacena el objetivo (necesario para su posterior bloqueo), el actor opaco, incidente, clave idempotente y **solo SHA-256 del motivo y payload**, sin conservar el texto del motivo ni ningún JWT. El plazo es **24 horas** desde `requested_at`; después no se puede aprobar. No se agrega ninguna revocación efectiva en esta etapa.

**2. Aprobación por una segunda persona**, con **solo su propio JWT Access**, un JWS firmado por la autoridad de incidentes y el identificador de la solicitud:

```http
POST /internal/operations/revocation-approvals
Cf-Access-Jwt-Assertion: <JWT del aprobador>
X-Folio-Incident-Approval-Jws: <JWS firmado por autoridad de incidentes>
Content-Type: application/json
```

El JSON contiene exactamente `{requestId}`. El servidor **verifica primero la identidad Access del aprobador**, luego recupera la solicitud D1 y valida que el JWS RS256 firma exactamente `kind`, hash de objetivo y motivo, `incidentRef`, `requestKey`, sujeto del actor y sujeto del aprobador. Exige `decision=approved`, `sub` del aprobador, `mfa=verified`, MFA reciente y un token no vencido. Una aprobación `approved` emite `200` sin revelar sujetos, hashes, tokens ni motivo.

Un JWS firmado acredita **la declaración de su emisor**, no demuestra que la persona examinó personalmente la prueba ni que la autoridad ejecutó MFA. Esa comprobación y la custodia de credenciales requieren un servicio externo independiente todavía no implementado.

## Persistencia, estados y protección de carrera

La migración **`0023_async_revocation_approvals.sql`** añade `processing_async_revocation_requests` con clave idempotente única `(actor_subject,request_key)`, `id` aleatorio, estado `pending` o `approved`, caducidad y las huellas inmutables. Triggers:
- Prohíben borrar registros, editar actor, destino, incidente, clave, motivo digerido, creación o ampliar su caducidad.
- Permiten **acortar** irreversiblemente la caducidad de una propuesta pendiente como barrera administrativa (no se agrega ruta para hacerlo).
- Solo admiten `pending → approved` con una identidad distinta, ambas filas de diario y denegatoria existentes y huellas coincidentes. Impiden falsificar una aprobación con `UPDATE` directo ordinario.
- El `UNIQUE(kind,target)` sigue aplicado **en la lista definitiva de revocaciones**, no en las propuestas: dos reportes pendientes de la misma imagen no se bloquean entre sí si uno se abandona.

La decisión usa un único `D1.batch` con **tres sentencias transaccionales**: inserción del asiento global `processing_redrive_revocation_actions`, de la denegatoria `processing_redrive_revocations` y de la transición de la propuesta a `approved`. El actor no necesita volver a iniciar sesión. La aprobación duplicada con **el mismo JWS** devuelve `replayed=true` únicamente si existen decisión, diario y denegatoria concordantes; otra JWS, otro incidente o un objetivo ya revocado produce conflicto. Si D1 falla antes de confirmar la transacción, no aparecen asientos parciales y puede repetirse la decisión válida.

No se ejecuta ninguna acción en Queue, R2 ni el inspector; los diez intentos agotados del outbox permanecen sin cambios.

## Defensa de la ruta previa

La ruta sintética combinada `POST /internal/operations/revocations` de R2.9 queda **deshabilitada por defecto** y responde `404`; requiere `allowLegacyCombinedRevocations:true` habilitado explícitamente solo en los tests de compatibilidad R2.9. No se registró en ningún Worker. La ruta R2.10 rechaza expresamente encabezados de aprobación/Access de la otra persona en la etapa del actor y el encabezado de segundo JWT en la etapa del aprobador.

## Pruebas reproducibles

```sh
pnpm exec vitest run apps/operator/src/async-approval.test.ts apps/operator/src/isolated-host.test.ts
pnpm exec vitest run packages/auth/src/revocation-authorization.test.ts packages/data/src/revocation-registration.test.ts
pnpm typecheck
sh scripts/ci.sh
# En worktrees concurrentes, seleccionar un puerto local libre para Chromium:
FOLIO_E2E_PORT=42791 sh scripts/ci.sh
```

La suite R2.10 prueba solicitudes independientes, caducidad, autoaprobación, JWT ajeno o ausente, JWS alterado, MFA caducada, motivos/objetivos no coincidentes, replay idempotente, colisiones con múltiples propuestas, carrera entre dos aprobaciones con JWS diferentes, inmutabilidad SQL, fallo transaccional sin asientos parciales y denegación HTTP en modo desactivado. Todas las identidades y documentos son sintéticos.

## Gate operativo pendiente

No existe un mecanismo real de firma institucional, cola de tareas humanas ni UI de revisión. El aprobador debe leer el motivo **a través de un sistema de incidencias autorizado independiente**; D1 conserva únicamente su hash. También faltan: política Access/MFA, roles y rotación de claves, auditoría de actividad humana, protección contra posesión indebida de JWT, revocación de permisos del actor antes de decidir, aislamiento de D1, alertas, clock-skew, backups, validación remota y aprobación expresa de recursos/costos. El bloqueo CVE del inspector sigue independiente y vigente.

**Este incremento implementa separación temporal de credenciales en software, pero no autoriza un despliegue Cloudflare ni certifica separación humana real.**
