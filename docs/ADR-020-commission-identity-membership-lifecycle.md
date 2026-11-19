# ADR-020 · Autoridad inicial de comisiones y ciclo de vida de miembros

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementado y probado localmente; **sin habilitación de operador ni despliegue Cloudflare**.

## Decisión arquitectónica

Una identidad autenticada por Cloudflare Access **no** posee automáticamente autoridad administrativa de Folio Cívico. La creación de la primera comisión usa un límite de confianza separado, cerrado por defecto:

- El Worker valida normalmente el JWT Access, su emisor, firma, audiencia y `sub`.
- Para `POST /api/commissions`, exige además que el `sub` **coincida exactamente** con `COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT` provisto por el operador como binding protegido del entorno. Si falta o está vacío, la operación devuelve **403** incluso con un JWT válido.
- `GET /api/session` comunica al usuario autenticado su `sub` y un booleano `canBootstrap`; no lista identidades de terceros ni expone la configuración del servidor.
- El operador proporciona **nombre e identificador Access del primer presidente**, verificado previamente fuera de la aplicación. No se permite que el navegador elija al operador ni afirme tener una firma institucional.
- Los registros se crean en una transacción D1 única: comisión, presidencia inicial, marcador de idempotencia inmutable y evento `commission.created`. No se crean comisiones parciales cuando falta capacidad en el listado (máximo 50 comisiones activas por identidad inicial).

**Configuración operativa pendiente:** entregar `COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT` al Worker con gestión de secretos autorizada, tras disponer de una identidad administrativa Access dedicada y controles MFA. No registrar su valor en Git, archivos `.dev.vars` compartidos ni documentación. **No se ha aplicado ningún binding remoto.**

## Administración por comisión

- `GET /api/commissions/{id}/members` — listado completo de hasta **100** identidades, sus roles, estado activo/revocado y revisión; solo presidencia activa.
- `POST /api/commissions/{id}/members` — alta, promoción, cambio de rol o reactivación. Body estricto: `{subject, role, expectedRevision}` con `expectedRevision: null` si es nueva y versión entera del registro cuando se actualiza.
- `POST /api/commissions/{id}/members/revoke` — revocación con `{subject,expectedRevision}`; no se borran identidades ni eventos.
- `role` admite solo `president`, `member`, `advisor` o `observer`. El `subject` es un identificador JWT Access opaco, **no una invitación por correo**. La presidencia no puede cambiar ni revocar su propia membresía. Una presidencia distinta puede delegar el cargo, pero el modelo evita terminar sin autoridad administrativa activa.
- El servidor exige presidencia y comisión activa tanto antes de la operación como en las condiciones SQL. Los cambios son idempotentes, atómicos, auditados y **optimistas por `revision`**; un formulario desactualizado produce conflicto (409) y se puede consultar de nuevo sin actualizar a ciegas.
- Las peticiones POST requieren `Idempotency-Key` de 8 a 96 caracteres, JSON estricto de como máximo 4096 bytes y origen del mismo sitio cuando el navegador transmite `Origin`. Identidades retiradas pierden acceso de inmediato aunque su JWT firmado no haya caducado.

## Datos y trazabilidad

- `0015_member_administration.sql`: `commission_members.revision`, diario inmutable `commission_member_actions` e índice por rol/estado.
- `0016_commission_bootstrap.sql`: diario inmutable `commission_bootstrap_requests`.
- Cada mutación escribe recurso, marcador y auditoría dentro de `D1.batch`. Se usan restricciones de modificación y `changes()` en las sentencias, de forma que una guarda fallida no crea un evento de éxito ficticio. El ID del actor procede exclusivamente del JWT verificado; el usuario no lo proporciona.
- No se almacena ni imprime un JWT, contraseña, token R2 o documento original.

## UX y verificación

- El formulario de **Crear comisión** solo aparece cuando `/api/session` confirma `canBootstrap`; requiere confirmación explícita de haber verificado a la persona que ejercerá la presidencia.
- El panel **Administración de miembros** solo aparece para presidentes de comisiones activas. Muestra identidades, rol, estado, revisión, incorporación, actualización, reactivación, revocación con doble confirmación y actualización manual.
- TDD sobre acceso cruzado, revocación, autosuspensión, concurrencia CAS, claves idempotentes, rollback, límites, estructuras inesperadas, origen, identidad Access firmada y lectura posterior. La verificación de integración es `sh scripts/ci.sh` sin recursos remotos.

## Lo que **no** certifica esta entrega

No se invita ni aprovisiona una persona automáticamente dentro de la política de Cloudflare Access; las políticas externas de acceso, MFA y revocación del IdP son operaciones independientes. Tampoco se han autorizado activaciones de Preview ni datos de una entidad real. La creación de una comisión no constituye su reconocimiento administrativo por una institución; es un espacio de trabajo interno de piloto. No se habilitan firma oficial, PDF de cuarentena ni herramientas MCP de escritura.
