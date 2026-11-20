# R2.12b/P2 · Diario inmutable de evidencia institucional (preparatorio)

**Estado:** código y D1 local sintéticos. **No equivale a aprobación institucional de R2.12b** ni habilita host, Access real, Queue, R2 o migraciones remotas. La autoridad externa sigue pendiente en [#19](https://github.com/DawoT/folio-civico/issues/19).

## Invariante añadido

En P1 se comprobaba el expediente en memoria antes de aprobar. No quedaba una constancia D1 de qué **revisión** del expediente autorizó la decisión; además, desactivar posteriormente el lector configurado podía degradar el flujo. P2 introduce una evidencia mínima, inmutable y vinculada a la aprobación.

La migración `0026_institutional_approval_evidence.sql` agrega a las propuestas asíncronas R2.10 y R2.11 el marcador `institutional_gate_required` (0 por defecto para compatibilidad sintética, 1 cuando la propuesta se crea con lector institucional configurado). Es inmutable desde la creación. No puede desactivarse posteriormente con un cambio de configuración ni con `UPDATE` D1 ordinario.

`processing_institutional_approval_evidence` conserva, con clave única `(purpose,request_id)`, únicamente: propósito `revocation|redrive`, ID de solicitud, sujetos opacos de actor y aprobador, SHA-256 del ámbito y del JWS exacto, revisión positiva de expediente, `checked_at`, vencimiento de solicitud y fecha de asiento. **No contiene JWT, JWS, motivo, PDF ni contenido del expediente.**

El insert de evidencia se realiza en **el mismo `D1.batch` transaccional** que los asientos de revocación o la constancia de redrive y la transición `pending→approved`. Los triggers:

- Rechazan constancia cuya solicitud no existe, está aprobada/expirada, tiene otro actor/aprobador o no está recién consultada (máximo 15 segundos, más 5 de tolerancia de reloj).
- Rechazan `UPDATE`/`DELETE` de la constancia y modificación del marcador de obligación.
- Rechazan transición `approved` de propuestas marcadas 1 si falta constancia del mismo actor, aprobador, JWS, solicitud, vencimiento y lectura reciente.
- Conservan las validaciones previas: independencia de identidades Access/JWS, revocación de facultades del ledger R2.12a, diario, un solo redrive y no Queue antes de autorización.

Antes de ejecutar un redrive, el adaptador vuelve a consultar el estado actual y compara la revisión, ámbito, digest de aprobación, sujetos y vencimiento con el asiento D1. **Cambio de revisión = 403; lector no disponible = 503, sin enviar Queue.** Replays verificados con una constancia anterior también requieren la misma revisión.

## Alcance y límites no negociables

- El marcador 0 y los registros anteriores son exclusivamente **compatibilidad sintética**. Este incremento **no añade ni habilita un Worker operador**; el único host conserva `mode:"synthetic-offline-only"`. La mera presencia de un asiento no demuestra que un humano haya aprobado en un IdP real.
- Un administrador con permiso de escritura/esquema D1 puede soslayar controles; siguen pendientes la cuenta de mínimo privilegio, revisiones y auditoría externa. No se ha elegido ni probado ningún proveedor de incidencias.
- **No hay transacción distribuida** entre sistema externo, D1 y Queue. Un expediente puede cambiar tras la última consulta; el asiento atómico prueba únicamente la versión reportada antes de la decisión D1. [R2.12b/P3](R2_INSTITUTIONAL_INVALIDATION_KILL_SWITCH.md) añade el ledger y bloqueo D1 de invalidación sintética antes de decidir/reservar y una relectura después de reservar. **Siguen pendientes** la entrega autoritativa de eventos desde la institución, la conciliación y el análisis de la ventana no transaccional con Queue; no hay linealizabilidad global.
- El veto por revocación de rol/membresía del IdP, la custodia de claves, revisión humana y MFA real, permisos de servicio, políticas de retención, CVE del inspector y autorización Preview siguen **bloqueantes**.
- La política de migraciones es solo aditiva. No se aplicó a un D1 remoto.

## Pruebas

TDD Red→Green contra la ausencia inicial de columna y ledger. Casos adversariales con SQL directo: marcador inmutable, obligación de constancia para aprobar, rechazo por identidad cambiada y lectura antigua, bloqueo de modificación/borrado y unicidad de la evidencia. Casos end-to-end sintéticos por HTTP lógico: propuesta marcada, prohibición de downgrade por configuración, asiento conjunto con decisión, revisión nueva bloqueando replay/Queue, fuente caída y rollback completo de decisión, denylist y evidencia ante fallo de transacción.

```sh
pnpm exec vitest run apps/operator/src/institutional-journal.test.ts apps/operator/src/async-approval.test.ts apps/operator/src/async-redrive.test.ts apps/operator/src/institutional-authority.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42916 sh scripts/ci.sh
```

**Condición de cierre:** ninguna prueba sintética sustituye el sistema institucional designado, sus responsables, autorizaciones o el [gate externo #19](https://github.com/DawoT/folio-civico/issues/19).
