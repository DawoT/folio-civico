# ADR-019 · Alta auditada de lotes e ítems de checklist por presidentes

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementado y validado localmente, sin despliegue ni carga de datos institucionales reales.

## Necesidad de producto

El piloto exigía insertar manualmente los lotes y el checklist en D1 antes de abrir la mesa de revisión. Las personas ya asociadas a una comisión activa necesitaban realizar estos pasos desde la interfaz, sin herramientas SQL ni alterar el historial de observaciones.

## Contrato funcional

- `POST /api/commissions/{commissionId}/batches`: crea un lote con `{label}` de 3 a 120 caracteres.
- `POST /api/commissions/{commissionId}/checklist/items`: crea un ítem con `{area:"works"|"procurement",expectedDocument}` de 3 a 160 caracteres; su estado inicial **siempre es `pending`**.
- Solo el `president` con membresía activa, JWT Access verificado y comisión abierta puede dar de alta. `GET` sigue disponible para los demás miembros autorizados.
- Ambos endpoints exigen `Content-Type: application/json`, `Idempotency-Key` de 8–96 caracteres, cuerpo máximo de 4096 bytes y origen de navegador compatible. Los datos adicionales y campos de autor suministrados por el cliente se rechazan.
- El servidor normaliza texto, impide caracteres de control y asigna ID y autor mediante identidad validada; no acepta `status` ni `reviewedBy` del cliente.
- D1 registra el recurso, su marcador inmutable de idempotencia y un evento `commission.batch_created` / `commission.checklist_item_created` **en una única transacción**. Un reintento idéntico devuelve el mismo recurso sin duplicar auditoría; una clave reaprovechada para otro payload u operación devuelve conflicto.
- Para evitar altas ocultas tras el límite de los listados actuales, se restringe cada comisión a **100 lotes y 100 ítems**. Si el recurso dejaría de caber, la transacción falla; no se simula una creación exitosa.
- React habilita **Crear lote** durante la selección de comisión y **Incorporar ítem** dentro de la mesa de revisión únicamente para el rol indicado. Tras crear un lote, lo selecciona; el usuario decide cuándo abrirlo.

## Seguridad, persistencia y TDD

La migración `0014_commission_provisioning.sql` añade `commission_provisioning_requests` con clave compuesta por comisión, actor y clave de petición, e impide editar/eliminar sus marcadores. La inserción utiliza una subconsulta que vuelve a exigir membresía, presidencia y comisión activa en el límite del SQL; si no se cumple, la restricción NOT NULL aborta toda la transacción. Los eventos de auditoría no se generan por lecturas o replays.

Las pruebas TDD cubren inserción y auditoría atómica, claves repetidas o reusadas, revocación y cross-tenant, comisiones cerradas, límites, cuerpos inválidos, origen inseguro, identidad JWT firmada con JWKS de prueba y acceso posterior a los recursos creados. La comprobación obligatoria es `sh scripts/ci.sh`, que también aplica las migraciones D1 locales.

## Límites y evolución

No se permite todavía crear la propia comisión, incorporar o revocar miembros, asignar roles ni editar el checklist institucional desde la interfaz. Estos pasos requieren una definición administrativa de alta autoridad, identidad real y política de auditoría. **No** es un despliegue ni onboarding institucional completo; la primera membresía sigue siendo un prerrequisito aprovisionado por un operador autorizado. No se toca el inspector ni la cuarentena PDF.
