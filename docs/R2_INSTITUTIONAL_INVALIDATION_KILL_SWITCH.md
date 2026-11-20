# R2.12b/P3 · Invalidación institucional irrevocable en D1 (solo sintética)

**Estado:** contrato de revocación negativa, migración D1 aditiva y pruebas locales. **No** existe lector/escritor autorizado de un sistema institucional real. No equivale a cerrar [issue #19](https://github.com/DawoT/folio-civico/issues/19), levantar el gate CVE, ni habilitar Cloudflare.

## Riesgo que aborda

En P2 una propuesta aprobada conserva una constancia inmutable de la revisión institucional y el host vuelve a consultar el expediente antes de Queue. Si la institución cierra la incidencia o retira las facultades **después** de esa consulta, no había un mecanismo D1 persistente para detener una reserva que aún no se había realizado o un redrive ya reservado.

La migración **`0027_institutional_approval_invalidations.sql`** introduce `processing_institutional_approval_invalidations`, un ledger append-only para cancelar permanentemente una solicitud **institucionalmente marcada**. La clave única `(purpose, request_id)` impide cancelaciones incompatibles del mismo flujo; `UPDATE` y `DELETE` están prohibidos por SQL. Se almacenan exclusivamente propósito, ID de solicitud, revisión de caso, motivo tipado (`case_closed`, `case_superseded`, `reviewer_withdrawn`, `authority_withdrawn`), huella SHA-256 de evidencia de invalidación y momento. No JWT/JWS, PII adicional ni contenido de expediente.

El insert valida que la solicitud exista y tenga `institutional_gate_required=1`. Si ya fue aprobada, la revisión informada no puede ser anterior a la que consta en el recibo P2. Esta comprobación **no autentica por sí sola al emisor** de la invalidación: actualmente los tests insertan filas por SQL con D1 en memoria, sin ruta HTTP ni conector institucional.

## Defensa en profundidad y carreras

- **Decisión:** triggers `BEFORE UPDATE OF status` en las solicitudes R2.10/R2.11 rechazan `pending→approved` cuando existe una invalidación, incluso si ésta se insertó después de leer el estado y antes del `D1.batch`. La transacción revierte el diario y los demás cambios de la aprobación.
- **Host sintético:** `requireInstitutionalGate` comprueba el kill switch antes de la consulta externa, incluyendo replays. La invalidación impide nuevas aprobaciones y ejecutores aunque el lector todavía devuelva `open`.
- **Reserva R2.11:** un trigger sobre `processing_manual_redrives` aborta la reserva de una solicitud invalidada, aun si la invalidación se registra entre preflight y la escritura atómica.
- **Después de reservar:** `executeOneShotManualRedrive` repite la consulta D1 inmediatamente antes de enviar a Queue; ante una invalidación deja la reserva en estado `halted` mediante la finalización auditada, **sin llamar a Queue.send**. Ante fallo de lectura D1 no envía y conserva una reserva que exige conciliación manual; nunca reencola automáticamente.

## Límites de seguridad

- No existe entrega de eventos verificada, IdP real, fuente autoritativa, firma del evento, política de retención institucional, ni cuentas D1 de mínimo privilegio. **Nadie debe tratar la inserción manual de una fila como un acto institucional legítimo.** Se debe definir el emisor, su autenticación, autorización, cadena de custodia, validación de revisión/versiones y auditoría en la issue #19 antes de una integración real.
- La comprobación post-reserva reduce la ventana, **pero no es transaccional con Queue.send**. Un cambio externo después del último check o un mensaje ya enviado no puede ser retirado automáticamente. Un futuro sistema operacional necesitará conciliación, protocolo de entrega/confirmación y control del efecto en el consumidor.
- Una revocación R2.10 **ya ejecutada** modifica una denylist irreversible: invalidar posteriormente su aprobación no restaura facultades ni deshace esa revocación. El control bloquea nuevas decisiones/replays, no efectos ya materializados. Un redrive **ya enviado** a Queue tampoco puede retirarse automáticamente.
- Un escritor con facultades de modificar esquema/administrar D1 puede alterar o eliminar los triggers. La separación de privilegios D1 y el gate real Preview siguen bloqueantes.
- Los flujos heredados con `institutional_gate_required=0` conservan compatibilidad de **pruebas sintéticas solamente**. No existe Worker operador ni despliegue nuevo.

## Verificación

El test de ledger fue creado **antes** de la migración (Red: tabla ausente); Green valida unicidad, tipos, alcance y filas inmutables. Los tests del host prueban invalidación de revocación tras preflight pero antes de `D1.batch` (rollback de diario+denegatoria+recibo); invalidación de redrive aprobada antes de reservar; invalidación entre preflight y SQL de reserva (abort atómico); invalidación inmediatamente después de reservar y antes de Queue (estado `halted`, sin send y sin replay que lo eluda).

```sh
pnpm exec vitest run apps/operator/src/institutional-invalidation.test.ts apps/operator/src/async-approval.test.ts apps/operator/src/async-redrive.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42921 sh scripts/ci.sh
```

**Condición de cierre externo:** conectar y acreditar el sistema institucional e IdP, registrar evidencia real bajo autoridad humana, definir permisos e invalidación de datos reales, y aprobar expresamente Preview, cumpliendo CVE independiente. [Issue #19](https://github.com/DawoT/folio-civico/issues/19) permanece abierta.
