# R2.12b/P6 · Barrera SQL transaccional para facultades del consumidor

**Estado:** preparado exclusivamente para pruebas sintéticas D1 locales. No implica un emisor institucional autenticado, MFA real, Worker operador desplegado, permisología D1 remota ni aprobación de Preview. La [issue institucional #19](https://github.com/DawoT/folio-civico/issues/19) y el gate independiente CVE siguen bloqueantes.

## Riesgo reproducido (Red)

R2.12b/P5 ya ata cada mensaje manual a una reserva opaca D1 y consulta las revocaciones R2.7 y la expiración antes de la inspección y publicación. Sus triggers de migración `0028` cubren exclusivamente la **invalidación del expediente institucional**. Si una autorización R2.7 se retiraba, la aprobación R2.11 caducaba, o la reserva pasaba a `halted` **entre la última consulta del consumidor y el batch D1**, el informe todavía podía quedar admitido. Una vez admitidas las páginas, un control de solo lectura no puede deshacer esa exposición.

TDD Red: **9 casos adversariales fallaron** antes del esquema P6: siete objetivos de revocación, carrera de revocación de aprobador justo antes de `D1.batch` y transición a `halted`. Los tests comprueban ambas vías de escritura (`document_processing_reports` y el estado de `document_versions`), y que no queden páginas, informe, transición ni auditoría parcial.

## Implementación (Green)

La migración **`0029_redrive_consumer_authority_atomic_fence.sql`** añade la vista de consulta `processing_redrive_consumer_denials` que clasifica la versión como no autorizada en el momento **de la escritura D1** si existe una reserva manual y se cumple cualquiera de estas condiciones:

- Reserva fuera de `reserved|sent|uncertain` (incluido `halted`).
- Solicitud R2.11 vinculada sin estado `approved`, sin coincidencia de SHA-256 de aprobación, caducada según `unixepoch()`, o sin recibo P2 cuando el gate institucional fue marcado.
- Revocación inmutable R2.7: operador solicitante o aprobador, referencia, digest de atestación, digest de imagen y huellas de claves de aprobación/liberación.

Dos triggers `BEFORE` reutilizan la **misma vista** y abortan con `REDRIVE_CONSUMER_AUTHORITY_DENIED` cualquier `INSERT` de informe o `UPDATE` hacia `ready/needs_review`. Esto complementa los triggers P5 para invalidaciones institucionales; ninguno se sustituye. Como el trigger corre dentro de la transacción de admisión, la carrera observada después del último preflight aborta la operación completa. La ruta de consumidor P5 detecta que ahora la autoridad está revocada, clasifica el mensaje como `stale` y no lo reencola; un fallo de consulta D1 distinto permanece en retry, nunca bypass.

**La vista no concede acceso:** las filas resultantes son usadas solamente por triggers D1 y no se expone una API nueva. Los mensajes originales de outbox sin reserva manual conservan su semántica anterior. No se añade Queue, crons, secreto ni vínculo Cloudflare.

## Pruebas y límites

- Red→Green de **7 clases de revocación** (incluye el aprobador independiente), bloqueadas en inserción de informes y transición del estado 422.
- Revocación intercalada después de verificar acceso pero antes de `db.batch`: rollback de informe, páginas, estado `ready` y auditoría, con retorno `stale`.
- Reserva marcada `halted` antes de materializar un informe, rechazo SQL incluso desde un escritor no consciente del mensaje Queue.
- **Caducidad**: adelantando exclusivamente el reloj `unixepoch()` de SQLite en un fixture local tras emitir la aprobación, se prueban ambas escrituras después del TTL, sin manipular ni relajar los triggers de autorización.
- Compatibilidad de los casos existentes del procesador, redrive R2.5/R2.11 e invalidación institucional P5. No se interpreta el reloj simulado como precisión temporal entre Cloudflare y el proveedor externo.
- Permanece la ausencia de transacción global `Queue ↔ D1 ↔ institución`. Si el informe ya se confirmó **antes** de la revocación, no se elimina. Si un documento ya salió hacia el inspector antes de la revocación, P6 no puede retirarlo. Una autoridad con permisos administrativos D1 puede alterar triggers/vistas; se exige separación y auditoría de privilegios real.
- P6 es una capa **negativa** sobre un flujo local, no una validación del IdP, roles reales, MFA, huella de contenedor ni de la identidad del escritor. No sustituye la revisión jurídica, custodia, políticas de retención y gate CVE.

## Gate técnico

```sh
pnpm exec vitest run apps/processor/src/manual-redrive-fence.test.ts apps/processor/src/consumer.test.ts packages/data/src/manual-redrive.test.ts apps/operator/src/async-redrive.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42930 sh scripts/ci.sh
```

**Cierre externo:** [issue #19](https://github.com/DawoT/folio-civico/issues/19) solo puede cerrarse con la fuente institucional y sesiones IdP/MFA realmente verificadas, roles D1 segregados, eventos auditados, conciliación de efectos y autorización explícita Preview/CVE.
