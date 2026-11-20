# S01-02 — Auditoría de lecturas multiconsulta y coste del último fence

**Corte:** 2026-11-20. **Estado técnico:** controles nuevos `implemented_local`; pruebas remotas `not_verified`. No acredita `accepted_human`, `verified_preview` ni `released`.

## Hallazgo y corrección

Varias rutas realizan dos o más `await` D1: primero comprueban acceso, después recuperan datos con predicados SQL de membresía. Si esa membresía se revoca **después** del retorno de la última consulta de datos y **antes** de componer la respuesta, podían divulgar un resultado ya obsoleto. Los nuevos tests interceptan la consulta D1 real respaldada por SQLite, obtienen sus filas y entonces modifican la membresía o el rol. No usan temporizadores ni resultados de base falsificados.

| Ruta | Recurso | Fence de respuesta | Efecto |
| --- | --- | --- | --- |
| `GET /api/commissions/:id/documents/:versionId/pages` | Texto inspeccionado | `getCommissionSummary` después de metadata + páginas | Revocación → **404**, D1 final fallida → **503** |
| `GET /api/commissions/:id/checklist` | Checklist | `getCommissionSummary` después de `listChecklist` | Revocación → **404** |
| `GET /api/commissions/:id/observations` | Observaciones recientes | `getCommissionSummary` tras `listObservationDrafts` | Revocación → **404** |
| `GET /api/commissions/:id/observations/history` | Historial paginado | `getCommissionSummary` tras `listObservationPage` | Revocación → **404** |
| `GET /api/commissions/:id/members` | Identificadores y roles de miembros | `getCommissionSummary` posterior al listado | Revocación → **404**, pérdida de presidencia → **403** |
| `GET /api/commissions/:id/batches` | Lotes de comisión | `getCommissionSummary` después de `listCommissionBatches` | Revocación → **404** |

**Compatibilidad:** los miembros activos siguen viendo datos históricos de comisiones cerradas; las restricciones de escritura no cambian. Las consultas iniciales mantienen sus `JOIN commission_members`; el fence es una protección **adicional**, no un reemplazo de los predicados SQL, la verificación JWT ni el aislamiento de comisiones.

**Controles ya integrados anteriormente:** el detalle de observación y el replay de borradores (PR #89), los listados y reintentos documentales con R2 (PR #93) y las exportaciones con revalidación final posterior al hash y evidencia estructural (PR #83).

## Inventario residual y límites

- `GET /api/commissions` y `GET /api/commissions/:id/summary` son consultas de acceso acotadas, sin segunda lectura de datos. No se puede prometer una transacción serializable de todo el tiempo HTTP.
- Las mutaciones de miembros, provisión de lotes/checklist y bootstrap usan predicados de escritura, `D1.batch` e idempotencia. Sus **replays después de cambios de autoridad** requieren una revisión específica y tests de carrera; **no se certifican aquí**.
- Las rutas de procesamiento, outbox, redrive y revocación institucional pertenecen a los gates de seguridad del inspector; su auditoría y liberación están separadas. Ningún cambio de este PR habilita Queue, Containers, PDF ni redrive.
- Un fence solo verifica el estado en el instante de la última consulta. No es una transacción serializable extremo a extremo ni demuestra ausencia de otras condiciones de carrera.

## Coste D1: medición local, no remota

`pnpm exec vitest run tests/d1-access-fence-local.test.ts` mide directamente la consulta de membresía `getCommissionSummary` usando el adaptador **SQLite D1 local**, sin red, con 30 llamadas de calentamiento y 200 muestras. La primera serie observada:

| Métrica | Valor local |
| --- | ---: |
| Consultas D1 adicionales por lectura protegida | **1** |
| Calentamiento | 30 |
| Muestras | 200 |
| Mediana de la consulta de membresía | **0,0324 ms** |
| p95 de la consulta de membresía | **0,0719 ms** |

Estas cifras corresponden al proceso SQLite del host en esta ejecución, **no son latencias de Cloudflare, una comparación de rendimiento end-to-end, un SLO, métricas de usuarios reales ni un cálculo de facturación**. Los números varían entre ejecuciones, no se imponen umbrales temporales. El coste remoto incluirá RTT, ubicación, carga, régimen de D1 y consumo facturable.

**Plan de medición real cuando exista autorización:** disponer de Preview exclusivamente Folio Cívico con Access/MFA y D1 dedicada, ejecutar lecturas sintéticas firmadas con y sin fence de forma controlada (sin debilitar el endpoint productivo), repetir en varias series y registrar percentiles p50/p95 de respuesta, tiempo dedicado a D1, consultas por operación, número de filas leídas y consumo/facturación informado por Cloudflare. Separar calentamiento, errores, región y versión de Worker. Prohibido guardar JWT, nombres reales, documentos o datos de otro producto en logs. Acordar presupuesto y límites antes de ejecutar carga adicional. Cualquier umbral definitivo se establecerá con esa evidencia y evaluación del piloto.

## Evidencia de imposibilidad de Preview

Consulta de solo lectura del conector **`lite_cloudflare_preview(status)`**, el 2026-11-20:

```text
Cloudflare preview is not configured by the operator
```

Lectura de `apps/api/wrangler.jsonc` y `apps/mcp/wrangler.jsonc`: ambos tienen D1 `00000000-0000-0000-0000-000000000000`, con `ACCESS_TEAM_DOMAIN` y `ACCESS_AUD` vacíos. No se ha consultado ni modificado ningún recurso de Cloudflare ajeno al proyecto.

**Gates externos pendientes:** autorización explícita del titular para recursos/costes, cuenta y allowlist exclusivos, D1/R2 privadas reales, hostnames, Access/MFA/OAuth, configuración del operador de Preview, pruebas de revocación con usuarios ficticios sobre D1 remoto y los gates separados de imagen/inspector (G2/G3/G4). Véanse [PREVIEW_CHECKLIST](PREVIEW_CHECKLIST.md) y [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md). Ningún gate queda desbloqueado por CI local.

## Reproducir y revertir

```sh
pnpm exec vitest run apps/api/src/text-routes.test.ts apps/api/src/review-routes.test.ts apps/api/src/member-routes.test.ts apps/api/src/discovery.test.ts
pnpm exec vitest run tests/d1-access-fence-local.test.ts
pnpm typecheck
sh scripts/ci.sh
```

Se requiere TDD Red → Green, `git diff --check` y CI local exit 0 antes de fusionar. **Rollback:** revertir el PR; no hay migraciones ni cambios de bindings.
