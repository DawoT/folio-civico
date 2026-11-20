# F3 · Revalidación de membresía durante exportación

**Estado:** cambio local de seguridad en exportación JSON de revisiones; sin cambio de API, esquema D1 ni recursos Cloudflare.

## Defecto reproducido

La exportación F3 validaba la identidad del miembro al obtener los metadatos de una comisión y repetía el filtro de membresía activa dentro de la consulta de observaciones. Sin embargo, si la membresía se revocaba **durante o después** de esa consulta, el flujo podía devolver la respuesta `200` usando el resumen anterior:

- Con **cero registros finalizados**, exponía el nombre y estado de la comisión después de la revocación.
- Con **registros finalizados ya consultados**, podía devolver también títulos, descripciones, revisores y evidencias tras perder el permiso.

La respuesta no se cachea, pero `Cache-Control: no-store` no revoca autorización.

## Corrección

`collectFinalizedReviews` ejecuta una segunda comprobación de `getCommissionSummary(db, subject, commissionId)` **después de la consulta de observaciones** y antes de formar el contenido de la respuesta. Si ya no existe membresía activa, devuelve `null` y la API retorna `404` genérico, sin descarga ni metadatos. Si persiste la autorización, el resumen final se toma de la segunda consulta. No hay operaciones asíncronas entre esta última comprobación y el retorno.

**Semántica preservada:** lectores autorizados siguen descargando informes completos (incluidos informes vacíos), las comisiones cerradas permanecen legibles para miembros activos, y los límites de 500 registros/8 MiB, el SHA-256 exacto y el verificador offline no cambian.

## Evidencia y límites

TDD **Red→Green**: tres fallos reproducidos (exportación vacía, exportación con hallazgos y endpoint API que devolvía `200` cuando la membresía se revocaba intercalada justo después de consultar los registros). Las pruebas usan las consultas D1 reales y ejecutan la revocación entre la obtención de filas y la respuesta, sin simular autorizaciones positivas. Green y regresiones de exportación + typecheck.

El control minimiza la ventana de desautorización, pero no puede retirar una descarga entregada **antes** de la revocación ni sustituye permisos D1 segregados. Una revocación que ocurra después de la última comprobación y después de generada la respuesta exige controles de sesión, transporte y custodia del entorno autorizado. No se considera evidencia de IdP/MFA institucional.

## Verificación local

```sh
pnpm exec vitest run packages/data/src/review-export.test.ts apps/api/src/review-export-routes.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42940 sh scripts/ci.sh
```

GitHub Actions no constituye el gate. Los bloqueos de [Preview](PREVIEW_CHECKLIST.md), el gate CVE del inspector y la [issue institucional #19](https://github.com/DawoT/folio-civico/issues/19) permanecen vigentes.
