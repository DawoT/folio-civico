# F3 · Revalidación de membresía durante exportación

**Estado:** defensa inicial integrada en `main` (`112b195`); cierre adicional de la carrera durante SHA-256 en `fix/f3-hash-revocation-fence`. Sin cambio de contrato HTTP, esquema D1 ni recursos Cloudflare.

## Defecto reproducido

La exportación F3 validaba la identidad del miembro al obtener los metadatos de una comisión y repetía el filtro de membresía activa dentro de la consulta de observaciones. Sin embargo, si la membresía se revocaba **durante o después** de esa consulta, el flujo podía devolver la respuesta `200` usando el resumen anterior:

- Con **cero registros finalizados**, exponía el nombre y estado de la comisión después de la revocación.
- Con **registros finalizados ya consultados**, podía devolver también títulos, descripciones, revisores y evidencias tras perder el permiso.

La respuesta no se cachea, pero `Cache-Control: no-store` no revoca autorización.

## Corrección

`collectFinalizedReviews` ejecuta una segunda comprobación de `getCommissionSummary(db, subject, commissionId)` **después de la consulta de observaciones** y antes de formar la colección. Si ya no existe membresía activa, devuelve `null` y la API retorna `404` genérico, sin descarga ni metadatos. Si persiste la autorización, el resumen final se toma de esa consulta.

**Cierre de la carrera durante hashing:** `handleReviewExportRequest` calcula el SHA-256 mediante WebCrypto, que es asíncrono y permite una nueva revocación después de la comprobación anterior. Por eso revalida la membresía **después de `crypto.subtle.digest` y justo antes de crear la respuesta**, sin nuevas operaciones asíncronas entre ese último control y la entrega. Una revocación durante el hash produce `404`, sin archivo ni cabecera SHA-256.

**Semántica preservada:** lectores autorizados siguen descargando informes completos (incluidos informes vacíos), las comisiones cerradas permanecen legibles para miembros activos, y los límites de 500 registros/8 MiB, el SHA-256 exacto y el verificador offline no cambian.

## Evidencia y límites

TDD **Red→Green**: tres fallos reproducidos para la carrera de consulta (exportación vacía, exportación con hallazgos y endpoint API). Además, una cuarta regresión reproduce la revocación mientras termina `crypto.subtle.digest`: **Red `200` en vez de `404`; Green `404`**. Las pruebas usan consultas D1 reales y revocaciones intercaladas, sin simular autorizaciones positivas. Las dos suites de exportación aprueban **11/11** pruebas y el typecheck es verde.

El control minimiza la ventana de desautorización, pero no puede retirar una descarga entregada **antes** de la revocación ni sustituye permisos D1 segregados. Una revocación que ocurra después de la última comprobación y después de generada la respuesta exige controles de sesión, transporte y custodia del entorno autorizado. No se considera evidencia de IdP/MFA institucional.

## Verificación local

```sh
pnpm exec vitest run packages/data/src/review-export.test.ts apps/api/src/review-export-routes.test.ts
pnpm typecheck
FOLIO_E2E_PORT=42940 sh scripts/ci.sh
```

**Verificación:** `FOLIO_E2E_PORT=42944 sh scripts/ci.sh`, **exit 0**, sobre `origin/main` `1a27026` con los fixtures de fecha corregidos por PR #48 y el gate local de demo aislado por PR #49. **496 Vitest + 210 Python inspector + 9 contratos CI + 33 UX5 + 5 workerd + 129 Chromium + 1 E2E de demo con API/JWT local = 883/883**; typecheck, builds/dry-runs y 30 migraciones D1 exclusivamente locales. Antes se detectaron dos fallos de fixtures basados en `CURRENT_TIMESTAMP` ajenos a F3, corregidos concurrentemente y preservados sin duplicar. El log Chromium contiene errores transitorios de proxy local, pero todas las pruebas terminaron en verde.

**Nueva verificación del cierre de hashing (2026-11-20):** `sh scripts/ci.sh` en `fix/f3-hash-revocation-fence`, **exit 0, 884/884**: 497 Vitest + 210 Python inspector + 9 contratos CI + 33 UX5 + 5 workerd + 129 Chromium + 1 E2E de demo. Typecheck, builds/dry-runs y 30 migraciones D1 locales aprobados; sin cambios de infraestructura ni autorización de despliegue.

GitHub Actions **está disponible**: el workflow `.github/workflows/ci.yml` delega en el mismo `sh scripts/ci.sh`; su [ejecución #44745464491](https://github.com/DawoT/folio-civico/actions/runs/44745464491) sobre `main` `1477ffee` concluyó en verde antes del cierre adicional de hashing. La aprobación de CI no autoriza Preview ni sustituye el gate CVE del inspector o la [issue institucional #19](https://github.com/DawoT/folio-civico/issues/19).
