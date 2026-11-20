# PERF-005 — Frontend compilado con API local real y JWT firmado

**Corte:** 2026-11-20. **Base inicial:** `origin/main@03ced86`.
**Objetivo:** medir la apertura de una comisión de ejemplo usando **el `handleApiRequest` de producción**, autenticado con JWT RS256 firmado en el servidor local y con membresía verificada contra el adaptador SQLite de D1, mientras el navegador ejecuta los **assets Vite compilados**.

## Diseño del laboratorio

`pnpm test:demo:performance` inicia una instancia nueva de la demo local, exclusivamente en `127.0.0.1`, con `reuseExistingServer: false`. La demo configura `handleApiRequest` real mediante Vite SSR, genera un par RS256 temporal, emite tokens con los claims esperados por el validador Access y sirve el JWKS local. La DB es SQLite desechable; R2 es una estructura en memoria. **No hay Cloudflare remoto, identidad institucional ni servicio del inspector.**

El frontend se compila previamente con `pnpm --filter @folio/web build`. Una ruta de Playwright **sustituye únicamente** el documento HTML y los recursos JS/CSS compilados procedentes de `apps/web/dist`; las solicitudes `/api/**` se **continúan sin responderlas ni falsificarlas** desde Playwright. No se modifica el servidor productivo ni se añade un servidor estático alternativo. Esta distinción importa: el navegador ejecuta código compilado, pero su entrega HTML/assets es un fixture de pruebas y **no mide la latencia de un CDN o Worker desplegado**.

Tres contextos nuevos de Chromium efectúan un recorrido de solo lectura, cada uno con una cookie HttpOnly de rol ficticio `reviewer`. Para cada recorrido se comprueban la sesión autenticada `/api/session`, la pertenencia real `/api/commissions`, la comisión en el selector, el documento inicial en cuarentena, los **dos ítems del checklist** y la huella SHA-256 de la versión. El backend no recibe mutaciones durante el recorrido: todos los objetos se precargan **antes** de iniciar las mediciones.

La validación falla si faltan artefactos de producción, archivos JS/CSS, existe un symlink en assets, el rol o membresía no corresponde, no se muestra el documento o el checklist, falta la petición de documentos, hay errores HTTP en API, solicitudes externas, mutaciones, menos de cinco lecturas API del navegador o alguna duración inválida. El comando exige **tres recorridos** y solo imprime la mediana, no las rutas, roles ni documentos.

## Mediciones y límites

| Etapa | Fuente de tiempo | Mediana de la primera serie |
| --- | --- | ---: |
| Descubrir comisión | Tiempo de Node.js alrededor de Playwright y React | 117,05 ms |
| Abrir lote, checklist y detalle documental | Tiempo de Node.js alrededor de Playwright y React/SQLite | 134,74 ms |
| Consulta firmada de sesión | Tiempo de `context.request.get` a `/api/session` | 5,21 ms |
| Petición de listado documental | `request.timing().responseEnd` observado por Chromium | 22,81 ms |

Son **duraciones de laboratorio sin throttling**, influidas por la carga del host, SQLite en memoria y la automatización de Playwright. No son INP, latencias de Cloudflare Access, métricas de campo ni tiempos humanos. No se impone un umbral temporal artificial hasta tener varias series en hardware controlado.

## Procedimiento

```sh
pnpm install --frozen-lockfile
pnpm --filter @folio/web build
pnpm test:demo:performance

# Ejecutar en un worktree paralelo usando un puerto libre
FOLIO_DEMO_PORT=55316 pnpm test:demo:performance

# Gate obligatorio, que incluye esta prueba y la demo funcional independiente
sh scripts/ci.sh
```

El E2E funcional `pnpm test:demo` permanece separado: no exige un build previo y sigue comprobando autoría, revisión independiente y exportación JSON. PERF-005 se añade después de esa prueba a `scripts/ci.sh`, antes de las migraciones D1 locales. Fallar PERF-005 impide emitir `CI PASSED`.

## Pendientes

- **No es Access remoto:** la firma y verificación JWT ocurren localmente con claves efímeras; la prueba no acredita ni activa Cloudflare Access/MFA real.
- **No es D1/R2 remoto ni procesado de PDF:** se usa el adaptador SQLite y una colección de objetos en memoria; el documento permanece en cuarentena.
- **No es Lighthouse del workflow autenticado:** PERF-003 sigue auditando el shell local sin iniciar sesión. Un escenario de Lighthouse autenticado con backend seguro es un experimento aparte.
- **No es investigación humana:** siguen pendientes UX-5.6 con participantes autorizados, NVDA/VoiceOver, zoom nativo, INP/RUM y aprobación institucional independiente.

Este control es evidencia técnica local, no un desbloqueo de seguridad, inspección documental ni producción.
