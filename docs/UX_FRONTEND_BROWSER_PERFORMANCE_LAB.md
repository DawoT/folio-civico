# PERF-002 — Laboratorio Chromium de rendimiento frontend

**Fecha:** 2026-11-20 · **Base inicial:** `main@573f323` (PERF-001 integrado).
**Ámbito:** frontend compilado con Vite, servido por `vite preview` sobre `127.0.0.1`.
**Autorización:** solo local; sin Cloudflare, expedientes reales ni servicios externos.

## Qué mide y qué no

`pnpm test:performance` arranca el frontend de producción compilado en un **servidor nuevo** (sin reutilización, puerto estricto configurable con `FOLIO_PERF_PORT`; por defecto `4178`). Chromium carga la pantalla inicial en **tres contextos de navegador nuevos**, cada uno sin caché HTTP ni cookies previas. Una API sintética satisface las peticiones de la UI, de modo que **no** se miden latencias institucionales ni permisos remotos.

Se capturan métricas reales desde Performance API y PerformanceObserver:

- **TTFB (ms):** `PerformanceNavigationTiming.responseStart` desde el origen de navegación.
- **FCP (ms):** evento nativo `first-contentful-paint`.
- **LCP (ms):** último `largest-contentful-paint` observado tras el render inicial.
- **CLS:** suma de `layout-shift` sin entrada reciente del usuario, desde el inicio hasta la captura.

El resultado muestra la **mediana de tres navegaciones**, y el gate exige números finitos no negativos y los eventos reales de FCP/LCP. Si el navegador no soporta los observadores, faltan los assets de producción, se intenta acceder a otra red, se ocupa el puerto o falta una métrica, el test **falla**. Nunca reemplaza métricas ausentes por cero.

## Línea base de laboratorio (captura inicial)

`pnpm --filter @folio/web build && pnpm test:performance`, Chromium incluido con Playwright, vista 1366×900, idioma es-PE, loopback, **sin throttling** de CPU/red, tres contextos fríos y API sintética:

| Métrica | Mediana inicial | Uso permitido |
| --- | ---: | --- |
| TTFB | 2,5 ms | Referencia local de navegación, no latencia de Worker/Access |
| FCP | 88 ms | Diagnóstico de primer contenido renderizado |
| LCP | 88 ms | Diagnóstico de mayor elemento visible al cargar |
| CLS | 0 | Diagnóstico de desplazamientos observados durante esta ventana |

Los valores pueden variar por máquina, carga, versión de navegador, sistema operativo y fixture. Se documentan **sin imponer un umbral temporal** antes de contar con varias series en un perfil de hardware estable. No comparar automáticamente estos números con los umbrales públicos de Core Web Vitals ni convertirlos en una puntuación Lighthouse.

## Reproducir

```sh
pnpm install --frozen-lockfile
pnpm --filter @folio/web build
pnpm test:performance

# Para worktrees paralelos: puerto libre diferente
FOLIO_PERF_PORT=4519 pnpm test:performance

# Gate de integración completo, también incluye PERF-001
sh scripts/ci.sh
```

`scripts/ci.sh` ejecuta PERF-001 (presupuesto gzip) y luego PERF-002 (laboratorio Chromium). La ejecución no utiliza GitHub Actions, telemetría remota ni despliegues. El reporte solo publica medianas numéricas, sin sujetos, rutas privadas ni contenido documental.

## Pendiente, no acreditado

- **Lighthouse:** [PERF-003](UX_FRONTEND_LIGHTHOUSE_LAB.md) ya ejecuta tres auditorías móviles sobre el shell inicial no autenticado con simulación de red/CPU. Aún no hay Lighthouse de un flujo autorizado ni perfil de hardware profesional o umbrales temporales validados.
- **Core Web Vitals de campo:** no hay RUM, usuarios reales, percentiles de población ni INP medido. La medición inicial de LCP/CLS **no** equivale a Core Web Vitals de producción.
- **Flujos completos:** PERF-002 mide **la primera navegación a la pantalla inicial**; [PERF-004](UX_FRONTEND_AUTHORIZED_WORKFLOW_LAB.md) mide por separado un recorrido sintético de apertura de lote, paginación de 40 observaciones y detalle. Aún faltan tiempos de subida, revisión con backend firmado, exportación real y latencia del API.
- **UX-5.6 humana:** siguen pendientes las sesiones moderadas, NVDA, VoiceOver y zoom nativo.

El presupuesto de bytes (PERF-001) sigue siendo el gate cuantitativo de rendimiento; PERF-002 es un gate de **disponibilidad y validez de instrumentación**, no un nuevo SLO temporal.
