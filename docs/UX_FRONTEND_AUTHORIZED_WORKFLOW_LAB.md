# PERF-004 — Laboratorio de recorrido de revisión con rol sintético

**Corte inicial:** 2026-11-20. **Base de implementación:** `origin/main@6fdc1f9`.
**Ámbito:** frontend **compilado para producción** servido con `vite preview` en `127.0.0.1`. Chromium de Playwright con contexto nuevo por repetición; navegador 1366×900, es-PE, sin throttling.
**Modelo de autoridad:** `SyntheticPilotApi`, con comisión y permisos **simulados**. **NO** se verifica Cloudflare Access, JWT remoto, RBAC del Worker ni datos de personas.

## Qué verifica exactamente

`tests/performance/workflow.spec.ts` ejecuta **tres veces** con un contexto de Chromium nuevo y una instancia nueva de la API sintética. El usuario sintético tiene el rol de revisor de la comisión. Cada fixture determinista de ensayo contiene una comisión, un lote, un documento PDF **solo representado por metadatos** en estado de cuarentena y **40 observaciones históricas sintéticas**. No carga, interpreta ni transfiere PDF original alguno.

El test espera realmente los resultados DOM antes de dar por completada cada fase:

| Etapa | Criterio de finalización |
| --- | --- |
| Descubrimiento | La comisión sintética aparece en el selector después de consultar `/api/commissions` |
| Apertura de lote | Se consultan documentos, checklist e historial; el detalle del documento está visible y hay **25** observaciones iniciales |
| Historial | Se solicita una segunda página mediante cursor y se muestran **40** observaciones; la más antigua está visible |
| Detalle | Se abre una observación de la segunda página y aparece su panel de detalle |

Para cada fase se mide `performance.now()` de **Node.js** alrededor de acciones de Playwright y comprobaciones de visibilidad. Por tanto son **duraciones extremas de automatización**: incluyen control remoto del navegador, respuestas del fixture, React y espera por estados de UI. **No son tiempos puros de render, INP, latencia real de Worker, tiempos humanos ni SLO.**

La validación falla si faltan las 25/40 filas, la paginación por cursor, el documento, el checklist, los assets `/assets/` de producción o el detalle. También falla si se detecta alguna petición HTTP externa, respuesta API de error o mutación HTTP (el flujo es de solo lectura), si algún tiempo es inválido o si hay menos de **tres recorridos completos**. Ninguna métrica ausente se sustituye por cero.

## Baseline inicial observado

Medianas de tres recorridos locales del build, antes de aplicar limitaciones de red y CPU:

| Etapa | Mediana |
| --- | ---: |
| Descubrimiento de comisión | 109,14 ms |
| Abrir lote con documento, checklist e historial inicial | 127,41 ms |
| Solicitar segunda página de historial | 66,49 ms |
| Abrir detalle de observación histórica | 60,28 ms |

Los números son orientativos. Su valor es detectar roturas de estados y disponer de un punto de comparación local; no se impone un presupuesto temporal porque el host y los tiempos propios de Playwright son variables.

## Reproducción y gate

```sh
pnpm install --frozen-lockfile
pnpm --filter @folio/web build
pnpm test:performance

# Para múltiples worktrees, usar un puerto local libre
FOLIO_PERF_PORT=4519 pnpm test:performance

# Gate local completo (incluye PERF-001, PERF-002, PERF-003 y PERF-004)
sh scripts/ci.sh
```

PERF-004 se ejecuta **dentro del comando `test:performance` que ya forma parte de `scripts/ci.sh`**, sin otra configuración ni dependencia. Mantiene `reuseExistingServer: false` y `--strictPort`, al igual que PERF-002. El resumen de CI contiene únicamente agregados numéricos, sin detalles de ruta, actores, identificadores o documentos.

## No acreditado

- **Lighthouse del flujo autorizado:** PERF-003 sigue auditando el shell público no autenticado; este ensayo usa Playwright, **no Lighthouse**. Una auditoría Lighthouse con fixture de backend seguro y estado autorizado es trabajo diferente.
- **Backend real:** PERF-004 usa una doble sintética en el navegador. [PERF-005](UX_FRONTEND_SIGNED_API_LAB.md) añade por separado un recorrido de consulta de lote con handler real, JWT RS256 y SQLite local; **no** mide Access, D1 ni R2 desplegados.
- **Interacción real:** no hay INP, RUM, percentiles de usuarios ni tiempos de personal institucional. No hay consentimiento ni sesiones humanas en este experimento.
- **Accesibilidad y seguridad:** siguen pendientes pruebas manuales NVDA/VoiceOver/zoom, autorización institucional, gates propios del inspector y validaciones de Cloudflare remotas.

Este avance no modifica APIs productivas, autorización, inspector ni política de despliegue.
