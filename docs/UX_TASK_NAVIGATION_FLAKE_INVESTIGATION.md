# CI / IA-001 · Diagnóstico de scroll en navegación por anclas (issue #87)

**Fecha:** 2026-11-20. **Estado:** diagnóstico preventivo de un fallo intermitente; **causa raíz no demostrada**.

## Señal original

El run GitHub Actions `44782865732` sobre `main@bebb2f6` registró
`locator.click: Timeout 8000ms exceeded` al pulsar el anchor nativo
«Registrar búsqueda» después de «Checklist» en Chromium desktop. La prueba
encontraba el enlace visible/habilitado/estable; Playwright seguía intentando
desplazarlo al viewport. **131/132** pruebas de navegador aprobaron.
La recuperación posterior del CI no prueba eliminación de la intermitencia.

## Contrapruebas y límites

- Un agente ejecutó **10/10** repeticiones desktop del recorrido en una rama
  anterior, sin reproducir el defecto (comentario de la issue #87).
- Sobre `main@6a31192`, se ejecutó con `CI=true`, Chromium real, origen local
  aislado y `--repeat-each=12` en desktop y 320 px:
  **72/72** pruebas del archivo, que contienen **24/24** recorridos de autor.
  El timeout **no se reprodujo**.
- Tras instrumentar la prueba se ejecutó `--repeat-each=5` en desktop,
  móvil Pixel 7 y 320 px: **60/60** pruebas, incluyendo el smoke de
  geometría/scroll y cinco recorridos de autor por viewport.
- El primer CI completo descubrió un fallo solo en el smoke móvil de
  telemetría (**134/135 Chromium**): el contenido sintético de 1500 px no
  garantizaba scroll en un viewport móvil escalado. Se elevó **solo la
  altura del fixture sintético** a 10 000 px; la CI completa repetida aprobó.
- **CI integral local final, exit 0:** 551 Vitest + 364 Python inspector +
  17 contratos CI + 33 UX5 + 2 Chromium PERF + 5 workerd +
  135 Chromium E2E + 1 demo + 1 demo PERF = **1109/1109**;
  Lighthouse móvil 3/3 informes reales, typecheck, builds/dry-runs,
  presupuesto de bundle y migraciones D1 locales.
- Ninguna de estas ejecuciones representa una repetición determinista de la
  carga, hardware o versión exactos del runner fallido de GitHub.

## Instrumentación no invasiva

El caso `tests/browser/task-navigation.spec.ts` conserva los seis anchors
nativos y el timeout de acción de **8 segundos**, sin `force`, dispatch
artificial, `skip` ni cambios en CSS o UX. Solo cuando una acción
falla, `task-navigation-diagnostics.ts` escribe
`task-anchor-diagnostics.json` y repropaga el **error original**.

El JSON incluye el anchor/id de un fixture fijo, el paso, duraciones,
rectángulos de navegación/objetivo, viewport, `window.scrollY`, altura
documental, `scroll-behavior`, cantidad de animaciones en curso,
muestras recientes de desplazamiento y `layout-shift`. **No contiene**
texto del DOM, documentos, rutas de origen completas, tokens, cabeceras,
cookies ni payloads. Las mediciones se obtienen mediante observadores pasivos
con un máximo de 64 eventos por tipo y no afectan a la aplicación real.

El workflow `.github/workflows/ci.yml` conserva únicamente
`test-results/task-navigation-*/task-anchor-diagnostics.json`, traces y
capturas de la suite sintética de navegación **si falla** el job; retención
**3 días**. No publica `test-results/**` ni artefactos de la demo con JWT.

## Interpretación de la próxima falla

1. Comprobar SHA exacto, Chromium/Node de runner, acción y tamaño de viewport.
2. Comparar `before`/`after`, altura documental y coordenadas del anchor.
3. Inspeccionar `scrollSamples` y `shiftSamples` para distinguir
   desplazamiento que no se estabiliza, reflow sostenido o pausa del runner.
4. Abrir trace de **navegación sintética exclusivamente** para verificar
   la secuencia de eventos y la posible superposición.
5. Reparar solo la causa observada. No concluir error de producto ni
   cerrar #87 mientras solo haya resultados verdes intermitentes.

## Comandos locales

```sh
pnpm exec playwright test tests/browser/task-navigation.spec.ts \
  --project=chromium-desktop --repeat-each=12
pnpm exec playwright test tests/browser/task-navigation.spec.ts \
  --project=chromium-reflow-320 --repeat-each=12
pnpm typecheck
sh scripts/ci.sh
```

Para worktrees concurrentes, establecer un `FOLIO_E2E_PORT` libre.
Las pruebas usan API sintética; no hay datos institucionales ni servicios
remotos activados.
