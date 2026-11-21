# Evidencia de fallos Playwright en GitHub Actions

**Alcance:** pruebas sintéticas en el CI de Folio Cívico, no entorno institucional ni producción. **Motivo:** issue #87 (timeout de desplazamiento en la navegación «Registrar búsqueda»). Fecha: 2026-11-20.

## Contrato de diagnóstico

`.github/workflows/ci.yml` ejecuta `sh scripts/ci.sh` sin alterar los gates. Si la ejecución falla, el paso `Preserve synthetic Playwright failure evidence` intenta conservar exclusivamente los archivos `test-results/task-navigation-*/task-anchor-diagnostics.json`, `trace.zip` y capturas del recorrido sintético de navegación mediante `actions/upload-artifact@v4`, con nombre único por run/attempt y **retención de 3 días**. Si el fallo ocurre antes de Playwright y no hay resultados, la ausencia de archivos **no convierte el CI rojo en verde**.

`playwright.config.ts` conserva las trazas **solo cuando falla la prueba** (`trace: "retain-on-failure"`) y genera capturas **solo en fallo** (`screenshot: "only-on-failure"`). No se cambia el timeout, no se fuerzan clics, no se omiten casos y no se introducen reintentos automáticos. Los artefactos pueden descargarse desde la ejecución específica en GitHub Actions, mientras estén disponibles; usar el SHA, run, proyecto, caso y posición del fallo para correlacionar evidencias.

El directorio general `test-results/` también recibe fallos de performance y la demo local firmada; **esos archivos se excluyen expresamente** de la subida. El artefacto contiene únicamente fallos de `task-navigation-*` con API sintética, no pruebas con JWT local. Sus coordenadas y muestras de scroll/layout se generan sin texto de expedientes, URLs completas ni cabeceras. El contenido sirve como **diagnóstico de un fallo**, no como certificación de UX o rendimiento.

## Riesgos y privacidad

- El CI actual utiliza API simulada, demo local, claves firmadas de laboratorio, SQLite local y **ningún documento institucional**. **No incorporar secretos, cookies reales, credenciales personales, datos sensibles o URLs de Preview/producción** a estas suites: las trazas Playwright pueden registrar solicitudes, cabeceras y DOM.
- Si en el futuro se agregan credenciales reales o conectores externos al CI, revisar la captura y sus permisos de acceso **antes** de conservar estos artefactos. La retención de tres días limita exposición temporal, pero no sustituye control de acceso, minimización ni revisión de contenido.
- No cargar `.dev.vars`, `.env`, datos institucionales, `playwright-report/`, trazas de la demo firmada ni archivos fuera de los patrones `test-results/task-navigation-*`. La carpeta permanece ignorada por Git y no se publica en releases.
- El job continúa fallando cuando falla `scripts/ci.sh`. Esta mejora es **observabilidad**, no permiso para fusionar PR, saltar gates o desplegar recursos.

## R1.48 — muestreo de geometría durante el clic (21-11-2026)

La incidencia histórica `#87` no se reprodujo de manera aislada: **12/12**
recorridos de navegación con anclas nativas en Chromium desktop y **12/12**
en reflow 320 px, usando `--repeat-each=12` y el `actionTimeout` de 8 s
sin modificaciones. El run original `44782865732` acabó en verde en su
segundo intento y no publica artefactos de diagnóstico. Esta ausencia de
fallos **no demuestra** una causa raíz resuelta; no se alteraron React, CSS,
timeouts, reintentos, ni la semántica del clic nativo.

La instrumentación sintética de `task-navigation-diagnostics.ts` conserva
las muestras previas de scroll y layout shift y añade **hasta 32** muestras
de geometría *durante* cada `locator.click()` real. Captura una posición
inicial síncrona y, cuando Chromium permite animación, una muestra como
máximo cada 80 ms: tiempo monotónico, `scrollY`, coordenadas verticales
de navegación/enlace/sección. La observación se desactiva al completar o
fallar la acción; ninguna muestra se sube en el camino verde.

Solo el fallo origina un adjunto JSON sintético; no se leen ni conservan
texto DOM, identificadores de usuarios, cookies, URLs completas ni cabeceras.
El buffer numérico es acotado y no toca el estado del producto. Una página
en segundo plano puede limitar los callbacks de `requestAnimationFrame`;
la muestra inicial sigue existiendo, pero su ausencia de cambios **no prueba**
que el navegador estuviera inmóvil. Sigue siendo necesario correlacionar
el registro con una traza real para atribuir causas.

TDD: el test de fallo intencionado de clic nativo se volvió rojo al exigir
`geometrySamples` ausentes, y pasó al instalar la captura acotada. Otra
prueba verifica que aparecen mediciones durante el scroll y que las muestras
no contienen sentinelas privadas. El issue permanece abierto hasta reproducir
la anomalía real o acumular evidencia que justifique su cierre.

## Próximo incidente #87

Si reaparece el timeout en `task-navigation.spec.ts`, guardar el SHA/run y consultar el artefacto durante los tres días siguientes. Contrastar `task-anchor-diagnostics.json` (scroll, rectángulos y layout shift) con la traza de Chromium desktop: elemento estable, desplazamiento, posición y cambios de layout durante el clic. Contrastar con Chromium móvil y reflow 320, y reproducir con datos sintéticos antes de corregir código. No cerrar el issue por una corrida posterior verde sin explicar la causa o documentar la incertidumbre.

**Limitación:** todavía no se ha provocado un fallo Playwright dentro de GitHub Actions para confirmar una descarga real del artefacto. Los tests del workflow comprueban su configuración; la validación material del artefacto depende del próximo fallo y permisos de GitHub.
