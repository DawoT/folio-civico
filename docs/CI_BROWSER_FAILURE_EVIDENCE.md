# Evidencia de fallos Playwright en GitHub Actions

**Alcance:** pruebas sintéticas en el CI de Folio Cívico, no entorno institucional ni producción. **Motivo:** issue #87 (timeout de desplazamiento en la navegación «Registrar búsqueda»). Fecha: 2026-11-20.

## Contrato de diagnóstico

`.github/workflows/ci.yml` ejecuta `sh scripts/ci.sh` sin alterar los gates. Si la ejecución falla, el paso `Preserve synthetic Playwright failure evidence` intenta conservar exclusivamente `test-results/` mediante `actions/upload-artifact@v4`, con nombre único por run/attempt y **retención de 3 días**. Si el fallo ocurre antes de Playwright y no hay resultados, la ausencia de archivos **no convierte el CI rojo en verde**.

`playwright.config.ts` conserva las trazas **solo cuando falla la prueba** (`trace: "retain-on-failure"`) y genera capturas **solo en fallo** (`screenshot: "only-on-failure"`). No se cambia el timeout, no se fuerzan clics, no se omiten casos y no se introducen reintentos automáticos. Los artefactos pueden descargarse desde la ejecución específica en GitHub Actions, mientras estén disponibles; usar el SHA, run, proyecto, caso y posición del fallo para correlacionar evidencias.

El directorio `test-results/` puede recibir fallos de otras suites Playwright sintéticas ejecutadas por el mismo script (performance, navegador, demo local firmada); no se puede afirmar que corresponda siempre a `test:browser`. El nombre del artefacto lo marca como **sintético** y su contenido como **diagnóstico de un fallo**, nunca como certificación de UX o rendimiento.

## Riesgos y privacidad

- El CI actual utiliza API simulada, demo local, claves firmadas de laboratorio, SQLite local y **ningún documento institucional**. **No incorporar secretos, cookies reales, credenciales personales, datos sensibles o URLs de Preview/producción** a estas suites: las trazas Playwright pueden registrar solicitudes, cabeceras y DOM.
- Si en el futuro se agregan credenciales reales o conectores externos al CI, revisar la captura y sus permisos de acceso **antes** de conservar estos artefactos. La retención de tres días limita exposición temporal, pero no sustituye control de acceso, minimización ni revisión de contenido.
- No cargar `.dev.vars`, `.env`, datos institucionales, `playwright-report/` ni archivos fuera de `test-results/`. La carpeta permanece ignorada por Git y no se publica en releases.
- El job continúa fallando cuando falla `scripts/ci.sh`. Esta mejora es **observabilidad**, no permiso para fusionar PR, saltar gates o desplegar recursos.

## Próximo incidente #87

Si reaparece el timeout en `task-navigation.spec.ts`, guardar el SHA/run y consultar el artefacto durante los tres días siguientes. Examinar traza de Chromium desktop: elemento estable, desplazamiento, posición y cambios de layout durante el clic. Contrastar con Chromium móvil y reflow 320, y reproducir con datos sintéticos antes de corregir código. No cerrar el issue por una corrida posterior verde sin explicar la causa o documentar la incertidumbre.

**Limitación:** todavía no se ha provocado un fallo Playwright dentro de GitHub Actions para confirmar una descarga real del artefacto. Los tests del workflow comprueban su configuración; la validación material del artefacto depende del próximo fallo y permisos de GitHub.
