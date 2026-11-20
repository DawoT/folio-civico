# PERF-003 · Diagnósticos sanitizados del arranque Vite

**Fecha:** 2026-11-20. **Ámbito:** CI local del laboratorio Lighthouse, sin Preview institucional. Relación: issue #81. **Causa del informe ausente todavía no identificada.**

## Defecto y superficie

El proceso Lighthouse ya clasifica códigos/errores sin volcar stdout/stderr, pero `scripts/run-lighthouse.mjs` adjuntaba `output.slice(-1300)` **sin filtrado** al mensaje `Vite preview stopped before ready`. Esto permite que cadenas arbitrarias impresas por un fallo de preview terminen en el log del CI. La ruta de `spawn error` propagaba asimismo el error original del proceso.

Se reutilizó el clasificador de códigos de `scripts/lighthouse-cli.mjs` y se extrajo `startLighthousePreview` a `scripts/lighthouse-preview.mjs`. La salida del proceso se utiliza en memoria únicamente para identificar el marcador Vite propio de loopback; cualquier error expone solo código de salida/señal y categorías de error fijas (`ENOENT`, `EACCES`, `port-in-use`, `node-error`, etc.). Los `ERR_*` arbitrarios se clasifican como `node-error`, **sin imprimir su sufijo**. En timeout el proceso se termina y se cierran los pipes para evitar exceder el límite por herencia de stdout/stderr.

Se conserva el mismo Vite binario local, `--host 127.0.0.1`, `--strictPort`, duración máxima de **25 segundos**, detección de marcador propio, perfil móvil Lighthouse, tres reportes obligatorios, origen y validación del archivo JSON. La implementación se integró sobre **PR #108** (puerto efímero por defecto): el controlador devuelve `{child,url}` con la URL extraída mediante el parser estricto de #108; un puerto explícito diferente se rechaza. No se restaura el puerto fijo anterior. El cambio no inventa métricas, no incorpora reintentos y no suaviza ningún gate.

## TDD y criterios

- **RED 1:** `tests/lighthouse-preview.test.mjs` no puede importar el nuevo controlador (exit 1).
- **RED 2:** la salida `Port 4181 is already in use` no tenía clasificación, incluso después de la primera extracción.
- **GREEN:** 17/17 pruebas focales de `lighthouse-preview`, `lighthouse-cli` y `lighthouse-lab`; TypeScript aprobado. Verifican salida sensible desde stdout/stderr, exclusión de URL ajena, rechazo del marcador de otro puerto, aceptación del proceso vivo propio, timeout, clasificación de puerto ocupado y sanitización de códigos `ERR_*`.
- **Sobre la base combinada del PR #108:** 19/19 pruebas dirigidas de CLI, parser de puerto efímero y preview sanitizado; TypeScript aprobado. Lighthouse directo sin override de puerto: exit 0, OS asignó 45719, 3/3 informes, mediana 100.
- **CI integral local combinada con PR #108, `sh scripts/ci.sh` exit 0:** 606 Vitest + 467 Python inspector + 18 contratos CI + 33 UX5 + 2 Chromium PERF + 5 workerd + 138 Chromium E2E + 1 demo + 1 demo PERF = **1271/1271**; Lighthouse 13.6.0 móvil **3/3 reportes reales** con puerto efímero 34793, mediana score 100, FCP/LCP 754 ms, CLS 0.049, TBT 0.5 ms; typecheck, compilaciones/dry-runs, budget y migraciones D1 locales aprobados.
- **CI integral local anterior a la integración con #108, `sh scripts/ci.sh`, exit 0:** 604 Vitest + 467 Python inspector + 18 contratos CI + 33 UX5 + 2 Chromium PERF + 5 workerd + 138 Chromium E2E + 1 demo + 1 demo PERF = **1269/1269**. Lighthouse móvil 13.6.0, **3/3 reportes reales**, mediana score 100, FCP/LCP 761 ms, CLS 0.049, TBT 9 ms; typecheck, builds/dry-runs, budget y D1 local aprobados. Cuatro puertos aislados. GitHub Actions del SHA del PR sigue siendo un gate independiente.

## Interpretación

Esto corrige **una filtración potencial de logs por el arranque Vite**, no demuestra que el wrapper pnpm causara el fallo `exit 0 sin JSON` observado en #81. La issue debe permanecer abierta hasta obtener evidencia causal o datos de recurrencia. La verificación no autoriza ningún runtime remoto ni despliegue del inspector.
