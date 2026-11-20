# PERF-003 — Eliminación del wrapper de proceso Lighthouse

**Fecha:** 2026-11-20. **Ámbito:** CI sintético en loopback, sin despliegues ni datos institucionales. Seguimiento: issue #81.

## Hallazgo y cambio

La incidencia original fue intermitente: el proceso `pnpm exec lighthouse` finalizó con código 0, pero el informe esperado `run-1.json` no existía. **No se ha demostrado una causa raíz** (Chrome, Vite, CLI, concurrencia o wrapper). El runner ya rechazaba informes inexistentes, vacíos o JSON inválido, sin interpolar stdout/stderr sensibles en el error.

Se elimina un proceso intermediario: el runner invoca `process.execPath` con `<workspace>/node_modules/lighthouse/cli/index.js` y los mismos argumentos de medición que antes. Esta ruta corresponde al binario anunciado por `lighthouse@13.6.0` en el paquete local bloqueado por `pnpm-lock.yaml`. Se exige que el archivo exista y sea regular; si falta, la ejecución falla antes del laboratorio, sin inventar mediciones ni recuperar artefactos de otros runs.

No se cambian puertos, budget, viewport, throttling, timeouts, etiquetas, captura de informes, almacenamiento temporal ni la obligación de **tres Lighthouse reales**. `scripts/ci.sh` conserva el gate `pnpm test:lighthouse`; solamente cambia el subprocess que lanza el ejecutable.

## TDD y evidencias

- **RED:** nuevo test `launches the locally pinned Lighthouse executable directly with Node, never a pnpm wrapper` falló con `TypeError: localLighthouseInvocation is not a function` (6/7 tests anteriores verdes).
- **GREEN:** 11/11 tests dirigidos en `tests/lighthouse-cli.test.mjs` y `tests/lighthouse-lab.test.mjs`; el test ejecuta `--version` mediante Node, comprueba `13.6.0` y prueba rechazo de instalación ausente.
- **Pendiente en este registro:** resultado de `sh scripts/ci.sh` integral y dos checks GitHub Actions del SHA definitivo. No asumir aprobación antes de verificar ambos.

## Seguridad y operación

El proceso Lighthouse ejecuta solo el frontend construido en `http://127.0.0.1`, en puerto configurable propio, con Chromium instalado; los informes se crean en directorio temporal privado y se destruyen al finalizar. La salida de Chrome/Lighthouse permanece reducida a marcadores de error permitidos, sin guardar secretos ni volcar URLs sensibles. Si `lighthouse` no produce uno de sus tres reportes, el CI **debe seguir rojo**.

El cambio reduce la complejidad del árbol de procesos, pero **no prueba** que el wrapper causara el incidente original. Mantener #81 abierto hasta validar varias ejecuciones comparables y documentar la recurrencia o su ausencia sin asumir causalidad; si reaparece, registrar SHA, runner, puerto y marcadores sanitizados antes de otra corrección.
