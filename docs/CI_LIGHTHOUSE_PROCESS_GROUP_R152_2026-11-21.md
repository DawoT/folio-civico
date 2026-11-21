# PERF-003 / R1.52 — cierre de procesos descendientes de Lighthouse

**Fecha:** 2026-11-21 (America/Lima). **Issue:** [#81](https://github.com/DawoT/folio-civico/issues/81). **Base inicial:** `main@894eed91a30b14ccb4a4e8c066c0ac9a4bb912a0`. **Ámbito:** `scripts/lighthouse-cli.mjs` y pruebas CLI sintéticas. Sin despliegues ni acceso a datos institucionales.

## Defecto concreto reproducido

El timeout de `runLighthouseCli()` mataba con `child.kill('SIGKILL')` exclusivamente al proceso hijo directo. Un descendiente que no heredaba sus pipes podía permanecer vivo, incluso después de que el CLI devolviera éxito y produjera un archivo JSON. Un proceso Chromium residual puede aumentar contención en siguientes laboratorios, pero **no se ha demostrado que explique el fallo histórico `exit 0` sin `run-1.json`**. La causa histórica permanece en investigación.

Reproducción con procesos Node sintéticos sobre Linux, sin lanzar Chrome ni servicios externos:

| Escenario | RED antes del cambio | GREEN después del cambio |
|---|---|---|
| Hijo agota timeout con descendiente | Descendiente vivo tras timeout (estado `S` en `/proc`) | Descendiente no ejecutándose |
| Hijo sale 0 sin escribir JSON | Rechazo del informe, pero descendiente vivo | Rechazo fail-closed y descendiente no ejecutándose |
| Hijo sale 0 y entrega JSON válido | Informe aceptado, pero descendiente vivo | Informe aceptado y descendiente no ejecutándose |

Cada prueba crea su propio directorio temporal y un PID artificial, comprueba la terminación del descendiente y tiene limpieza de emergencia en `finally` si falla una aserción. El detector reconoce `Z` (zombie no ejecutable) como proceso terminado; no se interpreta como proceso activo que consume CPU. No se conservan PIDs ni datos del host en Git.

## Corrección mínima

En POSIX, `spawn()` crea un grupo nuevo (`detached:true`) cuyo líder es el CLI Lighthouse. Al expirar el timeout se envía `SIGKILL` al **grupo completo** con `process.kill(-child.pid, 'SIGKILL')`. Tras el cierre normal/anómalo, `finish()` también termina cualquier miembro residual del grupo, tanto si el informe es válido como si falla su lectura. Se mantiene el fallback `child.kill('SIGKILL')` si el grupo ya desapareció o no puede alcanzarse. En Windows se mantiene el comportamiento previo de hijo directo; el CI actual se ejecuta en `ubuntu-latest`.

Se conserva la propagación del error original, cierre de pipes al timeout, diagnóstico sanitizado, verificación estricta de archivo fresco y regular, tres reportes auténticos y las restricciones de origen/performance existentes. No se agregan retries, `force`, `skip`, métricas sintéticas que suplanten a Lighthouse ni se elevan timeouts.

## Evidencia ejecutada

- RED inicial sin corrección: descendiente `S` tras timeout, limpieza manual segura al final de la reproducción.
- RED automatizado inicial: 1/13 falló por descendiente activo en timeout.
- RED incremental: 1/14 falló por descendiente activo con `exit 0` y JSON ausente.
- RED incremental: 1/15 falló por descendiente activo tras JSON válido.
- GREEN: `pnpm exec vitest run tests/lighthouse-cli.test.mjs tests/lighthouse-preview.test.mjs tests/lighthouse-lab.test.mjs --maxWorkers=1`, **26/26**, 3/3 archivos, exit 0; pruebas de faltantes, links, timeout, señales y contenido válido continúan.
- Node local: **v26.13.1**. Lighthouse fijado: **13.6.0**. Los casos de descendientes son **sintéticos, sin puerto ni Chrome**. CI GitHub usa Node 24 y requiere validarse sobre el SHA final; ejecución de `sh scripts/ci.sh` pendiente antes de merge.
- La observación de procesos no es una evaluación de rendimiento ni autoriza afirmar desaparecida la intermitencia original. Limitación: descendientes que deliberadamente crean otra sesión/grupo POSIX quedan fuera de este grupo.

## Integración y límites

Crear PR draft desde worktree aislado en cuanto quede cupo según WIP 2 de [#133](https://github.com/DawoT/folio-civico/issues/133). Revalidar contra `origin/main` actualizado; ejecutar `sh scripts/ci.sh` sin competir con otros CI shell pesados del host, exigir check GH y aprobación independiente; comprobar CI de `main` posterior. Mantener [#81](https://github.com/DawoT/folio-civico/issues/81) abierto salvo demostración de causa raíz histórica. Ningún cambio del inspector, frontend, `.github/workflows/**`, Cloudflare, Preview o D1 remoto.
