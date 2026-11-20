# PERF-003 — puerto efímero de Vite Preview en el laboratorio Lighthouse

**Fecha:** 2026-11-20 · **baseline:** `origin/main@353e0d642cb7314df41ad47f60c7ee9a759cc965` · **issue:** #81. Investigación local sintética, sin desplegar Preview institucional ni utilizar datos personales.

## Problema reproducido

Lighthouse ya se ejecuta directamente mediante el ejecutable Node fijado en el lockfile (PR #103); cada `pnpm test:lighthouse` lanza Vite Preview en `127.0.0.1:4181` por defecto, con `--strictPort`. Ese puerto fijo provoca colisiones entre worktrees y ejecuciones locales simultáneas.

Se construyó `apps/web/dist` desde el baseline mediante `pnpm install --frozen-lockfile` y `pnpm --filter @folio/web build`, sin acceso a servicios remotos.

| Escenario de laboratorio | Resultado observado |
| --- | --- |
| 2 laboratorios concurrentes con puertos explícitos distintos, 42611/42612 | Ambos exit 0, **6/6 reportes** válidos, medianas 100; ~34 s cada uno |
| **RED por contención:** 2 concurrentes sobre el **mismo puerto** explícito 42613 | Uno exit 0 / 3 reportes; otro exit **1** a los 0.6 s por `vite_preview_port_collision` |
| Prueba RED del nuevo parser de URL propia Vite | `extractOwnVitePreviewUrl is not a function`: 1/5 falló, 4/5 preexistentes pasaron |
| Prueba RED para excluir el puerto fijo implícito | `validateLighthousePort(undefined)` aún devolvía 4181; test nuevo falló |
| **GREEN:** dos laboratorios simultáneos sin `FOLIO_LIGHTHOUSE_PORT` | Ambos exit 0, OS asignó **41977 y 40539**, **6/6 reportes** válidos, medianas 100; ~38 s cada uno |
| **GREEN:** laboratorio único tras el cambio | Exit 0, puerto efímero 46293, **3/3 reportes**, mediana 100 |
| Pruebas dirigidas `lighthouse-cli.test.mjs` y `lighthouse-lab.test.mjs` | **12/12** aprobadas |

Los puertos concretos documentan únicamente esta ejecución y **no** son una política de asignación ni una garantía de disponibilidad futura.

## Corrección implementada

- Sin `FOLIO_LIGHTHOUSE_PORT`, Vite Preview recibe **`--port 0`**: el sistema operativo asigna un puerto realmente libre al establecer el socket. Esto evita la selección manual y la ventana TOCTOU de consultar/liberar puertos antes de hacer `listen`.
- El runner acepta **solo la URL propia** del mensaje `Local:` del proceso Vite recién lanzado, en `http://127.0.0.1:<puerto-no-privilegiado>/`. Se quitan códigos de color ANSI antes de validar, se rechazan URLs redirigidas, puertos ambiguos/múltiples, prefijos falsos o destinos externos. El puerto real se registra en la línea agregada de resultados.
- Si se define `FOLIO_LIGHTHOUSE_PORT`, se exige un entero TCP no privilegiado, se mantiene el **puerto explícito + `--strictPort`** y se rechaza una dirección de arranque diferente.
- Cada uno de los tres reportes Lighthouse conserva sus verificaciones de URL solicitada/final, integridad de métricas y errores. Se mantiene el presupuesto frontend, `pnpm test:lighthouse` bloqueante, perfil móvil, límites de procesos, eliminación del directorio temporal y aislamiento loopback.

## Seguridad, límite causal y seguimiento

La colisión de puertos está **reproducida y corregida** para concurrencia local, pero el incidente histórico de #81 fue **`Lighthouse exit 0` sin `run-1.json`**, no un error Vite explícito. **No se afirma que el fallo histórico tuviese esta misma causa**. Mantener #81 abierto hasta disponer de evidencia de recurrencia o un periodo/volumen de ejecución acordado; si reaparece, conservar SHA/run, puerto, versión Chromium/Node y marcadores sanitizados, sin subir stdout sensible.

No se modifica el frontend, D1, R2, API, seguridad de imagen, Cloudflare ni el proceso de publicación. El laboratorio únicamente usa archivos compilados y datos sintéticos locales.

**Pendientes de la integración de este commit:** CI integral local, dos checks GitHub Actions sobre el SHA exacto, verificación postmerge de `origin/main` y CI posterior al merge. Ninguno se da por aprobado antes de su conclusión.
