# PERF-003 / R1.49 — integridad de artefactos Lighthouse locales

**Fecha:** 2026-11-21 (America/Lima). **Seguimiento:** [issue #81](https://github.com/DawoT/folio-civico/issues/81). **Estado:** refuerzo de integridad del gate local, no cierre de la intermitencia original.

## Problema y alcance

El runner `scripts/lighthouse-cli.mjs` ya diferenciaba cierre anómalo, salida 0 sin JSON, JSON vacío/corrupto y diagnosticaba errores mediante marcadores permitidos que no exponen stdout/stderr bruto. El contrato seguía aceptando un fichero JSON que **existiera antes** de ejecutar Lighthouse, o un enlace simbólico a otro JSON, y `readFileSync` no imponía un límite explícito de tamaño antes de parsearlo. En `scripts/run-lighthouse.mjs`, cada invocación usa una ruta distinta en un directorio temporal privado, por lo que **no hay evidencia de que estos casos causaran el fallo de #81**; se añaden garantías preventivas de reproducibilidad.

## TDD / cambios

- **RED:** pruebas con un CLI sintético que retorna 0 sin escribir sobre una ruta preexistente, genera un symlink o hardlink a un JSON válido, crea un reporte sobredimensionado mediante fichero disperso o crea un directorio en lugar de un fichero. Las pruebas existentes para errores sanitizados, tiempo agotado, señales, JSON corrupto y reporte válido permanecen.
- **GREEN:** `runLighthouseCli` comprueba que `outputPath` **no existe** antes de lanzar el proceso. Solo tras `close` con exit 0 abre con `O_NOFOLLOW | O_NONBLOCK`, exige un archivo regular con un único enlace físico y tamaño no superior a **64 MiB**, después lee y parsea JSON. Los hardlinks se rechazan mediante `nlink !== 1`. `O_NONBLOCK` evita bloquearse si se sustituye el archivo por una FIFO. La lectura continúa siendo local, sin datos institucionales.
- Se preserva el diagnóstico redactado como categorías/errno permitidos; no se registran rutas arbitrarias, contenido JSON, URLs completas, secretos o datos de proceso sin filtrar.
- No se agregan retries, perfiles nuevos ni métricas sustitutas. `summarizeLighthouseRuns` conserva la obligación de **tres** reportes válidos correspondientes al loopback exacto; el gate `pnpm test:lighthouse` sigue siendo obligatorio en `scripts/ci.sh`.

## Mediciones reales aisladas

Tras compilar el frontend, dos ejecuciones consecutivas e independientes de `pnpm test:lighthouse` finalizaron `exit 0`, con **3 reportes válidos por ejecución**, Lighthouse **13.6.0**, perfil móvil simulado, puertos efímeros `46555` y `43471`, puntuación mediana **100/100** en ambas. Ninguna ejecución mostró ausencia de JSON. Estas dos observaciones locales no representan un estudio de fallos estadísticamente significativo ni reproducen el problema de CI; el tercer resultado corresponde al gate integral sobre el árbol exacto.

## Limitación

Estas verificaciones hacen que el reporte sea inequívocamente nuevo al iniciar la ejecución y limitan qué tipo de archivo puede leerse. No son una protección contra un atacante local con acceso de escritura concurrente al mismo directorio privado, ni explican el caso histórico de Lighthouse exit 0 sin reporte. Un fallo futuro seguirá dejando el CI rojo; la causa raíz exige evidencia de ese fallo y comparación de condiciones del runner.

## Evidencia y gobierno

La ejecución puntual y el CI deben registrarse contra el SHA Git/árbol exactos del PR, sin asumir aprobaciones de Preview, producción ni G2. No se modifica Cloudflare, D1 remoto, el inspector ni los límites de seguridad del producto. Mantener el [issue #81](https://github.com/DawoT/folio-civico/issues/81) abierto mientras no esté documentada una reproducción/explicación causal de la intermitencia.
