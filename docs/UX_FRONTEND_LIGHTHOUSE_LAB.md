# PERF-003 — Lighthouse real con perfil móvil simulado

**Corte:** 2026-11-20. **Base de implementación inicial:** `main@aff3eb2`.
**Herramientas:** Node.js `v26.13.1`, pnpm `12.21.0`, Lighthouse CLI `13.6.0` (dependencia exacta), Chromium incluido con Playwright (revisión local `chromium-1255`).
**Ámbito:** únicamente el **shell inicial no autenticado** del frontend Vite compilado, servido por `vite preview` en `127.0.0.1`. No hay backend institucional ni API sintética en este ensayo. Las solicitudes `/api/**` no suministran datos de comisión, de modo que **NO** representa el workspace de un usuario autorizado.

## Configuración de laboratorio

`pnpm test:lighthouse` lanza un proceso nuevo de `vite preview`, con puerto estricto (por defecto `4181`, opcional `FOLIO_LIGHTHOUSE_PORT`), y la versión fijada de Lighthouse sobre el Chromium del lockfile de Playwright. El servidor responde únicamente en loopback; un puerto ocupado **falla** antes de la auditoría, sin reutilizar procesos existentes.

| Parámetro | Valor configurado |
| --- | --- |
| Perfil | Mobile, 390 × 844, escala de píxel 2× |
| Método | `simulate` (Lighthouse/Lantern), **no es throttling de red real** |
| RTT simulado | 150 ms |
| Transferencia simulada | 1.638,4 Kbps |
| Factor CPU simulado | 4× |
| Categoría | `performance` |
| Ejecuciones | Tres informes Lighthouse reales, mediana |
| Código auditado | Artefactos `apps/web/dist`, no Vite dev |
| Destino | Solo `http://127.0.0.1:<puerto>/` |

El runner ejecuta Chrome headless con `--no-sandbox` **solo dentro de este entorno local de pruebas** porque Chrome Launcher no puede inicializar el sandbox del entorno actual; ese flag no cambia la seguridad de la aplicación ni configura navegadores de producción. No se deben navegar sitios externos con ese perfil. Se desactiva el envío voluntario de informes de error de Lighthouse.

Los informes JSON viven temporalmente en un directorio privado del sistema y se eliminan tras cada ejecución. Solo se imprime un agregado numérico: puntuación performance, FCP, LCP, CLS y TBT. Si la navegación termina en otra URL, Lighthouse emite un `runtimeError`, falta alguna métrica, el binario Chrome está ausente o la compilación excede PERF-001, **falla** el comando.

## Baseline observado (primera serie)

Tres ejecuciones reales de Lighthouse 13.6.0, bajo el perfil anterior:

| Medida | Mediana |
| --- | ---: |
| Puntuación Lighthouse Performance | 100/100 |
| FCP | 754,18 ms |
| LCP | 754,18 ms |
| TBT | 0 ms |
| CLS | 0,04913 |

**Interpretación estricta:** esta puntuación caracteriza la carga de un **shell no autenticado sin backend** servido en loopback. No autoriza afirmaciones de rendimiento premium para usuarios institucionales, colas de revisión, documentos, exportación o Access/MFA. El rendimiento del hardware anfitrión, su carga, versión del navegador y variabilidad entre series no están controlados como banco profesional. La red/CPU son parámetros **simulados**, no recursos reales limitados. Tampoco hay INP, RUM ni percentiles de usuarios.

Por eso, **PERF-003 no introduce un umbral de puntuación o milisegundos** que se pueda ajustar para desbloquear un PR. El gate exige que Lighthouse realmente funcione y produzca tres informes válidos; el presupuesto de transferencia PERF-001 sigue siendo el límite cuantitativo exigible.

## Corrección de CI — salida ANSI de Vite Preview

Tras integrar PERF-003 en `main`, las ejecuciones de GitHub Actions
reproducían `Vite preview startup timed out` a los 25 segundos, antes de
invocar Lighthouse. La causa no era un resultado de rendimiento: con `CI=true`
Vite introduce códigos de color ANSI incluso **entre el host y el puerto** de
la línea `Local: http://127.0.0.1:<puerto>/`. El runner esperaba el URL
literal sin esos códigos y nunca reconocía la señal de su propio proceso.
Se reprodujo el cambio de formato en un Vite real ejecutado localmente con
`CI=true`, confirmando la diferencia en stdout.

La corrección elimina únicamente secuencias ANSI de la salida del proceso
antes de contrastar el marcador `Local:` y el **origen/puerto exactos**;
también acepta el mismo marcador en stderr. No reduce el número de auditorías,
no cambia los perfiles ni los umbrales de integridad; mantiene
`--strictPort`, origen loopback, el proceso nuevo y la verificación del
frontend compilado. Una URL diferente o texto sin marcador siguen fallando.

**TDD:** prueba de ANSI partido en el número de puerto, salida sin ANSI,
puerto incorrecto, URL ajena y texto incidental. Red: 3/4 aprobadas (1 nueva
fallida); Green: **4/4 aprobadas**. La integración CI de GitHub es necesaria
antes de afirmar que el bloqueo común quedó resuelto.

## Diagnóstico fail-closed de reportes ausentes (issue #81)

Se identificó una falla intermitente: el proceso `pnpm exec lighthouse` podía
terminar con exit 0 sin escribir un archivo `run-N.json`. Antes la lectura
directa lanzaba únicamente `ENOENT`, sin conservar indicios del proceso cerrado.

El ejecutor `scripts/lighthouse-cli.mjs` ahora distingue **proceso no cero**,
**señal**, **timeout de 90 s**, **JSON ausente**, **vacío** e **inválido**. Recoge
stdout y stderr por separado con un máximo de 7 KiB cada uno, pero solo emite
códigos de error conocidos y clases de fallo permitidas (Chromium, sandbox,
red, timeout); jamás imprime líneas originales, tokens, URLs o rutas de
archivos. Si el proceso afirma éxito pero falta un reporte, el gate falla
con la causa y los marcadores seguros; no fabrica métricas ni reintenta.

**TDD:** proceso Node real que sale con código 0 sin escribir su JSON,
salidas con secretos que no aparecen en el error, salida 7, señal, timeout,
archivo vacío, JSON corrupto y JSON válido. El runner conserva exactamente
**tres auditorías Lighthouse válidas** antes de calcular medianas.

Esto mejora la capacidad de diagnóstico; **no determina todavía la causa raíz
ambiental** del fallo intermitente ni equivale a garantizar que no vuelva a
ocurrir. Para esa investigación siguen siendo útiles las evidencias de
versión Node/Chromium, puerto y carga concurrente sanitizadas.

## Reproducir

```sh
pnpm install --frozen-lockfile
pnpm --filter @folio/web build
pnpm test:lighthouse

# Puerto libre para otro worktree
FOLIO_LIGHTHOUSE_PORT=4520 pnpm test:lighthouse

# Gate completo de integración autorizado
sh scripts/ci.sh
```

## Próximas brechas

- **Rendimiento del flujo autorizado:** [PERF-004](UX_FRONTEND_AUTHORIZED_WORKFLOW_LAB.md) mide con Playwright un recorrido con rol/API sintéticos, sobre el build, desde comisión y lote hasta historial de 40 observaciones y detalle. Sigue pendiente una **auditoría Lighthouse** de ese estado autorizado con fixture backend seguro y reproducible, sin expedientes institucionales ni datos humanos inventados.
- **Serie controlada / presupuestos temporales:** fijar equipo físico, carga base, sistema operativo, versión exacta de Chromium y más series antes de decidir umbrales de Lighthouse.
- **Accesibilidad manual y campo:** siguen pendientes NVDA, VoiceOver, zoom nativo, sesiones UX-5.6 autorizadas, Core Web Vitals reales (INP incluido), y métricas de interacción por rol.
- **Liberación:** un CI local aprobado no desbloquea Cloudflare Preview, producción ni el inspector.
