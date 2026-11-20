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

- **Rendimiento del flujo autorizado:** crear un fixture API local explícito y seguro para mostrar una comisión/lote sintéticos en el build, y repetir mediciones en estados significativos. No usar expedientes institucionales ni inventar usuarios humanos.
- **Serie controlada / presupuestos temporales:** fijar equipo físico, carga base, sistema operativo, versión exacta de Chromium y más series antes de decidir umbrales de Lighthouse.
- **Accesibilidad manual y campo:** siguen pendientes NVDA, VoiceOver, zoom nativo, sesiones UX-5.6 autorizadas, Core Web Vitals reales (INP incluido), y métricas de interacción por rol.
- **Liberación:** un CI local aprobado no desbloquea Cloudflare Preview, producción ni el inspector.
