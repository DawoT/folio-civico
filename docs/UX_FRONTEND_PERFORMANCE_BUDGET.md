# UX Premium — presupuesto reproducible de transferencia frontend

**Corte:** 2026-11-20. **Referencia de baseline:** `origin/main@1477ffe`.
**Evidencia:** compilación Vite de `@folio/web` y medida directa gzip con Node.js `v26.13.1` / pnpm `12.21.0`.
**Estado:** control de regresión de bytes integrado en el gate **local**; **no** es una auditoría Lighthouse ni una aceptación de UX.

## Línea base del build

El build produce una hoja CSS y un bundle JavaScript; se computan **todos** los chunks `.js` y `.css` que aparezcan bajo `apps/web/dist/assets`, no solo el archivo de entrada.

| Tipo | Bytes sin comprimir | Bytes gzip (Node) | Presupuesto gzip | Margen |
| --- | ---: | ---: | ---: | ---: |
| JavaScript | 291 185 | 86 214 | 102 400 (100 KiB) | 16 186 bytes |
| CSS | 38 884 | 7 205 | 10 240 (10 KiB) | 3 035 bytes |

Los límites establecen un margen de evolución acotado respecto a la compilación observada, sin exigir reescrituras arbitrarias. Vite puede informar tamaños gzip ligeramente distintos según la implementación y los niveles de compresión; **la fuente de verdad es el conteo de `gzipSync` del script** y la versión Node declarada.

## Gate obligatorio

```sh
pnpm install --frozen-lockfile
pnpm --filter @folio/web build
pnpm check:frontend-budget
# Gate de integración completo, sin depender de GitHub Actions:
sh scripts/ci.sh
```

`scripts/ci.sh` invoca el presupuesto **después** de `pnpm build` y **antes** de workerd, Chromium y D1 local. El comprobador falla si falta `dist/assets`, alguno de los tipos JavaScript/CSS, aparecen symlinks en los artefactos, se invalida un presupuesto o se supera el máximo total. La medición no lee ni envía documentos ni contacta servicios remotos.

**Criterio:** regresión del peso gzip total JS o CSS por encima del límite → CI rojo. Un cambio al límite requiere revisión explícita de baseline y justificación del coste para usuarios; **no** basta con aumentar el umbral para desbloquear un PR.

## Fuera del alcance y próximos instrumentos

- **Fuera de PERF-001:** LCP, INP, CLS, TTFB, memoria, CPU, caché, latencia, carga en red lenta ni calidad de lectores de pantalla. La captura local inicial TTFB/FCP/LCP/CLS se añade por separado en [PERF-002](UX_FRONTEND_BROWSER_PERFORMANCE_LAB.md); no equivale a métricas de campo.
- La comparación de tiempos requiere un perfil de hardware y red documentado, navegador/versión fijos y múltiples series. PERF-002 registra tres navegaciones iniciales sin throttling y [PERF-003](UX_FRONTEND_LIGHTHOUSE_LAB.md) ejecuta tres auditorías Lighthouse móviles simuladas del shell sin autenticar; ninguna infiere rendimiento institucional del gzip ni de un solo indicador.
- La investigación UX-5.6 con personas autorizadas y los gates manuales de NVDA/VoiceOver/zoom siguen pendientes; este control no los sustituye.
- Sin cambios en Cloudflare remoto, retención, cuarentena, roles ni inspector.
