# UX-0 — Línea base de experiencia y frontend

**Corte:** 2026-11-19. **Estado:** diagnóstico basado en código y en pruebas de navegador documentadas; sin investigación con usuarios reales ni métricas temporales inventadas.  
**Plan de evolución:** [UX / Frontend Premium](UX_FRONTEND_PREMIUM_ROADMAP.md).

## 1. Inventario verificable

| Capa | Implementación existente | Riesgo UX/arquitectónico |
| --- | --- | --- |
| Composición | `apps/web/src/App.tsx` (comisión/lote, upload, selección de documento, administración por presidencia) | Una sola vista extensa; administración antecede los documentos para presidencia |
| Revisión | `apps/web/src/ReviewWorkspace.tsx` (checklist, búsqueda, borradores, revisión y exportación) | Estados y acciones distribuidos verticalmente |
| Acceso | `apps/web/src/CommissionAdmin.tsx` (altas/cambios/revocaciones auditables) | Entradas técnicas `sub` de Access requieren ayuda contextual |
| Evidencia | `apps/web/src/InspectedTextViewer.tsx` | Mostrar solo texto autorizado, nunca un PDF original en cuarentena |
| Apariencia | `apps/web/src/styles.css` (16 029 caracteres antes de DS-001) | Colores, tamaños, radios y feedback repetidos en declaraciones CSS |
| Control UI | React 19, Vite 8, TypeScript; sin biblioteca de componentes ni router | Cambios globales de UI pueden producir inconsistencias entre formularios |
| Verificaciones | `tests/browser/pilot.spec.ts` + axe Playwright/Chromium y `apps/web/src/*.test.tsx` | No sustituyen lectores de pantalla ni sesiones moderadas |

La suite existente cubre seis recorridos Playwright en escritorio de 1366×900, Pixel 7 y 320×640 (18 ejecuciones). Ese hecho no demuestra calidad percibida ni ergonomía para usuarios institucionales.

## 2. Trabajos críticos por rol (journey baseline)

| Perfil | Intención | Ruta actual | Fricción observada o derivada del código |
| --- | --- | --- | --- |
| Presidencia | Configurar comisión y revisar estado documental | Elegir comisión → crear lote o editar miembros → abrir lote → documentos → revisión | La administración aparece antes del trabajo; las decisiones no están priorizadas por una cola de tareas |
| Autor/miembro | Registrar ausencia documental de manera auditable | Elegir comisión/lote → checklist → registrar búsqueda con alcance → borrador → enviar | Varios pasos y desplazamiento largo; el estado de borrador debe mantenerse inequívoco |
| Revisor independiente | Comprobar evidencia y validar o descartar | Cambiar identidad → historial → abrir revisión → justificar → confirmar | Sin una bandeja de «pendientes para mí»; depende del historial y no debe permitir autoaprobación |
| Observador | Consultar evidencia e informe sin editar | Elegir comisión/lote → historial paginado → detalle → exportación | No hay navegación por tareas, aunque los botones de edición sí se ocultan por permiso |

**No reemplazar las reglas de negocio**: dos identidades humanas, versionado, control de acceso en servidor, comprobación de SHA-256, separación entre búsqueda sin resultado e irregularidad probada.

## 3. Hipótesis UX en orden de impacto

1. **P0 — Jerarquía administrativa:** mover gestión de miembros/lotes fuera del flujo documental principal reduce tiempo hasta la revisión, especialmente para la presidencia. Se verificará comparando tiempo de completar una tarea antes/después, no por intuición.
2. **P0 — Estado y siguiente acción:** un shell con contexto persistente y navegación por tareas reduce navegación perdida, especialmente en móvil.
3. **P1 — Revisión en contexto:** una bandeja de observaciones pendientes con evidencia y estado reduce desplazamiento y relecturas.
4. **P1 — Consistencia visual:** tokens y primitivas semánticas reducen divergencias entre formularios y nuevos componentes; deben conservar contraste y estilos presentes.

## 4. Baseline de estilos y primer alcance DS-001

Se conserva la paleta existente y el modo claro; **no** se ejecuta un rebranding. Los tokens introducidos en `apps/web/src/ui/tokens.css` cubren tinta, superficies, bordes, acción primaria, foco, estados de cuarentena/revisión/validación y geometría. El cambio migra selectivamente `:root`, controles, estados, mensajes y paneles; otros valores literales existentes son deuda planificada para DS-002 y UX-4, no una infracción a ocultar.

**Criterios de aceptación:** tests Vitest de tokens/contraste y CSS, regresión de navegador/axe sin alteración del flujo, verificación de reflujo a 320 px, TypeScript y compilación; `sh scripts/ci.sh` finaliza con código 0. Documentar los tests Red antes de implementar y Green después.

## 5. Métricas de usuario: pendientes de medir

No existe línea base de tiempo por tarea, tasa de error humano, satisfacción, comprensión de estados ni entrevistas. Se medirán en UX-5 con participantes y escenarios sintéticos: comisión, carga, constatación, revisión distinta, consulta y export. Los objetivos del roadmap son hipótesis. No instalar telemetría ni recopilar datos personales en esta fase.

## 6. Restricciones para UX-1/UX-2

- No introducir dependencias UI, fuentes remotas o framework de routing sin necesidad.
- No inventar contadores de documentos, decisiones o estados.
- El contraste automatizado es condición mínima, no certificación WCAG.
- Mantener enlace de lote mediante query params, ACL y lectura autorizada.
- No exponer, cargar ni renderizar PDFs originales en cuarentena.
- Documentar estados de carga, error, contenido vacío, controles deshabilitados y reenviados.
- No activar Cloudflare ni habilitar inspector bloqueado; el trabajo de diseño es independiente.

## 7. Evidencias y forma de reproducción

```sh
pnpm install --frozen-lockfile
pnpm exec vitest run tests/design-tokens.test.ts
pnpm test:browser
pnpm typecheck
pnpm build
sh scripts/ci.sh
```

El caso de tokens falló inicialmente **4/4** por inexistencia de `tokens.css` y falta de uso de variables; después pasó **4/4**. El resultado integral del CI debe anotarse únicamente tras ejecutarlo; el documento no sustituye el log de CI. Los tests de navegador emplean la API sintética y no constituyen E2E remoto.
