# IA-001.1 — Navegación orientada a tareas y administración separada

**Fecha:** 2026-11-19. **Estado:** primer corte de arquitectura de información frontend, sujeto a CI local y revisión de PR.

## Objetivo

Resolver la fricción de la página larga sin introducir una arquitectura nueva ni modificar contratos. El trabajo documental deja de compartir la parte superior con formularios de administración.

## Implementación

- `apps/web/src/layout/TaskNavigation.tsx`: navegación semántica mediante `<nav aria-label="Áreas de trabajo">` y enlaces nativos a las secciones existentes. Muestra la comisión y el lote autorizados disponibles; no inventa indicadores ni contadores.
- Enlaces de tarea cuando hay lote abierto: `#expedientes`, `#checklist`, `#observaciones`, `#informes`. Solo los usuarios con capacidad de redactar ven `#registrar-busqueda`; solo la presidencia autorizada o el operador habilitado ven `#administracion`.
- `apps/web/src/App.tsx`: creación de comisión (operador), alta de lotes y administración de miembros se agrupan en `<details id="administracion">` inicialmente cerrado. Puede abrirse por teclado, resumen nativo o enlace de navegación. Al cambiar comisión se cierra para evitar un contexto administrativo obsoleto.
- `ReviewWorkspace.tsx`: IDs de anclaje estables en la exportación interna, checklist, creación de búsqueda e historial; no cambia lógica ni validación de dos personas.
- `styles.css`: barra de enlaces con foco visible, objetivos táctiles de 44 px, etiquetas que admiten varias líneas y `flex-wrap` para 320 px. `summary` tiene foco visible.
- No se agrega router: los hashes preservan `?commission=<id>&batch=<id>`; el historial, enlaces profundos y refresco siguen siendo comportamientos nativos.

## TDD

**Red:** cuatro pruebas unitarias de `TaskNavigation` fallaron al importar el componente inexistente y tres recorridos Chromium desktop fallaron por ausencia de navegación.

**Green:** cuatro pruebas unitarias y tres recorridos de navegador desktop pasan; la suite de navegador completa de CI cubre desktop, móvil y 320 px. Se verifican rol de presidencia, autor y observador, la apertura de Administración y la recarga sin perder contexto.

Se actualizó la prueba previa de presidencia para abrir explícitamente Administración antes de gestionar miembros: conserva la funcionalidad y prueba el nuevo comportamiento UX.

## Seguridad y limitaciones

- Ocultar enlaces por rol mejora claridad, **no sustituye** la autorización del backend.
- La visualización de documentos y el acceso a texto inspeccionado conservan exactamente las puertas existentes; el original PDF permanece en cuarentena.
- El `details` agrupa administración pero no modifica el backend de asignación de miembros, roles ni logs.
- Es navegación **dentro de una página**, no un dashboard multipantalla. IA-001.2 deberá revisar estructura global, rutas por tarea y resumen con datos reales autorizados, después de validar usabilidad.
- No habilita OCR, Access remoto, Cloudflare ni lanzamiento institucional.

## Gate de integración

```sh
pnpm install --frozen-lockfile
pnpm exec vitest run apps/web/src/layout/TaskNavigation.test.tsx
pnpm exec playwright test --config=playwright.config.ts tests/browser/task-navigation.spec.ts
sh scripts/ci.sh
```

`sh scripts/ci.sh` incluye Vitest, Python, typecheck, build Workers dry-run, workerd, Playwright/axe y migraciones D1 locales. Solo un resultado **exit 0 sobre la base actual de main** permite fusionar este incremento. No se consulta GitHub Actions como gate.
