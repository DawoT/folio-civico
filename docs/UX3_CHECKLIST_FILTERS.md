# UX-3.3 — Checklist contextual por estado y área

**Fecha:** 2026-11-19. **Alcance:** UX y frontend de Folio Cívico, sin cambios de API.

## Resultado

La mesa documental permite consultar ítems del checklist autorizado por **área** (todas, obras, contrataciones) y **estado semántico** (todos, pendientes, validación interna, ubicados, otros). Se mantiene el orden original proporcionado por la API y la navegación a los registros de evidencia ya validados.

## Exactitud de los estados

| Filtro | Fuente | Precisión del lenguaje |
| --- | --- | --- |
| Pendientes | `status === "pending"` | No declara revisión completada |
| Validación interna | `statusSource === "validated_search"` y referencia de observación presente | **Revisión humana interna**, no conclusión oficial |
| Ubicados | `status === "located"` sin validación interna | No confundir documento ubicado con observación aprobada |
| Otros | Estados `observed/not_located` sin prueba de validación interna | «No ubicado» almacenado no equivale a validación humana |
| Todos | Filas cargadas | No reemplaza ni altera el checklist institucional |

El filtro por área y sus conteos se calculan únicamente a partir de las filas cargadas del checklist existente. **No se ejecuta un endpoint nuevo, no se duplican solicitudes ni se inventan totales.**

La presentación de estado usa `StatusBadge` reutilizable y texto visible; el botón **Ver validación** sigue enlazando exclusivamente a la observación registrada por segunda persona. Una consulta de detalle nunca expone el PDF original en cuarentena.

## TDD

- **Red:** cuatro casos de `ChecklistFilters.test.tsx` fallaron porque el componente aún no existía.
- **Green:** los casos verifican separación entre estado `not_located` sin revisar y validación interna, conteos por área, orden, accesibilidad del select/botones y conjuntos vacíos.
- **Navegador:** dos recorridos E2E con API sintética que cubren autor y segundo revisor, actualización tras validación, filtro por área, acceso al detalle autorizado; y observador de solo lectura con axe y reflujo.
- **Gate obligatorio:** `sh scripts/ci.sh` sobre base actual de `origin/main`, con puerto Playwright aislado mediante `FOLIO_E2E_PORT`. TypeScript, Vite/Workers dry-run, Vitest, Python, workerd, Chromium desktop/móvil/320, axe y migraciones D1 locales.
- **No se usa GitHub Actions** como criterio de aprobación.

## Resguardos

Sin cambios de backend, permisos, modelo de datos, importación documental, idempotencia o estado de cuarentena. No se incorpora ninguna dependencia externa. Los indicadores son descriptivos y no constituyen certificación documental ni autorización institucional.

## Próximos incrementos

UX-3.4: informes internos, recuperación de errores e integridad de exportación con mensajes accesibles; posteriormente UX-4: pulido editorial/visual y UX-5: pruebas de usabilidad representativas y lector de pantalla humano.
