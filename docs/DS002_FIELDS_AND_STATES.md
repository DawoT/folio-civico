# DS-002.2 — Formularios y estados reutilizables

**Fecha:** 2026-11-19 · **Tipo:** incremento frontend aislado con TDD · **Alcance:** componentes nativos, sin cambios de API.

## Resultado

Los nuevos componentes en `apps/web/src/ui` permiten migrar por pasos formularios existentes, sin reemplazar React ni introducir librerías UI:

| Componente | Contrato | Primera adopción |
| --- | --- | --- |
| `Field` | Label/ID explícitos, props HTML input, ayuda/error asociados por `aria-describedby`, `aria-invalid`, error con `role="alert"` | Título del registro de búsqueda |
| `SelectField` | Select/option nativos, label visible, valor controlado y nombre ARIA preservado | Comisión/lote e ítem esperado |
| `TextareaField` | Textarea nativa, props para longitud/filas, texto de ayuda, error semántico | Alcance de búsqueda y justificación del revisor |
| `Card` | Acepta `div`, `section`, `article`; preserva `aria-labelledby` | Paneles de documentos y evidencia |
| `EmptyState` | Mensaje explícito y `role="status"` con anunciación cortés | Sin lote y sin documentos |
| `LoadingState` | Texto visible, anunciación cortés (no spinner exclusivo) | Consulta de documentos |

Los componentes están estilizados con los tokens DS-001 y se adaptan a las clases previas. No se cambian los contratos de lote, checklist, justificación ni permisos. El PDF original continúa en cuarentena y el texto disponible no implica aprobación oficial.

## Ciclo TDD y regresión

**Red:** el test nuevo `apps/web/src/ui/forms-and-states.test.tsx` falló al importar componentes inexistentes. Los cinco escenarios protegen label, ayuda, error y atributos nativos, select con opción activa, textarea, landmarks y estados de carga/vacío.

**Green:** cinco escenarios aprobados tras la implementación y adopción inicial. `pnpm typecheck` finalizó correctamente.

**Gate de integración obligatorio:** `sh scripts/ci.sh` desde la rama sincronizada con `origin/main`. Incluye suite Vitest, Python, TypeScript, build/dry-run, workerd, Playwright + axe y migraciones D1 locales. Registrar el resultado solo cuando termine. GitHub Actions no se utiliza como aprobación.

## Consideraciones de seguridad y accesibilidad

- No se inyecta HTML sin confianza ni se relajan controles del backend.
- La asociación `aria-describedby` conserva referencias adicionales recibidas del consumidor y enlaza hint/error por ID estable.
- `aria-invalid` y `role="alert"` solo aparecen en errores reales suministrados por la interfaz.
- Los estados nunca prometen revisión automática, documentos admitidos o decisiones institucionales.
- El usuario conserva teclado y controles nativos; revisar resultado con Chromium/axe a 320 px.

## Pendientes

- Auditar manualmente con lector de pantalla y usuarios representativos antes de considerar la experiencia certificada.
- Evaluar la adopción gradual en administración de miembros; evitar cambios simultáneos de formularios sensibles y permisos.
- Siguiente fase: **IA-001** (navegación por tareas, contexto activo y administración separada), sin inventar rutas o indicadores del backend.
