# DS-002.1 — Primitivas de interfaz, primera integración

**Fecha:** 2026-11-19. **Estado:** incremento frontend; su aprobación de integración depende del `sh scripts/ci.sh` local.

## Alcance ejecutado

- `apps/web/src/ui/Button.tsx`: control nativo con `type="button"` por defecto, variantes `primary/secondary`, composición de `className`, `disabled` y `aria-busy` cuando hay una operación en curso. Evita submits accidentales y acciones duplicadas por loading.
- `apps/web/src/ui/InlineAlert.tsx`: mensajes con `role="alert"` para error y `role="status"` para información/confirmación, con `aria-live` adecuado. Conserva las clases de estilo `message error/success/info`.
- `apps/web/src/ui/StatusBadge.tsx`: etiquetas con texto explícito y variantes semánticas. `ready` significa que hay texto disponible, **no** hallazgo humano validado ni acta oficial.
- `apps/web/src/styles.css`: estilos de badges basados en variables DS-001, distinción visual entre cuarentena/en proceso, disponible y validación humana.
- `apps/web/src/App.tsx`: migración limitada de botón «Abrir lote», botón «Registrar PDF», etiqueta «Sin validación automática» y avisos de la mesa. No se reescriben formularios, estado ni contratos de API.

## TDD y verificación

1. **Red:** fallo al importar `Button`/componentes inexistentes; se introdujeron pruebas de etiquetas, HTML nativo y estados ocupados.
2. **Green:** 4/4 pruebas de primitivas aprobadas.
3. **Refactor con TDD:** se detectó clase `info` ausente mediante nueva expectativa (1 fallo), se corrigió; después una nueva expectativa impidió usar estilo de validación para `ready` (1 fallo), se separaron ambos estados.
4. **Gate final:** `pnpm exec vitest run apps/web/src/ui/primitives.test.tsx`, `pnpm typecheck`, `pnpm test:browser` y `sh scripts/ci.sh`. Registrar el éxito de este último solo después de ejecutarlo.

## No cambiado / decisiones conservadas

- Ninguna solicitud a backend, semántica de roles, doble revisión, exportación JSON ni PDF en cuarentena se modifica.
- `Button` mantiene clases originales, tamaño mínimo de 46 px y comportamiento de formulario.
- `InlineAlert` comunica errores y confirmaciones sin inventar éxito ni aprobación automática.
- Se conserva React, CSS nativo y TypeScript; no se instalan dependencias ni se usa GitHub Actions para decidir integración.
- Los componentes no sustituirán autorizaciones del servidor ni se compartirán en paquete externo sin segundo consumidor.

## Pendiente en DS-002.2

Migrar por etapas `Field`, `SelectField`, `TextareaField`, `Card`, `EmptyState` y `LoadingState`. Evitar un refactor general de `ReviewWorkspace.tsx` o `CommissionAdmin.tsx` en un único PR. En IA-001 llegará la navegación por tareas, sin métricas o permisos inventados.
