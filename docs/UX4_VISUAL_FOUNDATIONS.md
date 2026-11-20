# UX-4.1 — Consolidación visual de la mesa documental

**Fecha:** 2026-11-19. **Tipo:** incremento visual y de accesibilidad del frontend.  
**Base:** `origin/main` tras UX-3.4; sin nuevas dependencias, sin rebranding ni cambios de API.

## Alcance implementado

- **Jerarquía tipográfica:** mantiene la voz institucional de Folio Cívico; armoniza títulos de página, encabezados de panel, tarjetas y texto introductorio mediante tokens semánticos. El ancho de lectura recomendado es `66ch`.
- **Superficies y profundidad:** capa ambiental sutil del lienzo, elevación discreta de selección de comisión, navegación, resumen, paneles y tarjetas. Las tarjetas no se presentan como elementos clicables por tener sombra.
- **Acciones y selección:** contraste existente preservado; botones secundarios y enlaces de navegación tienen respuesta visual al hover, y los expedientes seleccionados mantienen un borde de estado inequívoco.
- **Accesibilidad por teclado:** enlace **«Saltar al contenido principal»** como primer elemento enfocable, visible únicamente al recibir foco, con destino `main#main-content`. No altera URL de comisión/lote salvo el fragmento si se activa.
- **Responsividad:** medidas de cuadrícula con `minmax(0, …)`, bloques que pueden envolver texto largo, espaciado reducido y reflujo adaptativo a 600 y 850 px.
- **Movimiento:** interacciones breves y discretas; la preferencia `prefers-reduced-motion: reduce` desactiva transiciones y scroll animado. No se añaden animaciones decorativas.
- **Tokens UX-4.1:** `surface-wash`, `shadow-shell/card`, `reading-measure`, `heading-md/sm`, `line-body`, `motion-medium`. La paleta se mantiene en tema claro y sin introducir estilos de aprobación institucional.

## Verificación TDD

1. **Red:** cuatro contratos de `tests/ux4-visual-foundations.test.ts` fallaron antes de implementar enlace, tokens y estilos.
2. **Green:** los cuatro pasaron tras incorporar el cambio; las pruebas previas de tokens DS-001 siguen pasando.
3. **Browser E2E:** `tests/browser/ux4-visual.spec.ts` incluye teclado/skip link, estilo calculado de la jerarquía y controles, lectura sin scroll horizontal, axe-core, preferencia de movimiento reducido y foco visible.
4. **Matriz:** escritorio 1366 px, Pixel 7 y reflow 320 px: **9/9** pruebas específicas aprobadas.
5. **Regresión Red → Green:** el primer CI local detectó que la prueba de teclado heredada asumía Comisión como primer destino de `Tab`. El enlace de salto añade legítimamente un destino previo; se amplió el contrato para comprobar explícitamente el salto **y luego** Comisión. Las 3 variantes de la prueba corregida pasan (escritorio, móvil y 320 px).
6. **Gate de integración:** `sh scripts/ci.sh` desde un worktree aislado y sincronizado con `origin/main`, con puerto Playwright único, incluyendo Vitest, Python, workerd, TypeScript, builds, Chromium/axe y D1 local. Registrar resultado real antes de fusionar; **GitHub Actions no se usa como gate**.

## Principios de calidad

- No convertir estados «procesando», «texto disponible» o «validación interna» en afirmaciones de aprobación automática.
- Conservar controles y componentes semánticos existentes, así como la autorización de Workers.
- Sin dependencias de fuentes externas, bibliotecas CSS, imágenes artificiales ni servicios remotos.
- No depender exclusivamente de color o sombra para expresar el estado de la evidencia.
- No tratar pruebas automatizadas de axe como reemplazo de pruebas manuales con lector de pantalla.
- Mantener selectores legados que la mesa necesita mientras se refina el sistema de diseño gradualmente.

## Pendientes UX-4

- **UX-4.2:** aplicar tokens y patrones a formularios de administración y revisión heredados sin cambiar los flujos de permisos.
- **UX-4.3:** comprobar edición/lectura con zoom 200–400 %, tamaños de letra personalizados, navegadores y lector de pantalla humano; registrar defectos reproducibles.
- **UX-4.4:** revisión visual con usuarios de la comisión y pruebas de comprensión antes de declarar experiencia institucional lista. El CI local exitoso no desbloquea despliegues ni el gate de seguridad del inspector.
