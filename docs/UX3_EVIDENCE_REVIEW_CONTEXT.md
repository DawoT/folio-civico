# UX-3.2 — Contexto de evidencia antes de decidir

**Fecha:** 2026-11-19. **Alcance:** frontend de Folio Cívico. **Estado:** incremento sujeto a `sh scripts/ci.sh` local en la rama sincronizada con `origin/main`.

## Objetivo

Reducir decisiones erróneas por falta de contexto en el flujo de revisión humana. Cuando un revisor autorizado selecciona `Revisar registro`, la interfaz presenta primero los datos documentales existentes, después la justificación y finalmente la confirmación de responsabilidad personal.

La UX **no afirma autenticidad documental, hallazgo automático ni condición de acta oficial**. Una referencia declarada tampoco significa que el PDF original haya sido inspeccionado.

## Implementación acotada

- Nuevo componente `apps/web/src/ui/ReviewEvidenceContext.tsx` muestra un resumen semántico (`section` con encabezado + `dl` accesible) de autor, fecha del registro, título, alcance de búsqueda y referencias autorizadas provistas por la API.
- Distingue tres tipos: `SEARCH_SCOPE` (lote, ítem, fecha), `DOCUMENT_PAGE` (versión/página y SHA-256 **declarado** solo si los datos pasan validaciones de formato), `OFFICIAL_SOURCE` (referencia a fuente **registrada**, que no presume autenticidad). Los valores se renderizan como texto plano de React: no se generan enlaces remotos, HTML inyectado, iframe ni vista del PDF original.
- Fallback explícito para evidencia ausente, no reconocida o incompleta. Las referencias inválidas no se normalizan a valores ficticios.
- `canPrepareReviewDecision`: guardia defensiva de UI exige un registro en revisión con `canReview===true`, identidad de registro activo coincidente, confirmación expresa y justificación entre 15 y 1000 caracteres; prohíbe operar durante transición. La **validación real permanece en Workers**.
- Mejora textual en el detalle: «Consultando el detalle autorizado» reemplaza «evidencia original» y «referencia a página documental» reemplaza «página verificada» cuando solo hay una cita.
- CSS basado en tokens, con reflujo en móvil, contenido técnico `overflow-wrap`, foco y contraste existentes; no incorpora dependencias.

## Ciclo TDD, criterios y riesgos

1. **Red:** cuatro pruebas nuevas fallaron al importar `ReviewEvidenceContext` inexistente.
2. **Green:** los escenarios verifican autor y alcance, referencias correctas sin enlaces, límites de evidencia, contenido escapado, ausencia de referencias y guardia de revisión.
3. **Integración:** pruebas Playwright con autor y revisor distintos: contexto antes de decidir, justificación insuficiente bloqueada, decisión habilitada con atestación, ausencia de solicitudes adicionales, operación validada; segundo caso sin referencias que cumple axe-core y reflujo.
4. **Gate:** `sh scripts/ci.sh` (Vite/Workers dry-run, Vitest, Python, workerd, TypeScript, Chromium en escritorio, móvil y 320 px, axe y migraciones D1 locales). Solo integrar cuando el resultado final sea `exit 0` sobre base `main` actual.

**No cambia:** autorización backend, doble revisión, idempotencia, registros, exportación JSON, D1/R2, Cloudflare, OCR o antivirus. Las citas de páginas permanecen sin vista del PDF original. Una referencia insuficiente no cambia por sí sola las reglas de validación de dominio.

## Límites y próximo corte

- El registro mostrado en el resumen procede del historial **autorizado** ya cargado. La decisión final se vuelve a validar en el servidor. No se introduce un endpoint nuevo ni se simula verificación de origen.
- El acceso a páginas de texto inspeccionado continúa disponible solamente mediante las condiciones actuales del `InspectedTextViewer`.
- Se requiere investigación con personal de comisión y auditoría manual con lector de pantalla para declarar UX institucional lista.
- UX-3.3 deberá concentrarse en checklist y estados de expedientes sin añadir autorizaciones ficticias ni comprometer cuarentena.
