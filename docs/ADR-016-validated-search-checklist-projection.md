# ADR-016 · Checklist funcional desde búsquedas con validación humana

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementado y probado localmente; sin despliegue.  
**Ámbito:** interfaz React, consulta D1 y endpoint autorizado `GET /api/commissions/{id}/checklist`. No modifica el inspector ni el tratamiento de PDF.

## Problema observado

La aplicación permite registrar una búsqueda de un documento ausente, someterla a revisión interna y validarla por una segunda persona, pero el checklist seguía indicando «Pendiente». El usuario no podía ver el resultado de la decisión en su mesa de revisión.

## Decisión y comportamiento

- La lectura del checklist proyecta **«No ubicado · validación interna»** solo cuando existe evidencia `SEARCH_SCOPE` asociada al ítem y una observación con estado `validated`.
- La autoría, el segundo revisor y la referencia de la observación son datos persistidos y verificados por el flujo de revisión existente; el navegador no los inventa.
- Borradores, observaciones en revisión y descartes **no** alteran el estado mostrado. El ítem `located` o `observed` almacenado tiene prioridad sobre una búsqueda validada anterior.
- La API expone `statusSource: "validated_search"` y `validatedSearchObservationId` para distinguir el resultado derivado del estado institucional original (`statusSource: "stored"`).
- La consulta conserva el aislamiento por comisión y membresía activa. La proyección es reproducible y no genera escrituras ni eventos de auditoría artificiales.
- **No** se modifica `checklist_items.status` en D1: el estado de constatación no implica modificación del checklist oficial y no genera una nueva autorización administrativa. La fuente de verdad sigue siendo la observación y sus evidencias inmutables.

## Validación y límites

TDD sobre consulta D1 real, endpoint de la API y representación React: ausencia provisional, presentación, descarte, decisión independiente, trazabilidad exacta, aislamiento entre comisiones y prevalencia de estados institucionales existentes.

El sistema **no** certifica la inexistencia material del documento, no supone que un PDF en cuarentena haya sido revisado y no autoriza un acta oficial. El flujo de páginas documentales requiere el inspector seguro y acceso a documentos ya admitidos; queda separado.

## Evolución

- Agregar enlace navegable al expediente de observación con paginación de historial, preservando acceso por membresía.
- Definir, con responsables institucionales, si se necesita una transición formal y auditable del checklist además de la proyección informativa; no automatizar esa autorización basándose solo en la validación interna.
