# UX-3.1 — Bandeja contextual de observaciones

**Fecha:** 2026-11-19. **Estado:** incremento frontend sujeto a gate local y PR independiente.  
**Plan matriz:** `docs/UX_FRONTEND_PREMIUM_ROADMAP.md` (UX-3: flujos de revisión y evidencia).

## Resultado

La lista documental mantiene su historial completo y agrega filtros **solo sobre los registros ya cargados**:

| Vista | Selección | Semántica |
| --- | --- | --- |
| Todas | `all` | Lista ya cargada, orden original del backend |
| Para revisar | `status=in_review && canReview===true` | El servidor expresa elegibilidad de revisión para la identidad actual |
| Mis borradores | `status=draft && canSubmit===true` | El servidor expresa elegibilidad de envío |
| Decisiones | `status=validated || dismissed` | Decisiones humanas finalizadas, no acta oficial |

Los filtros operativos solo aparecen si el contexto actual permite redactar. Los observadores ven únicamente «Todas» y «Decisiones». Todas las acciones siguen sujetas a verificación en API; **las capacidades del frontend no autorizan ninguna operación**.

Se introduce `apps/web/src/ui/ObservationInbox.tsx`: filtros con botones nativos `aria-pressed`, recuentos de registros *cargados* y selector puro y testeable. `ReviewWorkspace` incorpora las vistas, restablece una justificación/confirmación incompleta cuando el usuario cambia de filtro y preserva el control de paginación incluso en vistas sin coincidencias.

Las etiquetas de estado existentes migran a `StatusBadge`: borrador, en revisión, validación interna y descartada; nunca se transmite una aprobación automática mediante el color.

## Paginación: límite de información

La API proporciona un historial por páginas de hasta 25 observaciones. Los filtros son locales, de modo que **«Para revisar (0)» significa «ningún registro elegible entre los cargados»**, no que no existan pendientes en la comisión. El texto y la posibilidad de consultar páginas anteriores permanecen visibles, incluso cuando un filtro no tiene resultados. Cada carga adicional actualiza los contadores locales. No se agrega un endpoint de totales ni una consulta duplicada.

El resumen IA-001.2 conserva su alcance original: primera página de historial, que puede ser menor que el subconjunto filtrado tras paginar. En el futuro, una bandeja global de «pendientes para mí» exigiría un endpoint autorizado con paginación filtrada en origen.

## TDD y trazabilidad

1. **Red:** `apps/web/src/ui/ObservationInbox.test.tsx` falla sin `ObservationInbox`.
2. **Green:** cuatro contratos pasan: selección con capacidades de servidor, orden, texto sobre paginación, accesibilidad nativa y lectura sin cambios.
3. **Browser E2E:** tres escenarios Playwright por rol, con historial de 31 registros, carga de siguiente página, creación por un autor distinto, validación por segundo revisor y revisión de accesibilidad axe/overflow.
4. **Regresión:** la historia sigue visible en «Todas»; una vista filtrada vacía no oculta «Cargar observaciones anteriores». El filtro no produce solicitudes de red.
5. **Integración:** `sh scripts/ci.sh` en worktree aislado, puerto Playwright separado mediante `FOLIO_E2E_PORT`; solo se fusiona en `main` tras salida 0. No utilizar GitHub Actions.

## Restricciones conservadas

- Sin cambios de API, D1/R2, lógica de doble revisión, política de cuarentena, visor del PDF original o credenciales.
- Sin generar un conteo institucional a partir de la primera página.
- Sin datos reales, despliegues ni habilitación del inspector.
- La vista de evidencia inspeccionada sigue restringida al texto autorizado del backend.
- El cambio visual es incremental: no reescribe `ReviewWorkspace` ni incorpora dependencias UI.

## Próximos cortes UX-3

1. **UX-3.2:** jerarquía de la evidencia y preparación de la decisión, sin acceso al PDF original ni automatización de conclusiones.
2. **UX-3.3:** filtros de checklist y lectura documental por estado con prácticas de navegación y rendimiento verificadas.
3. **UX-3.4:** refinamiento de informes internos y retroalimentación de integridad, sujeto a investigación con usuarios.
