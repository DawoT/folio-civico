# Folio Cívico — Roadmap UX / Frontend Premium

**Estado a 2026-11-20:** incrementos técnicos UX-0 a UX-5.5 integrados en `main`; **UX-5 todavía no cumple la salida humana ni la auditoría manual**.

**Corte de arquitectura original:** 2026-11-19 (America/Lima). **Ejecución:** incrementos pequeños y comprobables sobre React/TypeScript, con CI local obligatorio. **Origen del plan:** `docs/ux-frontend-premium-roadmap`; seguimiento actualizado en la sección 12.
**No autoriza:** despliegues, cambio de marca irreversible, gastos, uso de datos reales ni desbloqueo del inspector.

## 1. Resultado de producto

Transformar una mesa documental React funcional en una herramienta institucional **clara, elegante, confiable y accesible** para comisiones de transferencia de gestión de Perú. El diseño premium se define por **claridad de estado, bajo esfuerzo cognitivo, continuidad de tareas, evidencia visible y conducta predecible**; no por efectos decorativos.

### Principios no negociables

1. **Primero la tarea, luego la entidad técnica.** Cada vista responde «¿qué debo hacer ahora?» y «¿qué cambió?».
2. **Nunca insinuar validación automática u oficial.** Separar `pending`, `quarantined`, `in_review`, `validated`, `dismissed`; no confundir ausencia observada con irregularidad comprobada.
3. **Evidencia antes que apariencia.** Identidad de autor y revisor, estado, fecha, versión, SHA-256 y referencia de página donde corresponda. Sin visor del PDF original en cuarentena.
4. **Roles seguros y legibles.** Operador, presidencia, miembro autor, segundo revisor, asesor y observador; no mostrar acciones que el backend nunca permitirá. El frontend no reemplaza autorización servidor.
5. **Accesibilidad estructural.** WCAG 2.2 AA como objetivo verificable (automatizado + manual), teclado y foco visible, reflujo a 320 px, semántica real de controles, mensajes y estados con texto y no solo color.
6. **Conservar la marca.** Profundizar la identidad `Folio Cívico — Evidencia para una transferencia ordenada` y su sobriedad; refinar el isotipo en otra decisión, no inventar rebranding en una refactorización.
7. **Simplicidad arquitectónica y entregas pequeñas.** React + Vite + TypeScript + CSS variables como primera opción; componentes propios mínimos; no incorporar un framework UI, router, motor de estado o CSS-in-JS sin necesidad demostrable.
8. **Proteger lo que funciona.** Conservar los endpoints, contratos, idempotencia, el flujo de dos personas, la verificación de exportación y las restricciones de cuarentena.

## 2. Línea base histórica verificada y límites

Esta tabla es la **fotografía previa** al programa UX (19 de noviembre), no un inventario del código actual. Los cambios posteriores están trazados en la sección 12 y en [UX-0](UX_BASELINE_2026-11-19.md).

| Área | Existe hoy | Brecha principal |
| --- | --- | --- |
| UI | `apps/web/src/App.tsx`, `ReviewWorkspace.tsx`, `CommissionAdmin.tsx`, `InspectedTextViewer.tsx` | Vista larga con administración mezclada con trabajo, mucha densidad y jerarquía por entidades |
| Estilos | `apps/web/src/styles.css`, ~16 KiB de reglas, paleta verde + azul tinta, botones, tarjetas, mensajes | Valores fijos repetidos, sin tokens semánticos, sin componentes reutilizables formales |
| Navegación | Selección comisión/lote y parámetros de URL, lista y detalle de observaciones | Sin shell por tareas, menú por rol, vista de resumen ni navegación consistente entre áreas |
| UX de seguridad | Mensajes de cuarentena, condición de segunda revisión, estados de error y export SHA-256 | Falta lenguaje de estados unificado y orientación contextual |
| Pruebas | Playwright/Chromium con axe y teclado en tres formatos; Vitest para API/UI | Falta regresión visual intencional, lectores de pantalla, usabilidad humana y métricas de tareas |
| Demo | PR #7 (`feat/local-guided-demo`), navegador+API real local con JWT sintético y SQLite/R2 simulado; CI verde en GitHub al corte | No está integrado en `main` y no hay Preview público/privado |
| Procesamiento | PDF original aislado, texto por página solo tras inspección firmada | Scanner remoto e imagen de inspector aún bloqueados por seguridad |

**La investigación de CVEs y los worktrees de seguridad son independientes.** El roadmap de UX nunca debe usar la demo o las pruebas locales como justificación para habilitar Cloudflare Preview, OCR, antivirus, Queue o expedientes reales.

## 3. Dirección visual «Folio Premium»

**Sensación:** precisión, serenidad institucional, autoridad sin rigidez, transparencia documental.

- **Color:** conservar verde profundo (`#075c57` como referencia visual existente), tinta azul oscuro (`#172740`), superficies suaves (`#f5f7f6`) y advertencias funcionales. Evitar saturación y usar semántica de estados verificada en contraste.
- **Tipografía:** jerarquías claras para título, subtítulo, cuerpo, metadatos y referencias técnicas; sistema de fuente local/fallback que no dependa de CDN; monoespaciada solo para ID/hash/citas; no equiparar tamaño pequeño con profesionalidad.
- **Ritmo:** espaciado modular de 4/8 px, máximo de contenido adaptativo, puntos de ruptura derivados de composición y no solo dispositivos, densidad elegible para formularios y evidencias.
- **Superficies:** paneles sobrios, bordes de bajo contraste, radios contenidos, hover/focus consistentes; sombras mínimas y únicamente para elevación real (menús/diálogos).
- **Iconografía:** un solo lenguaje vectorial con etiquetas accesibles; nunca depender de iconos para transmitir un estatus.
- **Movimiento:** transiciones breves y funcionales, respetando `prefers-reduced-motion`; ningún efecto que ralentice la revisión o oculte la confirmación.
- **Contenido:** español claro para personal administrativo, verbos de acción concretos y microcopy que distinga «revisado por una persona», «en cuarentena», «sin resultados en este alcance» y «validación interna».

### Familias de tokens de la propuesta original (implementación posterior en `apps/web/src/ui/tokens.css`)

```text
--fc-color-text-primary / secondary / muted
--fc-color-surface-base / raised / subtle
--fc-color-border-default / strong / focus
--fc-color-action-primary / primary-hover / disabled
--fc-color-status-pending / quarantined / reviewing / validated / dismissed / error
--fc-space-1 ... --fc-space-12
--fc-radius-sm / md / lg
--fc-shadow-menu / dialog
--fc-font-body / mono
--fc-type-title / heading / body / label / caption
--fc-motion-fast / normal
```

Ningún token semántico se considera aprobado hasta comprobar contraste sobre sus combinaciones de fondo y texto. Evitar duplicar `#hex` dentro de componentes.

## 4. Arquitectura de información orientada a tareas

**Contexto persistente:** comisión activa, lote opcional, rol visible, estado del alcance, usuario, ruta actual. El contexto no se pierde al volver a una sección.

| Destino | Necesidad del usuario | Acción principal | Visibilidad |
| --- | --- | --- | --- |
| Resumen | Qué está pendiente, en revisión, validado y qué requiere mi atención | Ir a siguiente tarea autorizada | Miembros autorizados |
| Expedientes | Registrar lotes, consultar versiones, confirmar cuarentena y estado de procesamiento | Abrir lote / registrar PDF | Según permiso de edición |
| Checklist | Ver ítems, cobertura y búsquedas validadas | Revisar alcance / abrir evidencia | Lectura para integrantes autorizados |
| Observaciones | Crear borrador, enviarlo, realizar revisión distinta, consultar historial | Registrar búsqueda / revisar solicitud | Acciones según rol y autoría |
| Informes | Exportar revisión interna con integridad comprobable | Descargar JSON verificado | Lectura para autorizados |
| Administración | Gestionar miembros, roles, lotes e ítems | Gestionar comisión | Presidencia / operador según contrato |

**Navegación:** escritorio con shell y menú contextual; móvil con menú accesible y encabezado de contexto compacto, nunca seis pestañas horizontales comprimidas. Migas y navegación de retorno. Mantener enlaces profundos a observación/evidencia; preservar `commission` y `batch` existentes. Una migración gradual a rutas se justifica solo si disminuye complejidad y pasa pruebas de historial y enlaces.

**Restricciones:** el panel de administración no ocupa la parte superior del flujo documental; la observación no debe desplazarse entre múltiples formularios para completar una revisión; la visibilidad de operaciones se determina por estado y permisos, no solo por la ruta.

## 5. Entrega por incrementos

> Esfuerzo aproximado para una persona con herramientas de IA, sujeto a descubrimientos. Son rangos de planificación, no compromisos de fecha.

### UX-0 — Definir baseline y flujo (3–4 días)

**Entregables:** inventario de componentes y estados; mapa de navegación actual, capturas de desktop (1366), tablet, móvil (390 y 320); user journeys de presidencia, autor, revisor y observador; lista priorizada de fricciones; baseline de bundle/performance y accesibilidad.

**Historias principales:**
- Presidente: «Identifico la comisión y abro el lote sin desplazarme por administración».
- Autor: «Encuentro el ítem, documento el alcance y sé que el borrador no está aprobado».
- Revisor: «Veo qué solicitudes esperan mi decisión, examino evidencia y valido o descarto con una justificación».
- Observador: «Encuentro decisiones y exportación, sin controles de modificación».

**Aceptación:** mapa de tareas y estado por rol aprobado, evidencias de 4 recorridos y línea base de medidas (sin afirmar métricas que aún no existen). Auditoría y hallazgos vinculados a código y pruebas.

### UX-1 — Folio Design System v0.1 (1–2 semanas)

**Entregables:**
- `apps/web/src/ui/tokens.css` (tokens semánticos CSS; modo claro inicial).
- Primitivas React tipadas con API estable: `Button`, `Field`, `SelectField`, `TextareaField`, `Card`, `StatusBadge`, `InlineAlert`, `EmptyState`, `LoadingState` y `ConfirmAction`.
- Pequeña página interna de catálogo/estados de componentes, solo local y sin exposición productiva.
- Estados `default/hover/focus/disabled/loading/error/success`; tamaños compatibles con interacción táctil.
- Migración **por pantalla**, no reescritura masiva, para conservar comportamiento.

**Aceptación:** cero hex nuevos fuera de tokens salvo excepciones justificadas; foco visible en todas las primitivas; texto, icono y color para estados; contraste WCAG objetivo en variantes; pruebas unitarias de componentes, regresión Playwright de formularios y teclado. No bloquear la entrega por introducir Storybook o un paquete externo: evaluar su coste si el catálogo simple deja de servir.

### UX-2 — Shell, navegación y resumen de comisión (1–2 semanas)

**Entregables:** shell responsivo, identidad y contexto de sesión, menú por tareas/roles, breadcrumbs, estado de comisión, pantallas vacías claras, vista resumen compacta con cifras basadas exclusivamente en API real/autorizada.

**Dependencia funcional:** antes de mostrar «pendientes para mí» o recuentos, confirmar que el API dispone de agregaciones por comisión y rol; si no existen, iniciar con navegación y estados reales disponibles, sin inventar estadísticas ni cargar todos los registros para contarlos.

**Aceptación:** cambio comisión/lote sin perder orientación; navegación con teclado y lector de pantalla; no hay scroll horizontal a 320 px; persistencia de deep links; la presidencia gestiona sin interferir en flujo documental; observadores no ven controles de edición. Verificar retorno desde detalle e historial.

### UX-3 — Flujos de revisión y evidencia (2 semanas)

**Entregables:**
- Explorador de expedientes con estado de cuarentena/versión y filtro básico útil; no exponer PDF original.
- Checklist accionable: distinguir «pendiente», «búsqueda documentada», «en revisión», «no ubicado · validación interna», «ubicado» cuando realmente respaldado.
- Cola contextual de observaciones; revisión humana con evidencia y justificación legibles, confirmación diferenciada, feedback irreversible claro.
- Detalle de observación con autor, revisor, fecha, tipo de evidencia, versión+SHA-256+página **solo cuando exista inspección válida**.
- Exportación interna con comprobación de integridad y explicación de qué representa el JSON; no llamarlo acta oficial.

**Aceptación:** en navegador con API real local del PR de demo, autor → borrador → enviar → revisor distinto → validar → checklist → abrir detalle → exportar y verificar SHA-256, sin interceptar el backend; permisos siguen fallando cerrado; no hay rutas de PDF original; volver/actualizar no duplica operaciones idempotentes.

### UX-4 — Acabado premium y confianza (1 semana)

**Entregables:** refinamiento de tipografía, layout, ritmo, tablas/listas largas, truncamiento accesible, densidad adaptable, microcopy institucional, vacíos, errores, bloqueos, carga, toasts/avisos y confirmaciones (solo si son necesarios); iconografía y movimiento coherentes.

**Aceptación:** cada acción importante tiene feedback visible y anunciable; formularios conservan contexto y clave de reintento; no hay cambios inesperados de layout en operaciones frecuentes; zoom a 200/400 % según WCAG aplicable; `prefers-reduced-motion` sin transiciones perturbadoras.

### UX-5 — Calidad, investigación y preparación de piloto (1–2 semanas)

**Entregables:** regresión visual determinista en desktop/móvil, revisión manual WCAG 2.2, prueba de teclado y al menos un lector de pantalla compatible; 5–8 sesiones moderadas con **participantes humanos autorizados** en entorno y expedientes sintéticos (sin datos institucionales reales), medición de tareas y mejoras priorizadas. Las pruebas automáticas no se cuentan como personas participantes.

**Aceptación:** 0 infracciones axe conocidas en pantallas/estados cubiertos; flujos críticos completables sin ratón; sin overflow a 320 px; 100 % de verificaciones de permisos y cuarentena conservadas; métricas de tareas y problemas de usabilidad documentados; `pnpm test`, `pnpm test:browser`, `pnpm test:demo`, `pnpm typecheck`, `pnpm build` y `sh scripts/ci.sh` verdes.

**Condición de salida:** el resultado de UX-5 habilita presentar una experiencia local de alto nivel, pero **no** autoriza recursos remotos, documentos reales ni lanzamiento institucional sin los gates R1/R3.

## 6. Priorización de tickets y cortes de producto

| Orden | Ticket | Tipo | Dependencia | Valor |
| --- | --- | --- | --- | --- |
| P0 | UX-001 Baseline de journeys, pantallas y accesibilidad | Documentación/pruebas | Ninguna | Evita rediseñar sin evidencia |
| P0 | DS-001 Variables semánticas de color/espaciado/tipo/estados | Infra UI | UX-001 | Consistencia sostenible |
| P0 | DS-002 Button, Field, Select, Alert, Status, Card | Componentes | DS-001 | Reutilización / accesibilidad |
| P0 | IA-001 Shell por tareas y contexto de comisión | UX/frontend | DS-002 | Hallazgo crítico: administración mezclada |
| P0 | DEMO-001 Adaptar la demo local a la nueva navegación | Pruebas | IA-001, PR#7 | Demostración convincente |
| P1 | IA-002 Resumen por rol con datos verificables | Producto/frontend | IA-001, API si precisa | «Qué hago ahora» |
| P1 | FLOW-001 Expedientes y cuarentena con estados claros | UX/frontend | DS-002, IA-001 | Menos errores |
| P1 | FLOW-002 Checklist → observación → revisión independiente | UX/frontend | FLOW-001 | Valor central |
| P1 | FLOW-003 Detalle y export verificado | UX/frontend | FLOW-002 | Trazabilidad |
| P2 | FINISH-001 Pulido visual, contenido y percepción de calidad | UI/copy | P0/P1 | Confianza y legibilidad |
| P2 | QA-001 Visual regression, SR, research, performance | Calidad | P0/P1 | Estabilidad y evidencia |

### Corte A — Demo premium (antes de la transformación integral)

UX-001 + DS-001 + DS-002 + IA-001 + adaptación de demo + flujo actual conservado. **Éxito:** experiencia visual coherente, contexto claro, roles comprensibles, demo E2E verde. *No necesita sumar nuevas funcionalidades backend ni OCR.*

### Corte B — Piloto UX de alta calidad

IA-002 + FLOW-001/002/003. **Éxito:** las tareas frecuentes se realizan desde una estructura orientada a trabajo y todas las decisiones son trazables. Depende del API autorizado para datos agregados y estados reales.

### Corte C — Preparación de experiencia institucional

FINISH-001 + QA-001, investigación, documentación y métricas. **Éxito:** accesibilidad combinada automatizada/manual, rendimiento medido y validación con perfiles objetivos. La autorización institucional/remota sigue siendo otro proceso.

## 7. Arquitectura técnica incremental

No crear un monorepo nuevo ni dividir a `packages/ui` sin un segundo consumidor real. Estructura propuesta dentro de `apps/web/src`:

```text
src/
  ui/
    tokens.css
    primitives/
      Button.tsx
      Field.tsx
      Card.tsx
      StatusBadge.tsx
      InlineAlert.tsx
    patterns/
      ConfirmAction.tsx
      EmptyState.tsx
      LoadingState.tsx
  layout/
    AppShell.tsx
    CommissionContext.tsx
    TaskNavigation.tsx
  features/
    commissions/
    documents/
    checklist/
    observations/
    reports/
    administration/
```

La migración es **estranguladora**: un nuevo componente o vista envuelve la lógica y API existentes, con tests antes de retirar la versión previa. Nunca mover toda `App.tsx` o `ReviewWorkspace.tsx` en una sola PR. Extraer estado y navegación solo cuando exista una necesidad concreta. Compartir componentes puros; la validación de permisos del servidor permanece en Workers/D1.

**Recomendaciones:** CSS custom properties antes que framework CSS; React/TS antes que dependencias nuevas; iconografía SVG homogénea con licencia verificada; no fuentes remotas obligatorias; dark mode no es prioridad hasta validar el modo claro; ningún uso de IA visible sin un flujo supervisado implementado y evaluado.

## 8. Instrumentación y métricas

Establecer **línea base** durante UX-0; los siguientes son **objetivos propuestos, no resultados medidos**.

| Métrica | Cómo medir | Umbral propuesto |
| --- | --- | --- |
| Éxito de tareas críticas | Sesiones moderadas por rol: seleccionar comisión, subir PDF, documentar búsqueda, revisar, exportar | ≥80 % sin asistencia en piloto inicial; revisar según tamaño de muestra |
| Tiempo hasta la acción principal | Medición por tarea con prototipo/datos ficticios | Mejoría respecto a baseline en cada iteración; cuantificar tras UX-0 |
| Errores de navegación/permisos | Observación cualitativa + logs sin datos sensibles | Cero navegación que induzca a operar sin privilegios |
| Accesibilidad | axe + teclado + revisión humana de WCAG 2.2 AA | 0 violaciones automáticas en cobertura; errores manuales bloqueantes corregidos |
| Reflujo / responsividad | 320, 390, 768, 1366 px + zoom | Cero desbordamiento horizontal no intencional en journeys principales |
| Rendimiento y peso | Lighthouse/Playwright con hardware y red declarados | No degradación injustificada frente al baseline; presupuesto de JS definido después de medir |
| Integridad documental | E2E con JSON y prueba negativa | 100 % exportados descargados pasan SHA-256; contenido alterado bloqueado |
| Seguridad de cuarentena | Pruebas de API/browser | 0 accesos UI al original no inspeccionado y 0 elevaciones de rol |

Para telemetría futura, usar eventos de interacción agregados y sin identificadores personales, nombres de archivos ni contenido de documentos; requerirá revisión de privacidad antes de activarse en remoto.

## 9. Calidad y estrategia de integración

**Regla por incremento:** pequeño PR propio → tests Red/Green/Refactor → typecheck → build → Vitest → browser y axe → comparación visual donde corresponda → CI verde → revisión → merge independiente. Ningún trabajo de UX desactiva condiciones de seguridad del backend ni el gate de imagen de inspector.

Pruebas prioritarias:
- `AppShell`: navegación y rol, retorno y deep links, estados sin comisión asignada.
- Componentes: variantes semánticas, deshabilitado, error, loading, focus-visible, lector de pantalla.
- Flujos: dos identidades distintas, reintentos idempotentes y revisión no autoaprobada.
- Export: JSON y huella SHA-256; falla bloqueante ante alteración.
- UI/contratos: cero accesos al PDF original en cuarentena.
- Navegador: desktop, Pixel móvil, 320 px + teclado; más matriz manual WebKit/Firefox al madurar.

**Dependencia resuelta:** el [PR #7](https://github.com/DawoT/folio-civico/pull/7) integró `pnpm demo:local` y `pnpm test:demo` en `main` el 20 de noviembre de 2026. `scripts/ci.sh` incorpora su E2E Chromium contra `handleApiRequest` local, JWT firmados, SQLite y R2 simulado. Este ensayo **no** acredita Access/MFA ni Cloudflare Preview reales, scanner/OCR ni una sesión con participantes.

## 10. Decisiones excluidas deliberadamente

- No implementar landing comercial ni branding completo como prerequisito del flujo del producto.
- No recrear un dashboard con estadísticas inventadas: obtener datos agregados de endpoints autorizados o mostrar estados verificables.
- No sumar gamificación, animaciones decorativas, modo oscuro o IA «de escaparate».
- No crear un design system empaquetado multiapp antes de tener un segundo consumidor.
- No mostrar PDF original en cuarentena, aunque un visor visual mejore la impresión de demo.
- No condicionar el rediseño a OCR, Containers ni Preview, ni usar la demo para eludir controles de despliegue.

## 11. Primer incremento autorizado de bajo riesgo (secuencia histórica)

**UX-0 / DS-001**, en PR independiente, estrictamente frontend/documentación y sin cambios del API:
1. Capturar baseline desktop/móvil, documentar 4 journeys y registrar tres fricciones prioritarias.
2. Proponer escala tipográfica, spacing, radios, paleta semántica y contrastes auditables; añadir `ui/tokens.css`.
3. Migrar solo estilos globales y **un** conjunto acotado de botones/campos a tokens sin alterar layout/función.
4. Añadir tests de regresión para focus, contraste y estados, y ejecutar gates locales.
5. Revisar screenshots antes/después y registrar qué cambió; preservar compacidad y sobriedad.

**DoD UX-0/DS-001:** PR aislado, estado `main` intacto hasta aprobación, capturas y métricas reproducibles, UI sin regresión, CI verde, tokens documentados y pendientes explícitos.

---

## 12. Estado de ejecución verificado (20 de noviembre de 2026)

Este apartado prevalece sobre las referencias históricas a tickets «propuestos», al PR #7 «abierto» y a brechas previas que ya se implementaron. **Integrado en código** no significa **validado con usuarios** ni **aprobado para despliegue**.

| Fase | Evidencia de implementación en `main` | Estado y deuda de aceptación |
| --- | --- | --- |
| **UX-0 / DS-001** | [Baseline](UX_BASELINE_2026-11-19.md), tokens semánticos y contratos; [PR #11](https://github.com/DawoT/folio-civico/pull/11) | Implementado; [PERF-001](UX_FRONTEND_PERFORMANCE_BUDGET.md) limita peso JS/CSS y [PERF-002](UX_FRONTEND_BROWSER_PERFORMANCE_LAB.md) registra FCP/LCP/CLS/TTFB con Chromium local. Lighthouse y tiempos humanos todavía no medidos. |
| **UX-1 / DS-002** | Primitivas tipadas, campos, estados y migración gradual; [PR #12](https://github.com/DawoT/folio-civico/pull/12), [PR #14](https://github.com/DawoT/folio-civico/pull/14) | Implementado y automatizado; accesibilidad manual pendiente. |
| **UX-2 / IA-001** | Navegación por tareas y resumen de comisión; [PR #15](https://github.com/DawoT/folio-civico/pull/15), [PR #18](https://github.com/DawoT/folio-civico/pull/18) | Implementado con límites: «para tu revisión» solo examina la primera página de 25 observaciones, no una cola global. |
| **UX-3 / FLOW-001–003** | Bandeja contextual, evidencia, filtros y exportación con SHA-256; PR [#21](https://github.com/DawoT/folio-civico/pull/21), [#22](https://github.com/DawoT/folio-civico/pull/22), [#23](https://github.com/DawoT/folio-civico/pull/23), [#25](https://github.com/DawoT/folio-civico/pull/25); demo [#7](https://github.com/DawoT/folio-civico/pull/7) | Implementado; recorrido con API real **local** verificado, sin equivalencia a E2E Cloudflare/Access remoto. |
| **UX-4 / FINISH-001** | Jerarquía, formularios, reflujo, contraste emulado y estados documentales; PR [#26](https://github.com/DawoT/folio-civico/pull/26), [#27](https://github.com/DawoT/folio-civico/pull/27), [#30](https://github.com/DawoT/folio-civico/pull/30), [#31](https://github.com/DawoT/folio-civico/pull/31) | Implementado y cubierto por pruebas; quedan NVDA, VoiceOver, zoom real y contraste nativo. |
| **UX-5.1–5.5 / QA-001** | [Aceptación sintética](UX5_PILOT_ACCEPTANCE.md), [protocolo moderado](UX5_MODERATED_STUDY.md), privacidad de agregados y escritura privada; PR [#33](https://github.com/DawoT/folio-civico/pull/33), [#34](https://github.com/DawoT/folio-civico/pull/34), [#36](https://github.com/DawoT/folio-civico/pull/36), [#39](https://github.com/DawoT/folio-civico/pull/39), [#42](https://github.com/DawoT/folio-civico/pull/42) | **Instrumentación aprobada; fase sin cierre humano.** No hay sesiones moderadas acreditadas, resultados humanos, ni auditoría manual de accesibilidad. |

### Demo E2E local incorporada

El [PR #7](https://github.com/DawoT/folio-civico/pull/7) quedó fusionado en `main@03a87d9` después de actualizar su rama contra `origin/main@e0fc8b1`. La misma rama completó `sh scripts/ci.sh` con **exit 0**: 476 pruebas Vitest, 210 de inspector Python (motores simulados), 33 del protocolo UX-5, 8 contratos de CI, 5 workerd, 129 Chromium con API sintética y **1 E2E Chromium de la demo con API real local**; TypeScript, compilaciones dry-run y migraciones D1 locales correctos. El reporte terminó con `CI PASSED`. No se utilizó GitHub Actions como criterio de integración.

La demo verifica JWT firmados localmente, reglas del API, dos identidades distintas, cuarentena, decisión humana y exportación íntegra. D1 usa SQLite de prueba y R2 es un doble en memoria. **No** verifica identidad institucional, Access/MFA remoto, scanner, OCR, Containers ni documentos reales.

### Gates pendientes antes de declarar «UX Premium validada»

1. **UX-5.6 — investigación humana:** reclutar participantes autorizados, obtener consentimiento, usar solo datos sintéticos, observar los cuatro perfiles conforme a [UX5_MODERATED_STUDY.md](UX5_MODERATED_STUDY.md), registrar incidentes privados y corregir defectos reproducibles. Hasta entonces, éxito, satisfacción y tiempos humanos figuran como **no medidos**; no simular sesiones.
2. **Accesibilidad manual:** ejecutar [UX4_ADVANCED_ACCESSIBILITY.md](UX4_ADVANCED_ACCESSIBILITY.md) con NVDA/Firefox, VoiceOver/Safari, zoom nativo 200–400 %, espaciado y alto contraste real, documentando entorno, resultado e issues. Axe/Chromium y `forced-colors` emulado no cierran este gate.
3. **Métricas por tarea y rol:** 5–8 participantes repartidos entre perfiles permiten principalmente encontrar problemas cualitativos; el instrumento exige **al menos cinco intentos de cada tarea** para exponer tasas y medianas internas. Sin ese denominador no publicar porcentajes ni agregados inferibles. Las categorías críticas de confusión de estados bloquean el cierre.
4. **Rendimiento y navegación:** [PERF-001](UX_FRONTEND_PERFORMANCE_BUDGET.md) limita el peso gzip (JS 100 KiB; CSS 10 KiB) y [PERF-002](UX_FRONTEND_BROWSER_PERFORMANCE_LAB.md) añade tres navegaciones Chromium del build de producción con captura nativa TTFB/FCP/LCP/CLS. Ambos se ejecutan en `sh scripts/ci.sh`. **Pendiente:** Lighthouse con perfil de hardware/red reproducible, Core Web Vitals **de campo** (incluido INP) y latencias del flujo completo. Evaluar si una cola de revisiones completa necesita un agregado del backend; nunca sustituir una cifra desconocida por cero.
5. **Seguridad e institución:** cerrar por separado gates del inspector, retención, políticas de privacidad, Access/MFA, autorización y E2E remoto antes de cualquier Preview o producción. La fusión UX no levanta esos bloqueos.

**Próximo punto de reanudación:** UX-5.6, sin construir nuevas métricas sintéticas ni presentar el piloto como aprobado. La coordinación y ejecución de sesiones humanas y lectores de pantalla requiere participantes/equipos autorizados; las correcciones derivadas deben pasar TDD y el CI local antes de integrarse.

---

**Estado del documento:** plan original conservado para trazabilidad, con seguimiento técnico actualizado. La aceptación UX Premium institucional permanece **pendiente**.
