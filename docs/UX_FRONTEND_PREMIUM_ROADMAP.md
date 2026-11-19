# Folio Cívico — Roadmap UX / Frontend Premium

**Estado:** propuesta ejecutable, aún no implementada.  
**Corte de arquitectura:** 2026-11-19 (America/Lima).  
**Responsable técnico previsto:** un ejecutor integral de producto/UX/frontend.  
**Rama de documentación:** `docs/ux-frontend-premium-roadmap`.  
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

## 2. Línea base verificada y límites

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

### Tokens propuestos (no implementados)

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

**Entregables:** regresión visual determinista en desktop/móvil, auditoría humana WCAG 2.2, prueba de teclado y al menos un lector de pantalla compatible; 5–8 evaluaciones moderadas con perfiles representativos (sintéticas o participantes autorizados, sin datos reales), medición de tareas y mejoras priorizadas.

**Aceptación:** 0 infracciones axe conocidas en pantallas/estados cubiertos; flujos críticos completables sin ratón; sin overflow a 320 px; 100 % de verificaciones de permisos y cuarentena conservadas; métricas de tareas y problemas de usabilidad documentados; `pnpm test`, `pnpm test:browser`, `pnpm test:demo` (al integrar PR#7), `pnpm typecheck`, `pnpm build` y `sh scripts/ci.sh` verdes.

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

**Dependencia:** PR #7 entrega `pnpm demo:local`/`test:demo`, y estaba abierto con CI aprobada. UX-0 y UX-1 no dependen de fusionarlo; UX-2/3 deberían añadir este E2E cuando esté integrado, sin copiar lógica entre ramas.

## 10. Decisiones excluidas deliberadamente

- No implementar landing comercial ni branding completo como prerequisito del flujo del producto.
- No recrear un dashboard con estadísticas inventadas: obtener datos agregados de endpoints autorizados o mostrar estados verificables.
- No sumar gamificación, animaciones decorativas, modo oscuro o IA «de escaparate».
- No crear un design system empaquetado multiapp antes de tener un segundo consumidor.
- No mostrar PDF original en cuarentena, aunque un visor visual mejore la impresión de demo.
- No condicionar el rediseño a OCR, Containers ni Preview, ni usar la demo para eludir controles de despliegue.

## 11. Primer incremento autorizado de bajo riesgo

**UX-0 / DS-001**, en PR independiente, estrictamente frontend/documentación y sin cambios del API:
1. Capturar baseline desktop/móvil, documentar 4 journeys y registrar tres fricciones prioritarias.
2. Proponer escala tipográfica, spacing, radios, paleta semántica y contrastes auditables; añadir `ui/tokens.css`.
3. Migrar solo estilos globales y **un** conjunto acotado de botones/campos a tokens sin alterar layout/función.
4. Añadir tests de regresión para focus, contraste y estados, y ejecutar gates locales.
5. Revisar screenshots antes/después y registrar qué cambió; preservar compacidad y sobriedad.

**DoD UX-0/DS-001:** PR aislado, estado `main` intacto hasta aprobación, capturas y métricas reproducibles, UI sin regresión, CI verde, tokens documentados y pendientes explícitos.

---

**Estado del documento:** roadmap propuesto. Ninguna fase UX se declara implementada por el mero hecho de escribir este documento. La ejecución requerirá PRs separados con evidencia de pruebas.
