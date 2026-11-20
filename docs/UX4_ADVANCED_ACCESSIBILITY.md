# UX-4.3 — Ampliación de texto, reflujo y accesibilidad avanzada

**Corte:** noviembre de 2026  
**Ámbito:** frontend de Folio Cívico; datos sintéticos y pruebas locales.  
**Estado:** implementación automatizada, sujeta al CI local y la integración del PR. **No es certificación WCAG ni auditoría manual de tecnologías de asistencia.**

## Hallazgos confirmados y solución

| Severidad | Hallazgo reproducido con Playwright | Medida aplicada | Evidencia |
| --- | --- | --- | --- |
| Alta | La tipografía principal no aumentaba cuando se duplicaba el tamaño raíz (`html { font-size:32px }`) | Tokens de fuente `rem` y migración de etiquetas, ayudas, notas, botones de lectura, título y datos del expediente | `200% root text preference`, `document filenames and evidence metadata` |
| Alta | Etiquetas del encabezado de documentos (`count`, `read-only`) quedaban **recortadas dentro de contenedores ocultantes** a 320 CSS px + texto al 200 % | `flex-wrap`, tamaño mínimo flexible, envoltura de texto, limitación de ancho y composición responsive | `noHorizontalOverflow`, capturas de regresión durante TDD |
| Alta | Una identidad Access larga y válida (173 caracteres, límite de contrato 200) generaba scroll horizontal por el label de rol | `overflow-wrap:anywhere` en `.fc-field-label` y conservación de `sub` sin truncar | `long identifiers` |
| Media | Los encabezados con `clamp(rem, vw, rem)` solo escalaban 1,7× cuando se solicitaba 2× en escritorio | Encabezados `rem` por tramo de viewport (900/600px), para respetar la preferencia de tamaño raíz | `200% root text preference` en tres viewports |
| Media | Textos de archivo y metadatos de evidencia todavía tenían tamaños fijos en píxeles | Unidades relativas sin cambio de semántica ni política de cuarentena | `document filenames and evidence metadata` |
| Alta | En `forced-colors: active` la selección de un expediente dependía únicamente de `box-shadow`, que desaparece en alto contraste | Borde físico `Highlight` para selección, filtros `aria-pressed` y foco visible; sin depender de color de fondo | `forced-colors preserves visible selected records` |

## Contratos automatizados

`tests/browser/ux4-advanced-a11y.spec.ts` contiene seis escenarios que se ejecutan en **escritorio (1366×900), Pixel 7 y 320×640**: 18 casos totales.

1. **Texto al 200 %:** se fija `font-size:32px` en el elemento raíz y se comparan tamaños computados de contenido introductorio, campos, encabezados, notas y marca; cada tamaño crítico debe alcanzar al menos 1,9× el original. Se confirma que el informe interno sigue disponible.
2. **Expediente al 200 %:** se registra un **PDF sintético en cuarentena** y se comprueba la ampliación del nombre, metadatos y detalle documental sin `iframe`, `embed` ni `object` y sin navegación al original.
3. **Alto contraste:** se emula `forced-colors:active`, se registra un PDF sintético y se comprueba una selección con borde del sistema, la identidad `aria-pressed` de filtros, foco, ausencia de desbordamiento y axe-core.
4. **Espaciado de texto WCAG 1.4.12:** se inyecta estilo de estrés con `line-height:1.5`, `letter-spacing:.12em`, `word-spacing:.16em` y separación inferior de párrafos `2em` en la vista de presidencia. Deben permanecer visibles los campos y permitir incorporar una identidad sintética; axe-core no debe registrar infracciones A/AA y no debe haber desbordamiento horizontal.
5. **Identidades largas:** un `sub` sintético válido con 173 caracteres debe presentarse completo y dejar accesibles los selectores de rol sin scroll horizontal.
6. **Revisión al 200 %:** dos identidades sintéticas separadas crean y revisan un registro. La justificación y atestación deben seguir operativas, la decisión sigue siendo autorizada por la API y la página no tiene desbordamiento; se ejecuta axe-core.

### Límites de interpretación

- **320 CSS px** es una comprobación automatizada de reflujo equivalente al espacio horizontal disponible al ampliar una ventana de 1280 CSS px al **400 %**. **No es una ejecución de zoom nativo al 400 %** y no verifica el comportamiento del menú de zoom del navegador.
- `forced-colors` emulado permite verificar reglas de contraste forzado, pero no sustituye una revisión en Windows High Contrast real.
- `font-size:32px` prueba **una preferencia de texto equivalente al doble del tamaño raíz**. No equivale a zoom de página completo al 200 %, que altera también el viewport efectivo y otros tamaños.
- Las inyecciones CSS de espaciado de texto son una aproximación controlada al criterio WCAG 1.4.12; no garantizan que no existan defectos en todas las combinaciones de usuario/dispositivo.
- La auditoría `axe-core` automatizada no demuestra conformidad integral WCAG ni sustituye el uso por personas con discapacidad.
- No se han utilizado Cloudflare Preview/producción, archivos reales, ni servicios de lector de pantalla.

## Protocolo manual pendiente — no declarar validado sin evidencia

Para una verificación institucional completa deben ejecutarse y registrar los siguientes recorridos usando una instancia de pruebas con datos sintéticos:

| Caso | Herramienta y condiciones | Criterio de aceptación |
| --- | --- | --- |
| Zoom nativo 200 % y 400 % | Chrome y Firefox de escritorio, ventana efectiva de 1280 CSS px antes de ampliar | Sin contenido funcional cortado, scroll horizontal general ni acciones inaccesibles; se pueden abrir comisión, documentos, checklist, observaciones e informes |
| Zoom de solo texto y fuente aumentada | Firefox «Zoom Text Only» y ajuste de fuente de sistema | Etiquetas y ayuda escalan, se leen completas y no colisionan con botones |
| Navegación de teclado | `Tab`, `Shift+Tab`, `Enter`, `Space`, `Escape` donde corresponda | Foco visible, orden lógico, salto al contenido, sin atrapamientos ni pérdidas de foco en estados de error |
| NVDA + Firefox (Windows) | Modos lectura/formulario; anuncios de etiquetas, errores, ayudas, estados | Nombres/roles accesibles, contenido y estado correctos, sin duplicar mensajes o anunciar falsamente aprobaciones |
| VoiceOver + Safari (macOS/iOS) | Rotor, lectura de encabezados y formularios, activación de botones | Navegación semántica coherente; datos de evidencia y decisiones distinguidos de certificación oficial |
| Alto contraste / colores forzados | Windows High Contrast y `forced-colors: active` | Indicadores y foco visibles sin depender exclusivamente de color o sombras |
| Comportamiento de revisión | Autor, revisor distinto, observador, presidencia; zoom y lector de pantalla | Nadie obtiene acciones de otro rol; ninguna validación automática; evidencia original permanece en cuarentena |

**Evidencia que debe adjuntarse a cada corrida manual:** fecha, OS/versión, navegador/versión, AT/versión, tamaño de viewport, zoom, escenario, captura o grabación autorizada, resultado y defecto si existe. Vincular defectos bloqueantes a issues concretos; no redactar una aprobación general sin resultados.

## Calidad, seguridad e integración

- Implementación intencionalmente limitada a `apps/web/src/ui/tokens.css` y `apps/web/src/styles.css`; pruebas nuevas en `tests/browser/ux4-advanced-a11y.spec.ts`.
- Sin JavaScript de aplicación, nuevos endpoints, migraciones, paquetes, datos reales o cambios en permisos.
- TDD: primero falló la prueba de escalado; después se descubrió recorte de indicadores y scroll horizontal en el campo con identidad larga; se corrigió cada causa y se repitió la matriz.
- **Gate del PR:** `FOLIO_E2E_PORT=<puerto aislado> sh scripts/ci.sh` sobre `origin/main` actualizado, sin utilizar GitHub Actions como aprobación. Incluye Vitest, pruebas Python y workerd, TypeScript, builds, Chromium con axe y migraciones D1 locales.

## Seguimiento

UX-4.4 debe incorporar investigación contextual con usuarios y revisión visual sobre tareas reales, usando datos sintéticos. Los casos manuales anteriores permanecen **pendientes** hasta su ejecución efectiva. No desbloquear Preview, inspector ni producción en base a este incremento de UI.
