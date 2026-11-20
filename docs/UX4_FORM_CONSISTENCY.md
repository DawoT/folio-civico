# UX-4.2 — Formularios coherentes de administración y revisión humana

**Fecha:** noviembre de 2026. **Alcance:** frontend (React/TypeScript/CSS), pruebas y documentación.  
**Estado:** incremento aislado, sujeto a `sh scripts/ci.sh` sobre `origin/main` actualizado antes del merge.

## Problema identificado

La consola institucional contaba ya con primitivas de campo accesibles (`Field`, `SelectField`, `TextareaField`), botones y alertas semánticas, pero partes de la administración seguían utilizando controles HTML y estilos repetidos. La justificación del segundo revisor solo comunicaba la longitud mínima en texto estático, sin indicar al usuario cuánto faltaba antes de habilitar las acciones.

## Resultado

### Administración de acceso

- La incorporación de miembros y el alta inicial de comisión reutilizan `Field` y `SelectField` con etiquetas `htmlFor`, descripciones asociadas por `aria-describedby` y ayudas explícitas. No se asume que un correo sea el identificador de Cloudflare Access: se exige registrar el `sub` exacto.
- Los campos de identidad desactivan autocorrección/capitalización y autocompletado (`spellCheck=false`, `autoCapitalize=none`, `autoComplete=off`) para evitar alteraciones involuntarias. **No se modifican valores ni su autorización en la API.**
- La selección de rol para cada miembro utiliza `useId` para generar un identificador de campo estable sin insertar el `sub` en un identificador HTML.
- Los controles de alta usan `Button` con `busy`, y los resultados emplean `InlineAlert` accesible. Se conserva la confirmación de identidad de la presidencia y la prohibición de autorrevocación.
- Formularios responsive con tokens existentes, foco perceptible y reflujo para 320 px.

### Decisión de revisión humana

- Nuevo componente `ReviewDecisionGuidance` expone cuántos caracteres útiles (*trimmed*) faltan de una justificación de al menos **15** y máximo **1000**, además de recordar que la declaración personal es necesaria.
- La guía se asocia mediante `aria-describedby` a `TextareaField`. No se usa una región en vivo por pulsación para evitar saturar lectores de pantalla.
- `ReviewEvidenceContext.canPrepareReviewDecision` reutiliza la misma función `reviewDecisionProgress`, evitando divergencia entre el texto explicativo y la condición de habilitación.
- «Requisitos de formulario completos» no implica autenticidad ni hallazgo validado: se aclara que **el servidor verificará la decisión**.
- Los botones finales siguen requiriendo `canReview` del backend, registro activo, revisión independiente declarada, justificación y ausencia de transición en curso. **La API permanece como autoridad final.**

## TDD y verificación

1. **Red:** las pruebas de guía fallaron al importar el módulo ausente; los contratos de campos administrativos se definieron antes de migrar el formulario.
2. **Green:** pruebas unitarias de cálculo exacto, límites, lenguaje no oficial, HTML semántico, asociación de ayuda, identidad de Access y confirmación inicial.
3. **Browser:** recorridos Playwright con presidencia (creación de miembro + cambio real de rol), segundo revisor (justificación y validación con dos identidades) y observador (sin acciones de modificación).
4. **Accesibilidad:** axe-core WCAG A/AA y verificación de desbordamiento horizontal por caso; matriz desktop/Pixel 7/320 px (ancho de reflujo equivalente a 400 % de zoom sobre un viewport de 1280 px, no sustituto de una prueba manual con zoom real).
5. **CI obligatorio:** `sh scripts/ci.sh` tras incorporar `origin/main` y con `FOLIO_E2E_PORT` aislado. Incluye Vitest, Python, Workerd, TypeScript, Vite/dry-runs, Chromium y migraciones D1 locales. **GitHub Actions no determina la aprobación de este PR.**

## Archivos afectados

- `apps/web/src/CommissionAdmin.tsx`
- `apps/web/src/ReviewWorkspace.tsx`
- `apps/web/src/ui/ReviewEvidenceContext.tsx`
- `apps/web/src/ui/ReviewDecisionGuidance.tsx`
- `apps/web/src/styles.css`
- `apps/web/src/CommissionAdmin.test.tsx`
- `apps/web/src/ui/ReviewDecisionGuidance.test.tsx`
- `tests/browser/ux4-form-consistency.spec.ts`

## Límites y pendientes

No se alteran APIs, D1/R2, políticas de Cloudflare Access, doble revisión humana, cuarentena documental, JSON SHA-256 ni inspector. Sin despliegue remoto.

**UX-4.3:** ejecutar pruebas de zoom real 200–400 %, lectores de pantalla (NVDA/VoiceOver) y tamaños de texto personalizados con operadores representativos; documentar defectos observables antes de declarar accesibilidad institucional plenamente validada.
