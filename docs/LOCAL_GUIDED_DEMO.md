# Demo local guiada — Folio Cívico

**Propósito:** mostrar la mesa documental ante evaluadores sin Cloudflare remoto, sin credenciales institucionales y sin afirmar que el inspector OCR/antivirus funciona en la nube.

## Arranque reproducible

Requisitos: Node 24+, pnpm 12, dependencias instaladas. Ejecutar **únicamente en el repositorio**:

```sh
pnpm install --frozen-lockfile
pnpm demo:local
# En este mismo equipo: http://127.0.0.1:4176/__demo
```

El servidor está fijado a **127.0.0.1:4176** y exige ese encabezado Host; no escucha en red externa. Antes de servir el frontend, inicia el `handleApiRequest` real en Vite SSR, migra SQLite **en memoria** con las migraciones del repositorio y prepara un R2 **simulado en memoria**. Crea un par RS256 temporal, firma JWT sintéticos y responde localmente al JWKS esperado por `authenticateAccess`. Ningún JWT de navegador controla `Cf-Access-Jwt-Assertion`: el servidor de demo lo reemplaza por su token local. No se conecta a Cloudflare, proveedores de identidad, Queue ni contenedores.

## Recorrido recomendado (10 minutos)

1. En `/__demo`, abre la mesa como **president** y muestra comisiones, miembros, lote y checklist.
2. Regresa a `/__demo`, cambia a **author**, entra a la mesa, confirma el PDF ficticio en **cuarentena** y registra una búsqueda manual del ítem «Expediente de contratación de obra» con descripción y consentimiento. Guarda el borrador y envíalo a revisión.
3. Vuelve a `/__demo`, cambia a **reviewer**. Abre la mesa, pulsa «Revisar registro», escribe una justificación de revisión independiente y valida.
4. Comprueba «No ubicado · validación interna» en el checklist, abre «Ver validación» y exporta el informe interno JSON con huella SHA-256.
5. Cambia a **observer** para mostrar lectura sin controles de modificación.

La creación de observaciones y su segunda revisión utilizan la **API de producción y reglas reales de membresía**, no la API interceptada de `tests/browser/synthetic-api.ts`. La sesión y la base de datos son desechables: **al reiniciar se pierde todo el estado**. Los PDF no se abren ni se procesan; un PDF en cuarentena nunca se transforma automáticamente en evidencia inspectada.

## Verificación automatizada

```sh
pnpm test:demo
pnpm typecheck
pnpm build
```

`pnpm test:demo` **siempre exige arrancar una instancia nueva** y usa Chromium real para recorrer la web y la API sin interceptar `/api/**`. Si el puerto ya está ocupado, la prueba **falla sin reutilizar** un servidor antiguo: un CI local no puede aprobar por error una revisión ajena o un estado previo. El puerto predeterminado es `4176` y puede aislarse por worktree configurando `FOLIO_DEMO_PORT`, por ejemplo `FOLIO_DEMO_PORT=4518 pnpm test:demo` o `FOLIO_DEMO_PORT=4518 sh scripts/ci.sh`; el servidor y Playwright comparten la misma validación de rango `1024–65535`. No usar un puerto ocupado ni `--update-snapshots` para eludir fallos.

## Límites explícitos

- No hay inspección real ClamAV/Poppler/Tesseract, OCR, Queue ni Cloudflare Access/MFA remoto.
- La D1 local es un adaptador SQLite del suite de pruebas; el R2 es una colección en memoria, no almacenamiento real.
- El PDF sintético precargado es un fixture mínimo para ejercitar la ingesta; no es un expediente municipal legítimo ni se puede visualizar.
- No hay URL pública, soporte multiusuario remoto, datos reales ni firma oficial. No presentar esta demo como una instancia desplegada o lista para producción.
- La vulnerabilidad del inspector conserva su gate de liberación independiente: **esta demo no modifica ni levanta ese bloqueo**.

No modificar `apps/api/wrangler.jsonc`, credenciales, recursos Cloudflare ni la política de cuarentena para presentar la demo.
