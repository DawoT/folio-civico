# Folio Cívico

**Evidencia para una transferencia ordenada.**

Folio Cívico es una mesa de revisión documental asistida por IA para comisiones de transferencia de gestión en Perú. La comisión constata y valida; la aplicación conserva referencias verificables. **No constituye el aplicativo ni el acta oficial de la Contraloría.**

## Estado real (18 de noviembre de 2026)

- **Implementado:** monorepo TypeScript, reglas de evidencia y permisos, borradores de observación, migraciones D1, API protegida, ingesta PDF a R2 en cuarentena con SHA-256 e idempotencia, descubrimiento de comisiones/lotes por membresía, mesa React con selectores y servidor MCP de **solo lectura**.
- **Verificado:** pruebas unitarias y de integración con SQLite real, JWT firmados con JWKS local simulado, llamadas JSON-RPC MCP y aislamiento de comisiones, integración Vitest dentro de workerd (D1/R2 locales), typecheck, compilación React, dry-run de ambos Workers y migraciones D1 locales.
- **No implementado todavía:** visor del documento, análisis/escáner PDF, OCR, Workflows, observaciones persistentes, exportación DOCX, onboarding, OAuth/Access configurado, herramientas MCP de escritura ni despliegue. La interfaz web inicial solo lista y registra PDFs; no permite ver originales de cuarentena.
- **Seguridad de arranque:** los endpoints protegidos deniegan acceso si faltan las variables de Cloudflare Access o la membresía activa de la comisión. No se aceptan identidades enviadas por el navegador.

Ver [roadmap](docs/ROADMAP.md), [arquitectura](docs/ADR-001-cloudflare-mcp.md), [decisión de ingesta](docs/ADR-002-r2-intake.md), [autorización y descubrimiento](docs/ADR-003-auth-discovery.md) y [modelo de evidencias](docs/EVIDENCE.md).

## Requisitos

Node 24+ y pnpm 12. Versiones verificadas localmente: Node 26 y pnpm 12.21.

```sh
pnpm install
pnpm test
pnpm typecheck
pnpm build
pnpm test:workers
```

`pnpm test:workers` usa `@cloudflare/vitest-plugin` y requiere que el frontend esté compilado (`pnpm build`). Los objetos R2 y consultas D1 de estas pruebas son totalmente locales, sin acceso a recursos Cloudflare remotos.

La compilación primero construye React con Vite y después ejecuta `wrangler deploy --dry-run` para la API y MCP: **no publica Workers**. El frontend se sirve como Static Assets del Worker API, preservando el mismo origen y evitando CORS entre la aplicación y su API.

## Cloudflare

La cuenta Cloudflare está compartida con otros proyectos: **no reutilizar D1, R2 ni credenciales de otros proyectos**.

**Bloqueo comprobado:** el operador de `mcp-folio-civico` no tiene configurado Cloudflare Preview. No se ha creado ni desplegado ningún recurso remoto para Folio Cívico. Es necesaria esa configuración para ejecutar pruebas E2E contra recursos reales de Preview.

Los archivos `apps/api/wrangler.jsonc` y `apps/mcp/wrangler.jsonc` tienen el UUID D1 ficticio `00000000-0000-0000-0000-000000000000` y Access sin configurar. Son deliberadamente **no publicables para datos reales**. Antes del primer despliegue de preview:

1. Crear recursos exclusivos `folio-civico-*` (D1 y R2 privado). El nombre de R2 en Wrangler es todavía un placeholder, no un bucket creado.
2. Reemplazar la referencia D1 en ambas configuraciones, con el mismo UUID y nombre.
3. Crear aplicaciones Cloudflare Access protegidas, con IdP y MFA. Habilitar **Managed OAuth para MCP**; definir el dominio de destino y el AUD correcto.
4. Configurar `ACCESS_TEAM_DOMAIN` y `ACCESS_AUD` de cada aplicación, restringir rutas y deshabilitar rutas `workers.dev`/Preview URL hasta disponer de protección.
5. Validar el control de membresía en D1, registrar y auditar el acceso. No insertar datos reales hasta resolver condiciones de residencia, consentimiento y retención.

Para una base local descartable:

```sh
pnpm exec wrangler d1 migrations apply folio-civico-preview --local --config apps/api/wrangler.jsonc
```

**Importante:** los datos locales de API y MCP pueden usar directorios Wrangler distintos. En producción ambos Workers deben enlazar explícitamente a la misma D1 piloto, no a los datos locales.

## Endpoints de la primera iteración

- `GET /health` en la API, sin información institucional.
- `GET /api/commissions`, lista de comisiones según membresía activa del sujeto verificado.
- `GET /api/commissions/{id}/batches`, lista de lotes de una comisión autorizada.
- `GET /api/commissions/{id}/summary`, sujeto a JWT de Access y membresía activa.
- `GET /api/commissions/{id}/batches/{batchId}/documents`, listado autorizado sin claves privadas de R2.
- `POST /api/commissions/{id}/batches/{batchId}/documents` con `Content-Type: application/pdf`, `X-Document-Filename: <filename-URI-encoded>` e `Idempotency-Key`: almacena PDF en cuarentena (máximo 8 MiB) y registra un original con hash SHA-256. Aún no hay descarga ni visor para estos originales.
- `POST /mcp` (Streamable HTTP), con herramientas de solo lectura `list_my_commissions`, `list_commission_batches` y `get_commission_summary`, sujetas a la misma identidad y membresía.

La mesa inicial de React está en `apps/web` y se construye como Static Assets dentro del Worker API. Obtiene comisiones y lotes según la identidad autenticada, lista archivos, recibe cargas (si el rol y estado lo permiten) y muestra metadatos. No afirma que la revisión o el OCR estén operativos.

El MCP acepta llamadas stateless en el protocolo moderno (cabeceras y sobre `_meta` pertinentes), no expone CORS y deniega solicitudes con `Origin`. Las pruebas JSON-RPC se realizan con una identidad de prueba inyectada y **no acreditan una sesión OAuth real**.

El MCP **no** admite acciones de aprobación, eliminación, firma, envío a la Contraloría ni acceso directo a SQL/R2.

## Entrega

No se despliega a producción desde este repositorio sin autorización expresa. Los workflows de CI deben compilar, probar y comprobar migraciones locales. El piloto inicia exclusivamente con documentación ficticia o anonimizada.
