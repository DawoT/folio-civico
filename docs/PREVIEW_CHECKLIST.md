# Cloudflare Preview · habilitación segura y criterios de aceptación

**Estado comprobado el 2026-11-18:** el operador del conector `mcp-folio-civico` responde **“Cloudflare preview is not configured by the operator”**. No existe un entorno remoto Folio Cívico disponible para este flujo. El UUID D1 de Wrangler es un placeholder (todo ceros), y las variables `ACCESS_TEAM_DOMAIN` y `ACCESS_AUD` están vacías.

Este documento prepara la activación; **no ejecuta** la creación de recursos, un despliegue ni una configuración de Access. La cuenta Cloudflare contiene otros productos que no deben modificarse.

## Gate 0 · Aislamiento, permisos y costos

Antes de iniciar, el titular de la cuenta debe autorizar explícitamente el entorno de pruebas, el tratamiento de datos exclusivamente ficticios, los posibles costos R2/D1/Workers/Access y el acceso del operador MCP a **recursos exclusivos de Folio Cívico**. Revisar cuotas, límites de consumo y presupuestos.

Comprobar cuenta destino, titular y recursos existentes. Nunca reutilizar bindings, bases D1, R2 ni credenciales de otros productos. No desplegar un Worker que tenga rutas de gestión desprotegidas.

## Gate 1 · Recursos de preview dedicados

Con acceso autorizado, crear una D1 con nombre `folio-civico-preview` y un bucket R2 **privado** con nombre `folio-civico-quarantine-preview`. Los comandos del CLI actual para crear los recursos son:

```sh
pnpm exec wrangler whoami
pnpm exec wrangler d1 create folio-civico-preview
pnpm exec wrangler r2 bucket create folio-civico-quarantine-preview
```

**No ejecutar esos comandos hasta contar con autorización para gastos y confirmar que no existe ya un recurso con ese nombre.** La creación es un procedimiento administrativo, no un paso de CI.

Copiar el `database_id` real recibido de D1 en los dos archivos `apps/api/wrangler.jsonc` y `apps/mcp/wrangler.jsonc`, con el **mismo UUID**. Nunca usar `00000000-0000-0000-0000-000000000000` para un despliegue.

El bucket no debe habilitar dominio público ni acceso sin autenticar. Validar configuración de ciclo de vida/retención y plan de reconciliación de objetos en cuarentena antes de recibir documentos reales.

## Gate 2 · Hostnames y Cloudflare Access

Asignar hostnames propios y distintos, bajo dominio administrado por la entidad o el piloto autorizado. No suponer un dominio real ni usar URLs predeterminadas `workers.dev`/Preview URL para saltarse Access.

1. Crear aplicación(es) de Cloudflare Access de alcance exclusivo para el hostname de la API y el de MCP.
2. Configurar proveedor de identidad y MFA; emitir políticas de acceso restringidas a los participantes del piloto. Probar explícitamente denegación a quien no pertenezca al piloto.
3. Copiar `ACCESS_TEAM_DOMAIN` completo y el `ACCESS_AUD` correspondiente a cada Worker. Los dos valores pueden ser diferentes entre la aplicación web y la de MCP. El código comprueba firma, emisor y audiencia de JWT.
4. Para MCP no basta un encabezado JWT de Access en desarrollo: el **cliente remoto debe completar un flujo OAuth real**. Diseñar y configurar la integración Access/Managed OAuth o el proveedor OAuth compatible con la versión del SDK y probar descubrimiento, consentimientos, autorización, refresco y revocación.
5. Mantener MCP solo servidor-servidor, sin CORS y rechazando `Origin`, hasta incorporar un cliente web con modelo de amenazas específico.

**Redrive manual:** además de Access, [R2.6](R2_OPERATOR_SIGNED_AUTHORIZATION.md) exige dos firmas independientes de autoridad de aprobación/MFA y de release del inspector, claves públicas fijadas, digest de imagen real y evidencia externa de auditoría. No conectar el módulo sin firmantes verificados y autorizados ni inferir MFA solo del JWT Access.

La selección de aplicación Access, Managed OAuth o un OAuth provider debe basarse en la configuración real de la cuenta; no introducir credenciales en código, archivos de configuración versionados ni logs.

## Gate 3 · Configuración del operador MCP

Habilitar expresamente **Cloudflare Preview de Folio Cívico** en el operador del conector, con su allowlist D1/R2/Workers y permisos mínimos. La configuración la controla el operador: **no se puede resolver editando este repositorio**.

Confirmar por separado lectura y capacidad de mutación del entorno, sin añadir permisos para otros proyectos.

## Gate 4 · Validación antes del primer despliegue

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm build
pnpm test:workers
pnpm exec wrangler d1 migrations apply folio-civico-preview --local --config apps/api/wrangler.jsonc
```

Todo debe terminar con código 0. El `build` actual usa `wrangler deploy --dry-run`; no publica Workers.

Tras verificar una cuenta, Access y los recursos remotos exclusivos, realizar una prueba con **solo datos sintéticos**, incluido: JWT válido y expirado, membresías revocadas, lectura cross-tenant (404), PDF en cuarentena inaccesible, no duplicación de POST, revisión por dos personas y auditoría. Comparar versiones de esquemas aplicadas con las migraciones versionadas y verificar rollback/backup.

No usar una migración remota desde CI hasta disponer de controles explícitos de aprobación, copia de seguridad y verificación.

## Gate 5 · Requisitos pendientes para documentos institucionales

- **Bloqueo de seguridad de imagen (ADR-013):** el escaneo real Trivy/CycloneDX reportó 1 CRITICAL, 149 HIGH y 19 UNKNOWN en Trixie multi-stage. `pnpm audit:inspector:image` devuelve **2 / blocked**. No desplegar Inspector/Containers hasta obtener una imagen corregida o evaluar cada excepción mediante VEX aprobado, con análisis de aplicabilidad y evidencias. Los smokes exitosos no levantan este bloqueo. La [ADR-014](ADR-014-native-zlib-signature-lifecycle.md) verifica la revisión de seguridad `zlib1g`, el descenso a 634 hallazgos, y que el inspector responde `503` ante firmas incompletas o caducadas. La **rotación real de imagen antes de 72 h** sigue pendiente.
- Base jurídica y acuerdos de tratamiento/residencia/retención de datos.
- **Completado en local (ADR-010):** tras pasar preflight con más de 114 GiB libres se construyó la imagen y se ejecutó `pnpm test:inspector:docker` (script equivalente) con motores reales: PDF nativo, OCR del PDF sin texto, PDF dañado, cifrado y con adjunto rechazados y EICAR detectado; **6/6, exit code 0**. La [ADR-012](ADR-012-patched-clamav-supply-chain.md) ya instaló **ClamAV 1.5.5 verificado con firma GPG**, gate de versión y smoke HTTP real local. Para Preview repetir las pruebas en la imagen aprobada, ejecutar escaneo CVEs/SBOM del sistema completo y demostrar renovación de firmas e indisponibilidad al vencerlas antes de recibir documentos.
- Activar solo tras autorización la [ADR-009](ADR-009-private-container-gateway.md): `apps/inspector-gateway/wrangler.container.example.jsonc` modela el Container Durable Object privado; el archivo `wrangler.jsonc` activo **no tiene binding**. Construir la imagen, comprobar firma y vigencia de ClamAV con `freshclam`, disponer de qpdf/Poppler/Tesseract y verificar `/health`. **El motor se probó en Docker local, pero todavía no se ha conectado ni probado el Container con Service Binding real.** Configurar `INSPECTOR_SERVICE_TOKEN` y `INSPECTOR_HMAC_KEY` como secretos de Processor y Gateway, con rotación; **solo el token llega al contenedor, la clave HMAC queda en Workers**.
- Aprovisionar la Queue `folio-civico-pdf-pending`, su dead-letter queue, productor `PROCESSING_QUEUE` en API, consumidor `folio-civico-processor` y cron de outbox con aprobación y límites de costo; **no existe ninguno en los Wrangler activos**. Solo se preparó un [ejemplo no activo de consumidor con DLQ y runbook de triaje](R2_DLQ_TRIAGE_RUNBOOK.md): exige autorización para crear recursos, alertas por retención de mensajes y revisión individual antes de redrive. Probar recuperación, 422 como `needs_review`, errores 503 y reintentos. Revisar la [ADR-011](ADR-011-processing-backlog-audit.md) y su resumen agregado `folio.processing.audit`, configurar alertas y completar un runbook humano de DLQ y reintentos agotados; no habilitar redrive automático.
- Activar y verificar, solo tras aprobación, el trigger programado para el diagnóstico R2–D1. Hoy está **desactivado**. Acordar política de limpieza, retención, borrado e incidentes; la auditoría no elimina ni certifica el contenido físico.
- Checklist institucional aprobado, provisión y revocación de usuarios, segregación de funciones.
- Validación de seguridad de la sesión OAuth/MFA; evidencia de pruebas E2E remotas.
- Procedimiento de archivo y exportación documental, firma y actas oficiales **externos** al MVP hasta autorización.

**Fuentes oficiales:**  
[Cloudflare Workers Access](https://developers.cloudflare.com/workers/configuration/cloudflare-access/) · [Cloudflare D1 CLI](https://developers.cloudflare.com/d1/wrangler-commands/) · [Cloudflare R2 Lifecycle](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) · [Cloudflare MCP Authorization](https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/)
