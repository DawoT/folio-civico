# ADR-007 · Puerta de admisión firmada para texto documental por página

**Fecha:** 2026-11-18  
**Estado:** código implementado y probado localmente. Servicio externo de inspección y OCR **no desplegado**; PDFs entrantes permanecen en cuarentena.

## Problema y límite de confianza

Una cabecera `%PDF-` y un SHA-256 de recepción prueban el tipo aparente y la integridad del original, pero **no** su inocuidad. Renderizar un PDF en cuarentena en el navegador o analizarlo como archivo seguro dentro del Worker API aumentaría el riesgo de explotación y exposición de documentos institucionales.

Las citas de evidencia deben mantener el vínculo verificable con el archivo original, sin cambiar la clave privada de R2 ni sustituir silenciosamente su contenido.

## Decisión

La aplicación introduce un contrato interno para recibir **texto que ya haya sido inspeccionado y extraído por un servicio aislado de confianza**. Separa original, constancia de inspección y texto de páginas:

1. El PDF original sigue bajo `quarantine/` y es accesible solo mediante el binding R2, sin endpoint de descarga.
2. Un servicio externo futuro deberá inspeccionar malware, ejecutar transformación/validación segura del PDF, extraer todas las páginas (con OCR cuando corresponda) y emitir un manifiesto con `documentVersionId`, `sourceSha256`, `scanVerdict:"clean"`, `scanner`, `scannerReportId`, `scannedAt` y `pages: [{page,text}]`.
3. El componente firmante de confianza firma bytes UTF-8 de JSON determinista con **HMAC-SHA256** (propiedades en el orden anterior; dentro de cada página: `page`, `text`). El contrato de serialización está implementado en `serializeInspectionManifest`. La clave de firma no se envía al navegador ni se versiona.
4. La función interna `publishInspectedText` verifica la firma, que el resultado sea `clean`, los identificadores y tiempos, la continuidad de páginas 1..N (máximo 100), y texto no vacío de máximo 8 000 caracteres por página, sin controles y caracteres de dirección Unicode peligrosos.
5. **Reabre el original privado en R2 únicamente para calcular su SHA-256 real** y compararlo con el manifiesto y el hash inmutable de D1. No ejecuta un parser PDF, scripting, renderizador ni OCR dentro del Worker API. El tamaño original admitido está limitado a 8 MiB.
6. Inserta constancia de inspección, páginas `ready`, estado de versión y evento de auditoría **en una sola transacción D1**. La constancia es única por versión, inmutable e idempotente por huella de manifiesto. Un reintento idéntico no crea páginas ni auditoría duplicadas.
7. La migración `0009` ajusta las reglas de evidencia `DOCUMENT_PAGE`: en vez de exigir cambiar la clave R2 a `processed/`, requiere un informe de inspección que coincida con el SHA-256 de la versión y su estado `ready`. Con `0010`, páginas y metadatos de una versión inspeccionada no pueden alterarse una vez admitidos.
8. `GET /api/commissions/{id}/documents/{versionId}/pages` devuelve **solo texto JSON**, versión, SHA-256 y números de página a miembros activos de esa comisión, tras validar el JWT de Access. Nunca devuelve la ruta privada ni los bytes del original. Usa `Cache-Control: private, no-store`, `nosniff` y CSP restrictiva.
9. React muestra el texto como **nodos de texto escapados por React**, no como HTML, iframe, PDF embebido ni SVG. Solo cuando la versión está `ready` se ofrece crear un borrador con `versionId` y `page`. El servidor toma el SHA-256 directamente de D1 e impide una cita a una página inexistente o pendiente.
10. La observación sigue siendo propuesta humana (`draft`) y requiere una decisión interna de otro miembro o presidente (ADR-005). Ni la admisión ni la IA producen conclusiones oficiales.

## Barreras actuales (fail closed)

**Existe código para el inspector externo y gateway privado (ADR-008/009), pero no están desplegados, no se ha probado antivirus/OCR real, no hay secretos configurados ni colas activas.** Tampoco existe endpoint público de admisión de manifiestos. `publishInspectedText` es una función de backend para un adaptador futuro; no se la llama al subir documentos. Por tanto, un PDF nuevo conserva `extraction_status='pending'` y no obtiene páginas visibles por esta vía.

Una constancia `clean` solo es confiable si la emite un motor real, aislado, actualizado y autenticado. La firma HMAC valida procedencia del mensaje según la custodia de la clave; **no garantiza por sí misma la calidad del antivirus ni la corrección del OCR**.

## Pruebas locales

- Rechazo de firmas falsas, veredicto no limpio, hash R2 distinto, manifiestos incompletos, salto de páginas y contenido sobredimensionado.
- Repetición idempotente, auditoría única, transacción D1 de informe+páginas+estado.
- Bloqueo de estado `ready` sin informe, cambios posteriores a SHA/clave y modificación de páginas.
- API de consulta: denegación de páginas pendientes, usuarios ajenos o revocados, prohibición de POST.
- API de borrador de cita: derivación del hash en servidor, idempotencia y rechazo de inputs forjados.
- JWT firmado en el handler API, permisos por comisión; escape HTML del texto en React.
- Migraciones `0009` y `0010` comprobadas con SQLite real y Wrangler D1 local. No es una prueba de un escáner desplegado.

## Requisitos para completar el motor documental

- Probar, endurecer y desplegar **en un entorno autorizado** el servicio aislado ya implementado en código, que inspecciona PDF (malware, estructura, adjuntos y cifrado), extrae páginas y ejecuta OCR con límites. Aún faltan pruebas reales de motores/firmas y políticas complementarias de acciones activas, contenido remoto y derivados visuales saneados.
- Aprovisionar y verificar Queues/Workflows con el outbox, consumidor, gateway y DLQ ya escritos, con trabajos idempotentes, recuperables y estados de error/conservación definidos; todo permanece sin activar.
- Aprovisionar y rotar la clave secreta HMAC con control de identidad servicio a servicio; considerar firma asimétrica para verificación desacoplada, protección contra replay y revocación por clave/inspector.
- Implementar visor visual **solo** para derivados saneados, independientes del original de cuarentena. Verificar concordancia de página y texto/OCR, y prueba E2E remota con Access y MFA.
- Establecer límites y políticas institucionales para documentos escaneados de más de 100 páginas o texto vacío, con rutas `needs_review` y revisión humana.

## No objetivos

No abrir originales en la interfaz, no ejecutar código incluido en PDF, no publicar objetos R2, no automatizar aprobación de observaciones y no afirmar que existe análisis antimalware real.

**Evolución de custodia (ADR-009):** en Cloudflare Containers, el inspector retorna un manifiesto sin firma; un Worker gateway distinto valida identidad, SHA-256, estructura y páginas y aplica HMAC. La clave no ingresa al proceso de análisis PDF. 

**Referencias:** [ADR-002](ADR-002-r2-intake.md), [ADR-004](ADR-004-human-review.md), [ADR-005](ADR-005-human-decisions.md), [ADR-009](ADR-009-private-container-gateway.md), [modelo de evidencias](EVIDENCE.md), [roadmap](ROADMAP.md).
