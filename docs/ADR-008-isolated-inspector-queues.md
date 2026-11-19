# ADR-008 · Inspector PDF aislado, outbox D1 y consumidor Cloudflare Queues

**Fecha:** 2026-11-18  
**Estado:** código, pruebas y aislamiento de despliegue preparados. **No desplegado**; no se ha procesado ningún expediente institucional real.

## Problema

La puerta de admisión firmada (ADR-007) exige un servicio externo que realmente someta un PDF a controles antimalware y extracción por página. El esquema previo no programaba trabajos: después de la carga un documento quedaba indefinidamente `pending`. La carga D1+R2 también necesita un puente duradero hacia colas con reintentos controlados y auditoría.

## Diseño implementado

### 1. Outbox duradero en D1

Las migraciones `0011_document_processing_outbox.sql` y `0012_processing_outbox_guards.sql` crean y protegen `document_processing_outbox` con una fila por versión, `pending → sent → completed`, contador de intentos y fecha del último envío. Los triggers impiden fingir un trabajo `completed` sin informe de inspección, reabrirlo, cambiar el ID o eliminarlo sin política de retención. Un trigger crea el trabajo **en la misma transacción que inserta la versión documental**; la migración también registra versiones `pending` anteriores y otro trigger marca `completed` cuando se inserta un informe de inspección válido.

`dispatchProcessingOutbox` selecciona como máximo 10 trabajos por ejecución, solo comisiones activas y versiones aún pendientes, y envía a Cloudflare Queues únicamente:

```json
{"kind":"folio.process.pdf","versionId":"<id>","sourceSha256":"<64 hexadecimal>"}
```

No transmite el contenido PDF, clave R2, nombres de archivo ni datos de la comisión. Marca `sent` **después** de confirmar el envío; un fallo de Queue no altera el registro. Reintenta un mensaje `sent` tras 15 minutos y limita cada trabajo a 10 entregas del outbox. Las entregas pueden duplicarse: el consumidor y la admisión firmada son idempotentes.

El manejador `scheduled` del Worker API ahora puede despachar si `PROCESSING_QUEUE` está enlazado, **pero no hay ni Queue ni cron configurados** en `apps/api/wrangler.jsonc`.

### 2. Worker consumidor independiente

`apps/processor` ejecuta un `queue()` de Cloudflare Workers:

- Solo admite mensajes de `folio-civico-pdf-pending`, con tres propiedades exactas, ID limitado y SHA-256 verificado frente a D1; no permite configurar el destino de la inspección desde el mensaje.
- Verifica comisión activa y versión `pending` antes de abrir el original privado R2. Vuelve a calcular SHA-256 sobre bytes reales antes de enviarlos a inspección.
- Exige `INSPECTOR` como **Service Binding privado**, `INSPECTOR_SERVICE_TOKEN` y `INSPECTOR_HMAC_KEY` como secretos del Worker. Sin alguno de esos elementos, falla cerrado y solicita reintento; no admite páginas.
- Entrega el PDF original al servicio interno, espera un resultado acotado a 2 MiB y comprueba la firma HMAC, el veredicto y referencias mediante `publishInspectedText` de ADR-007.
- Resultado HTTP `422` documentado del inspector: marca la versión `needs_review` y escribe auditoría. Otros errores o informes inválidos provocan reintento, sin publicar texto. Reentregas de versiones `ready` son reconocidas sin ejecutar de nuevo el escáner.
- Cada mensaje se confirma o reintenta individualmente. Las cargas JSON inesperadas se confirman como inválidas sin tocar R2 ni registrarse con su contenido.

No se configuró `[[queues.consumers]]` ni se creó DLQ. El Worker compila en `dry-run`, pero **no se ejecutará en la plataforma hasta aprovisionarlo explícitamente**.

Configuración **orientativa, no aplicada**, solo para cuando el operador haya creado recursos dedicados y autorizado costos:

```jsonc
// apps/api/wrangler.jsonc (agregar, NO presente hoy)
"queues": {
  "producers": [
    {"binding":"PROCESSING_QUEUE","queue":"folio-civico-pdf-pending"}
  ]
},
"triggers": {"crons":["*/15 * * * *"]}

// apps/processor/wrangler.jsonc (agregar, NO presente hoy)
"queues": {
  "consumers": [{
    "queue":"folio-civico-pdf-pending",
    "max_batch_size":1,
    "max_retries":5,
    "dead_letter_queue":"folio-civico-pdf-dlq"
  }]
},
"services": [
  {"binding":"INSPECTOR","service":"folio-civico-inspector-gateway"}
]
```

**Evolución (ADR-009):** el código del gateway `folio-civico-inspector-gateway` ya existe como Worker y Durable Object Container, con configuración activa inerte y plantilla privada de habilitación. No hay instancias ni Service Binding remoto desplegados. `INSPECTOR_SERVICE_TOKEN` y `INSPECTOR_HMAC_KEY` se configuran solo como secretos de Processor y Gateway (nunca en `vars`); **la clave HMAC no se pasa al contenedor**. No incorporar estos fragmentos en Wrangler hasta que exista una cuenta aislada con autorización, Queues y gateway protegidos.

### 3. Inspector de PDF aislado, ejecutable, sin autoaprobar documentos

`apps/inspector/inspector.py` es un servidor HTTP de uso exclusivo interno (`POST /inspect`) con autenticación mediante token de servicio y tamaño de entrada 8 MiB. En su modo local original puede firmar HMAC; **en la integración Cloudflare (`FOLIO_INSPECTOR_OUTPUT_MODE=unsigned`) únicamente devuelve un manifiesto sin firma que el Worker Gateway comprueba y firma** (ADR-009). No expone un endpoint público a usuarios finales. Es obligatorio disponer de:

- **ClamAV:** base de firmas montada en modo lectura, presencia de `.cvd`/`.cld` y antigüedad aparente máxima de 72 horas; un escaneo no limpio o fallido no puede declarar `clean`. La edad de archivo es una comprobación operativa, no una garantía criptográfica de actualización de firmas.
- **qpdf:** `--check` sobre el original, con rechazo ante errores de estructura. Los errores de motor ClamAV (código 2) se clasifican como indisponibilidad, no como detección (código 1).
- **Poppler:** `pdfdetach` rechaza archivos incrustados, `pdfinfo` rechaza cifrado y limita el expediente a 100 páginas. `pdftotext` extrae cada página individualmente.
- **Tesseract:** si la página no produce texto, `pdftoppm` genera una rasterización **solo interna** y Tesseract ejecuta OCR `spa+eng`. La página debe producir texto no vacío y de máximo 8 000 caracteres, sin controles peligrosos.
- **Firma:** en modo local `signed`, Python firma HMAC; en Cloudflare Containers (ADR-009), el proceso de análisis devuelve JSON no firmado y el Worker gateway, único tenedor de la clave HMAC, firma después de verificarlo. No devuelve PDF, imagen rasterizada ni rutas internas.

Usa `subprocess.run` con argumentos explícitos (sin shell), timeout de 30 segundos por herramienta y presupuesto total de 8 minutos por PDF, directorio temporal privado y no incluye contenido documental en logs. `Dockerfile` instala los ejecutables requeridos y se ejecuta con UID 65534, pero su aislamiento efectivo **depende de flags/políticas del orquestador**.

La imagen no se ha construido ni ejecutado en este entorno: no hay `clamscan`, `qpdf`, `pdfinfo`, `pdftotext`, `pdftoppm` o `tesseract` instalados. Sus pruebas de Python utilizan ejecutables simulados; **no acreditan una firma AV actual ni la eficacia de detección ni la fidelidad del OCR sobre documentos reales**.

### Ejemplo de ejecución local contenida (no automatizada)

Después de instalar motores, obtener firmas actualizadas de una fuente confiable y crear dos secretos con permisos mínimos fuera del repositorio:

```sh
docker build -t folio-civico-inspector:local apps/inspector
docker network create --internal folio-inspector-internal

docker run --rm \
  --network folio-inspector-internal \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --mount type=bind,src=/secure/clamav-db,dst=/opt/clamdb,readonly \
  --mount type=bind,src=/secure/inspector-token,dst=/run/secrets/token,readonly \
  --mount type=bind,src=/secure/inspector-hmac,dst=/run/secrets/hmac,readonly \
  -e FOLIO_INSPECTOR_TOKEN_FILE=/run/secrets/token \
  -e FOLIO_INSPECTOR_HMAC_FILE=/run/secrets/hmac \
  folio-civico-inspector:local
```

Los paths `/secure/*` son ejemplos que el operador debe sustituir. La red debe permitir tráfico **solo** desde un gateway interno autenticado, sin salida pública; las restricciones de CPU, memoria, disco, syscall y tráfico deben auditarse en la plataforma de despliegue.

## Dependencias necesarias antes de un piloto

1. Aprovisionar exclusivamente para Folio Cívico: Queue de pendientes y **dead-letter queue**, productor/consumidor, cron, D1/R2 y Access/OAuth, con aprobación de costos. La retención de fallos exige la DLQ: sin ella, Cloudflare puede descartar mensajes agotados.
2. **Desplegar y verificar** el gateway de Service Binding ya implementado en `apps/inspector-gateway` con el contenedor HTTP aislado. El código existe, pero **no hay ninguna instancia Container ni Service Binding remoto activo**; sin ellos no hay cadena ejecutable real. Mantener acceso a los originales limitado a la conexión de inspección.
3. Inyectar y rotar secretos de servicio/HMAC como secretos de Cloudflare, jamás como `vars` o en el repo; restringir identidad y egreso del contenedor y supervisar su base ClamAV.
4. Verificar con **motores reales y fixtures sintéticos**: PDF nativo, página escaneada con OCR, adjuntos, PDF cifrado, archivo EICAR controlado, PDF dañado y firmas antiguas. Limitar fallos por recurso, extracción incompleta y timeout.
5. Probar toda la cadena en Preview protegido y con cuenta aislada: carga → D1 outbox → Queue → servicio aislado → manifiesto firmado → D1 texto → cita humana. Validar la DLQ, métricas, concurrencia y reintentos.
6. Definir políticas de aceptación en PDFs con páginas sin texto, de más de 100 páginas, contenido sospechoso y falso positivo de antivirus. Nunca publicar el PDF sin transformación y visor derivados autorizados.

## Seguridad y límites

- **Sin despliegue, sin Queues activas, sin cron y sin costos remotos habilitados en este incremento.** La ADR-010 añade preflight de disco/RAM, fixtures sintéticos y smoke real opt-in sin haber ejecutado los motores todavía.
- No hay URL del inspector configurable por el mensaje, ruta pública de sus originales ni procesamiento en la API frontend.
- `needs_review` es conservador, nunca aprobación. El pipeline no sustituye revisión normativa ni inspección humana y puede producir falsos positivos o falsos negativos.
- El scanner no sanea un derivado visual para descarga; el visor seguro PDF sigue pendiente.
- El Service Binding del Processor apunta al gateway Worker de ADR-009, el cual utiliza un Durable Object y el puerto privado del Container. **Sigue desactivado** hasta contar con una arquitectura de Preview autorizada, secrets reales y firmas vigentes.

**Referencias:** [ADR-007](ADR-007-inspected-text-gate.md), [roadmap](ROADMAP.md), documentación oficial de [Cloudflare Queues](https://developers.cloudflare.com/queues/configuration/configure-queues/) y [reintentos/DLQ](https://developers.cloudflare.com/queues/configuration/batching-retries/).
