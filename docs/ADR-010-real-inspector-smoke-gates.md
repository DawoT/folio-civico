# ADR-010 · Validación real del inspector con protección de recursos

**Fecha:** 2026-11-18  
**Estado:** pruebas y procedimiento local implementados. **Ejecución con motores reales bloqueada de forma explícita por el entorno**, sin sustitución silenciosa por simulaciones.

## Objetivo

Convertir la revisión de antivirus/OCR de ADR-008/009 en una comprobación reproducible y verificable con ejecutables, firmas oficiales y documentos **exclusivamente sintéticos**. Evitar que un Docker build pesado agote un host compartido o que se declare `clean` sin haber ejecutado ClamAV, Poppler y Tesseract reales.

## Estado observado y decisión de seguridad

En el host de desarrollo del operador (18-11-2026), el volumen compartido informa menos de **4 GiB libres**, con una capacidad total de 495 GiB prácticamente llena. No están presentes `clamscan`, `qpdf`, `pdfdetach`, `pdfinfo`, `pdftotext`, `pdftoppm` ni `tesseract`, ni existe un directorio de firmas oficiales ClamAV listo.

**Decisión:** no ejecutar `docker build`, `apt`, `freshclam` ni descargas de imágenes en este host. No borrar otras imágenes, cachés ni recursos compartidos para liberar espacio; eso podría afectar otros productos. El proceso se puede reanudar en un host de validación **aislado** con capacidad suficiente, sin solicitar acceso a documentos institucionales ni habilitar Cloudflare.

## Componentes implementados

### Comprobación local sin efectos secundarios

`apps/inspector/preflight.py --mode build` verifica:

- Al menos **8 GiB libres** tanto en el volumen del repositorio como en el directorio de datos del daemon Docker.
- Al menos **4 GiB de RAM disponible**, siguiendo la recomendación oficial de ClamAV para contenedores.
- Binario Docker, daemon disponible y contexto **local** mediante socket Unix. Los contextos SSH/TCP y los daemons remotos no se aceptan.

`--mode smoke` exige 1 GiB libre en el volumen de trabajo y al menos 128 MiB en el directorio temporal privado, 4 GiB RAM disponible, todos los ejecutables del inspector en PATH y bases de firmas `.cvd`/`.cld` presentes y con una antigüedad aparente máxima de 72 horas. Los controles no modifican el host. Un requisito ausente devuelve **exit code 2** y un JSON `{"ready":false,"problems":[...]}`.

Comandos reproducibles:

```sh
python3 apps/inspector/preflight.py --mode build
python3 apps/inspector/preflight.py --mode smoke --database /opt/clamdb
```

### Generación autocontenida de PDFs sintéticos

`apps/inspector/fixtures.py` construye dos PDFs válidos y un tercero dañado con la biblioteca estándar de Python:

- PDF **nativo** de una página con texto de prueba «EXPEDIENTE OBRA 2026».
- PDF **escaneado** de una página cuya única fuente de contenido es una imagen en escala de grises con «OBRA 2026» dibujado como glifos originales; no hay operadores PDF de texto ni fuente incrustada.
- PDF truncado con encabezado aparente, pero sin tabla xref ni cierre válido.

Las pruebas independientes del generador comprueban que la tabla xref apunta a los objetos esperados, que el escaneado contiene un XObject de imagen sin texto PDF y que el documento dañado carece de cierre.

### Smoke test real, que no puede aprobar usando mocks

`apps/inspector/smoke_real_engines.py` ejecuta de verdad `inspect_pdf`, con los motores del sistema:

1. Native PDF: ClamAV, qpdf y Poppler completan; el texto extraído debe conservar «EXPEDIENTE», «OBRA» y «2026».
2. Scanned PDF: ClamAV, qpdf y Poppler completan, `pdftotext` no debe aportar texto y `pdftoppm + Tesseract` deben recuperar «OBRA» y «2026».
3. PDF truncado: debe rechazarse por estructura, nunca producir un manifiesto `clean`.
4. **EICAR**, cadena de prueba antivirus inofensiva, creada exclusivamente en un directorio temporal fuera del repositorio: `clamscan` con las firmas configuradas debe identificarla (código 1).

El smoke emite solo estados agregados de cada comprobación, sin contenido ni nombres institucionales. Si falta un motor, falla la prueba previa (código 2); si un motor real responde incorrectamente, falla (código 1). Un test Python normal no se confunde con una ejecución de este smoke.

### Ejecución manual en Docker con privilegios mínimos

`bash apps/inspector/validate_real_engines.sh` encadena **estrictamente** comprobación de capacidad → build de una imagen nombrada solo para Folio Cívico → ejecución sin salida a Internet:

```sh
pnpm test:inspector:docker
```

El `Dockerfile` incluye los generadores y el smoke para ejecutarlos dentro de la misma imagen, exige `freshclam` durante el build y falla si no hay definiciones. El contenedor de prueba ejecuta sin red, sin puertos publicados, sin capacidades Linux, con `no-new-privileges`, root filesystem de solo lectura, UID no privilegiado, máximo 64 procesos, límite de CPU, **4 GiB de RAM**, sin swap adicional y tmpfs privado de 256 MiB. El proceso no recibe HMAC ni token del servicio: son innecesarios para la prueba CLI.

La imagen local resultante conserva el nombre `folio-civico-inspector:validation` para inspección manual; el script no borra archivos/cachés/imágenes de otros proyectos. La ejecución real no está automatizada en CI por requerir motores pesados y descargas de definiciones oficiales.

### Endurecimiento adicional de ejecución

`inspector.command()` ahora redirige la salida de herramientas externas a un archivo **temporal y privado** bajo el directorio aislado, en vez de usar `subprocess.run(capture_output=True)`, que podía acumular texto arbitrariamente grande en la RAM del proceso. Tras la ejecución comprueba el tamaño máximo de **2 MiB**, decodifica UTF-8 de forma estricta y falla cerrado. Los límites del tmpfs y del contenedor siguen siendo obligatorios; no se interpreta ni se registra la salida del parser como código.

## Resultados y límites

- Se ejecutaron los tests unitarios Python del generador, preflight, límites de salida, condiciones de rechazo y política de despliegue.
- Se ejecutó el comando real de preflight en el host: **denegó la construcción por disco insuficiente**. La ejecución de `smoke_real_engines.py` también devolvió código 2 por motores/firmas ausentes.
- **No se ha construido Docker ni ejecutado un motor real. No existe validación real de OCR ni antivirus aún.**
- La presencia de firmas y la detección EICAR son comprobaciones necesarias, no prueba de ausencia de malware en PDFs arbitrarios. El reconocimiento OCR debe validarse además con muestras de distintos escaneos, calidades e idiomas cuando se habilite un entorno aislado.
- No se crea Queue, Container, R2, D1 ni ningún recurso Cloudflare remoto; no hay despliegue de producción ni tratamiento de expedientes institucionales.

## Criterio para cerrar el bloqueo

Solo dar por completada la validación real cuando, en un entorno local **aislado y con ≥8 GiB libres y ≥4 GiB disponibles**, `pnpm test:inspector:docker` finalice con **exit code 0**, todos los estados `passed/rejected/detected` sean observables y se documenten versiones de motor, fecha/versión de firmas y límites reales. Después corresponde el Preview con Access/MFA, Queue, DLQ y contenedor autorizados por el titular.

**Fuentes oficiales:** [Requisitos de ClamAV en Docker](https://docs.clamav.net/manual/Installing/Docker.html), [actualización de firmas](https://docs.clamav.net/manual/Usage/SignatureManagement.html), [límites de Cloudflare Containers](https://developers.cloudflare.com/containers/platform/limits/).

**Evolución:** [ADR-008](ADR-008-isolated-inspector-queues.md) · [ADR-009](ADR-009-private-container-gateway.md).
