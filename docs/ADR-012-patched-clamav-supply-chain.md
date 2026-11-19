# ADR-012 · Cadena de suministro ClamAV 1.5.5 y verificación del servicio real

**Fecha:** 2026-11-18 (America/Lima)  
**Estado:** implementación local con ClamAV 1.5.5 firmado y control de versión; **no desplegado en Cloudflare Preview ni producción**.

## Riesgo identificado

El Dockerfile anterior instalaba `clamav` desde Debian Bookworm y construyó ClamAV `1.4.6`. El boletín publicado por Cisco Talos el **18 de noviembre de 2026** anunció ClamAV `1.5.5` y `1.4.7` para corregir fallos de seguridad, incluidos `CVE-2026-76422` (formato de logs), `CVE-2026-76411` (contabilidad de longitud de URL) y `CVE-2026-76415` (unpacker y acceso fuera de límites). Los tres pueden afectar versiones antiguas, incluidas `1.4.6` y `1.5.4`.

Se comprobó directamente que las etiquetas oficiales Docker `clamav/clamav-debian:1.5` y `1.5_base` **todavía contenían `1.5.4`**. La simple migración a estas etiquetas habría dado una falsa sensación de actualización y dejado el fallo abierto.

## Decisión implementada

En `apps/inspector/Dockerfile`:

1. Se mantiene `python:3.12-slim-bookworm` para no introducir cambios ajenos a la actualización y se instala qpdf, Poppler y Tesseract con apt, **sin instalar el ClamAV obsoleto del repositorio Debian**.
2. Se descarga **exclusivamente durante el build** el paquete oficial `clamav-1.5.5.linux.x86_64.deb`, su firma `.sig` y la clave pública Talos publicada en `Cisco-Talos/clamav-documentation`, siempre por HTTPS.
3. Se comprueba la **huella principal completa** de la clave Talos `5BADCA2665EF59DCF8A23D8B707F0DB480836771` y se ejecuta `gpg --verify` sobre la firma separada y el paquete **antes de `dpkg -i`**. Una clave diferente, firma inválida o paquete adulterado hacen fallar la construcción. La imagen exige arquitectura `amd64` y no asume que un .deb x86_64 funcione en ARM.
4. `freshclam` obtiene y verifica las bases oficiales `daily`, `main` y `bytecode` durante la construcción. Estas definiciones se incorporan a la imagen y están disponibles en `/opt/clamdb` para inspección **sin red**; se mantienen los límites de antigüedad de 72 horas y su comprobación en cada inspección.
5. `verify_clamav_version` en Python exige la serie probada **ClamAV 1.5 con parche ≥5**. Se invoca tanto en `inspection_ready` (incluido `GET /health`) como en `inspect_pdf`. Versiones obsoletas, formatos no válidos o una línea de características no probada fallan como `ScannerUnavailable`, nunca como un documento `clean`.
6. Se mantienen las seis comprobaciones del smoke auténtico de la ADR-010. Se agrega `apps/inspector/smoke_http_real.py` que invoca el manejador HTTP real en loopback dentro de otro contenedor local, con credenciales **solo sintéticas**, verificando `/health`, rechazo `403`, manifiesto `clean` sin clave/firma HMAC dentro del contenedor y rechazo `422` ante SHA-256 falsificado.
7. Se conserva `--network none`, root filesystem de solo lectura, usuario no privilegiado, límites de CPU/RAM/tmpfs y `--cap-drop ALL` durante la inspección. No se publican puertos ni se proporcionan secretos reales.

El script `apps/inspector/validate_real_engines.sh` sigue siendo manual y comprueba la capacidad del host antes de crear **solo una imagen local del proyecto**. No modifica recursos de otros proyectos ni despliega Workers. El smoke HTTP es deliberadamente independiente del Worker gateway: no constituye una verificación de Queue, Durable Objects, firma HMAC externa, D1/R2 o Access real.

## Evidencia y límites

La primera imagen local actualizada verificó la firma GPG de Talos, instaló ClamAV `1.5.5-1`, regeneró las definiciones ClamAV y completó las **seis pruebas reales** con exit code 0. Herramientas verificadas dentro del contenedor: ClamAV `1.5.5`, qpdf `11.3.0`, Poppler `22.12.0`, Tesseract `5.3.0`. El manejador HTTP real, ensayado dentro del mismo aislamiento sin red, respondió `200` a salud y escaneo autorizado, `403` a credencial incorrecta y `422` a checksum falsificado; devolvió manifiesto sin HMAC.

Se ampliaron pruebas Python que bloquean versiones `1.4.6` y `1.5.4`, exigen fallo cerrado en admisión y salud, y verifican controles de la cadena de suministro en el Dockerfile. Los resultados anteriores de la ADR-010 permanecen válidos para el motor anterior, pero **no deben confundirse con el estado actual de seguridad**.

### Límites pendientes

- Un **parche antivirus vigente no demuestra ausencia universal de malware**. EICAR es una verificación funcional, no un ensayo completo de ataques sobre PDFs adversariales.
- La versión del motor y la edad de las firmas no demuestran la seguridad de dependencias. **Evolución ADR-013:** el SBOM y escaneo completo ya se realizaron y reportaron hallazgos críticos/altos persistentes, por lo que la imagen está bloqueada para Preview. Sigue pendiente la renovación de firmas con evidencias y remediación o VEX autorizado.
- La imagen base `python:3.12-slim-bookworm` está referida por una etiqueta actualizada con `--pull`, no por un digest aprobado; validar procedencia, pin y actualización controlada en CI al preparar el despliegue.
- Los ejecutables `curl` y `gnupg` usados en el build quedan instalados en esta primera versión. Antes de publicar la imagen en Preview se deberá evaluar una construcción multi-stage para reducir la superficie y el tamaño de ataque, sin debilitar la verificación de firma.
- La construcción depende de la disponibilidad del artefacto oficial y la clave Talos. Al rotar la clave o cambiar la versión hay que revisar la nueva huella por un canal independiente; fallará cerrado hasta actualizar la política. No se introducen secretos institucionales en la imagen.
- Las firmas no se actualizan durante el uso del contenedor sin red. Se debe **reconstruir y reemplazar la imagen antes de las 72 horas**, con alertas de indisponibilidad y sin reautorizar automáticamente `clean`.
- **No hay** instancia Cloudflare Container, Service Binding activo, Queue, DLQ, cron, Access, OAuth, entorno Preview autorizado ni documentos institucionales procesados. Es obligatorio comprobar todo el flujo remoto y su modelo de amenazas antes de un piloto.

## Referencias

[ADR-008](ADR-008-isolated-inspector-queues.md) · [ADR-009](ADR-009-private-container-gateway.md) · [ADR-010](ADR-010-real-inspector-smoke-gates.md) · [ADR-011](ADR-011-processing-backlog-audit.md) · [Checklist de Preview](PREVIEW_CHECKLIST.md).

Fuentes oficiales consultadas: [anuncio ClamAV 1.5.5 y 1.4.7](https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html), [boletín Cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-multi-e93M3vdA), [verificación de firmas GPG ClamAV](https://docs.clamav.net/manual/Installing.html), [descargas originales](https://www.clamav.net/downloads) y [recomendaciones oficiales Docker](https://docs.clamav.net/manual/Installing/Docker.html).
