# ADR-026 · Aislamiento del entorno de los analizadores PDF y revisión de Expat

**Fecha:** 2026-11-19 (America/Lima)
**Estado:** implementado en código y verificado sobre motores locales reales; **imagen no reconstruida ni aprobada para despliegue**.

## Situación verificable

La versión de `libexpat1` en el experimento de Poppler sigue siendo **`2.9.0-1~deb13u1`**, incluida de forma transitiva a través de Fontconfig. El seguimiento de Debian indica que esta versión continúa vulnerable a los CVE `2026-113351`, `2026-115506`, `2026-117610`, `2026-118370`, `2026-124317` y `2026-128241`. Cuatro tienen corrección incluida en Expat **2.10.0**, disponible en la rama *unstable* de Debian, **no** como actualización aprobada de Trixie. Los dos restantes constan en la rama de desarrollo de Expat **2.11.0**, sin versión estable publicada al momento de esta revisión. El responsable de Debian pidió esperar una publicación upstream completa en lugar de utilizar selectivamente un debdiff con prerequisitos y regresiones potenciales.

Se conserva Fontconfig, porque en el experimento R1.6 eliminarlo hizo que el mismo PDF Helvetica no incrustado perdiera el **100 %** del texto visible en la rasterización. Actualizar directamente a `sid`, sobrescribir bibliotecas Debian o presentar como corregida una versión fuente sin seguimiento de advisories introduciría riesgos nuevos.

Fuentes:
- [Debian Security Tracker: Expat](https://security-tracker.debian.org/tracker/source-package/expat)
- [Debian: discusión del backport de los cuatro CVE](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1151840)
- [Registro de cambios upstream Expat, sección 2.11.0 en desarrollo](https://github.com/libexpat/libexpat/blob/master/expat/Changes)
- [R1.5: inventario y decisiones CVE](SECURITY_CVE_REVIEW_2026-11-19.md)

## Causa raíz adicional: variables del proceso heredadas

`inspector.py` ejecutaba ClamAV, QPDF, Poppler y Tesseract con `subprocess.run` **sin el argumento `env`**. De manera predeterminada, todos los analizadores externos heredaban el entorno del proceso Python. En el modo local firmado, eso podía incluir `FOLIO_INSPECTOR_SERVICE_TOKEN` y `FOLIO_INSPECTOR_HMAC_KEY`. Además, las variables `FONTCONFIG_FILE`, `FONTCONFIG_PATH`, `FONTCONFIG_SYSROOT`, `HOME` y `XDG_CONFIG_HOME` podían cambiar el origen de la configuración XML utilizada por Fontconfig/Expat, y `LD_PRELOAD`/`LD_LIBRARY_PATH` podían modificar el enlazado de bibliotecas.

La herencia de variables no demuestra por sí sola explotación, pero amplía las consecuencias de un defecto de memoria en cualquier analizador que procese PDF no confiable. El modelo de despliegue ya limita el acceso a red, permisos, capacidades y filesystem, pero esos controles no reemplazan el aislamiento de los secretos del entorno de los subprocesos.

## Cambio aplicado

Todas las invocaciones de motores desde `inspector.command()` reciben una **copia nueva de un entorno allowlist**, independiente de `os.environ`:

| Variable entregada al motor | Valor fijado |
| --- | --- |
| `PATH` | `/opt/folio-poppler/bin:/opt/folio-ocr/bin:/usr/local/bin:/usr/bin:/bin` |
| `LANG`, `LC_ALL` | `C.UTF-8` |
| `TESSDATA_PREFIX` | `/usr/share/tesseract-ocr/5/tessdata` |
| `FONTCONFIG_FILE` | `/etc/fonts/fonts.conf` |
| `FONTCONFIG_PATH` | `/etc/fonts` |
| `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` | `/nonexistent` |

No se heredan tokens, clave HMAC, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `FONTCONFIG_SYSROOT`, `PYTHONPATH`, parámetros de Fontconfig ni rutas de modelos OCR proporcionadas por el entorno del servicio. Las rutas de firmas de ClamAV continúan pasando como argumento `--database`; no hay dependencia de variables secretas en el proceso hijo.

Los Dockerfiles candidato y experimental comprueban ahora en el build que `/etc/fonts/fonts.conf` existe, es legible, no es un enlace simbólico y que `/etc/fonts/conf.d` existe. El Dockerfile experimental continúa utilizando explícitamente el backend `fontconfig`. Estos cambios solo afectan **futuras reconstrucciones**; las imágenes locales anteriores conservan sus IDs.

## Pruebas y evidencia

1. **TDD red → green:** inicialmente fallaron los tests porque `subprocess.run` no recibía `env` y no existía `engine_environment()`. Con el cambio pasan los tests de captura de argumentos de subprocess y un proceso Python hijo **real** que compara todas sus variables recibidas con la lista autorizada.
2. **Prueba con entorno hostil sintético:** `smoke_real_engines.py` establece temporalmente valores falsos para token, HMAC, `LD_LIBRARY_PATH`, `FONTCONFIG_FILE`, `FONTCONFIG_PATH`, `XDG_CONFIG_HOME` y `TESSDATA_PREFIX`. Ejecuta `/usr/bin/env` a través de `inspector.command()` y verifica **igualdad exacta** con la allowlist, sin registrar secretos.
3. **Calidad de OCR bajo configuración contaminada:** el smoke procesa también el PDF sintético escaneado con esos overrides activos en el proceso padre, y exige recuperar `OBRA` y `2026` usando Tesseract/Poppler reales. Se preserva la fidelidad pese a rutas externas inválidas.
4. **Prueba real offline:** `bash apps/inspector/verify_raster_guard.sh` cargó el código Python actualizado desde el repositorio en memoria dentro de `folio-civico-inspector:poppler-experiment`, identificado por ID inmutable, sin rebuild, network, puertos ni mounts: **8/8 comprobaciones aprobadas**, incluyendo `parser_environment=isolated`, PDF nativo, OCR, cifrado rechazado antes de Poppler, PDF dañado, adjuntos y detección antivirus EICAR.
5. **Contracts:** tests de Dockerfile y runtime verifican que Fontconfig mantenga la ruta estática de configuración y el nuevo `env=engine_environment()`. No se modificó `audit_image.py`, su severidad, los reportes CVE, ni las excepciones VEX.

## Límites y publicación

Esta defensa limita las variables transmitidas a un proceso externo al ejecutar un motor y la selección de XML de configuración Fontconfig por ese motor. **No evita** automáticamente toda posible inspección del proceso padre por `/proc`, una vulnerabilidad del kernel, acceso por UID o un escape del contenedor. El aislamiento completo necesita políticas de ejecución y secretos del orquestador, que siguen sin habilitarse. Los motores también pueden procesar estructuras PDF no confiables y conservan vulnerabilidades aún no remediadas.

Se mantiene el **bloqueo del gate Trivy/CycloneDX** para la imagen experimental: **0 CRITICAL / 70 HIGH / 19 UNKNOWN** y dos componentes compilados desde fuente sin evaluación formal de advisories. No se declara solucionado ni `not_affected` ningún CVE por introducir este aislamiento.

La integración del **código** a `main` se permite únicamente por [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md). No publicar imágenes, sustituir `validation`, realizar despliegues Cloudflare/Preview/producción, migrar D1 remoto ni procesar documentación institucional.

## Pendientes verificables

- Paquete de Expat **corregido y soportado para Trixie** que cubra los seis avisos, sin comprometer fidelidad PDF; no extrapolar parches de la rama de desarrollo.
- CVE restantes de Poppler/Tesseract compilados desde fuente, con procedencia, pruebas y evaluación granular.
- Triaje formal de los siete CVE históricos detectados en ClamAV 1.5.5 frente a correcciones de 1.5.3, sin exenciones masivas.
- Imagen multi-stage limpia, SBOM de componentes fuente, firmas y ciclo de renovación, tests con corpus documental representativo y gate aprobado antes de cualquier autorización de Preview.
