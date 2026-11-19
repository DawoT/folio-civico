# ADR-016 · Experimento: Tesseract 5.5.4 sin libarchive/libxml2

**Fecha:** 2026-11-19 (America/Lima)  
**Estado:** **hipótesis técnica verificada mediante imagen Docker local y smokes reales**. Este incremento NO cambia el Dockerfile operativo y NO autoriza despliegues. La imagen experimental **queda bloqueada** por CVE residuales y por falta de cobertura de vulnerabilidades para el binario OCR compilado desde fuente.

## Problema

El [ADR-015](ADR-015-runtime-cve-triage.md) identificó el CVE crítico `CVE-2026-6653` en la biblioteca `libxml2` de Debian Trixie, enlazada al OCR Tesseract. El seguimiento de seguridad de Debian continúa mostrando **sin paquete corregido para Trixie**.

La inspección de las dependencias en la imagen local de Folio Cívico determinó la cadena real:

```
tesseract → libtesseract5 → libarchive13t64 → libxml2
```

`libarchive` y `libcurl` proporcionan funcionalidades opcionales en Tesseract. Para el uso actual de Folio Cívico, Tesseract **solo recibe PNG temporales sintetizados por Poppler dentro de un contenedor sin red** y devuelve texto OCR. No necesita cargar modelos comprimidos desde archivos que aporta el solicitante ni descargar recursos por HTTP. La opción `DISABLED_LEGACY_ENGINE=ON` reduce rutas de ejecución no requeridas por el OCR LSTM, que utiliza los modelos `spa` y `eng` incluidos en la imagen.

## Alternativas estudiadas

| Alternativa | Ventaja | Limitación | Decisión |
| --- | --- | --- | --- |
| Esperar paquete `libxml2` corregido para Trixie | Mantiene mantenimiento automático Debian | No publicado en Trixie para `CVE-2026-6653` al corte | Seguir supervisando |
| Importar `libxml2` desde Debian sid/forky | Versión corregida disponible para otra rama | Riesgo ABI y mantenimiento de distribución mixta; nuevos CVE posibles | **Rechazado** |
| Parchear/recompilar `libarchive` sin `libxml2` | Mantiene soporte de archivos comprimidos | Mantiene funcionalidad innecesaria y crea otra biblioteca compilada fuera del gestor de paquetes | No preferido |
| Sustituir Tesseract por otro OCR | Permite eliminar todo el stack nativo actual | Requiere nueva evaluación de precisión en español, tamaño, licencias, rendimiento y SBOM; riesgo de dependencias nuevas | No necesario inicialmente |
| **Compilar Tesseract 5.5.4 sin archive/curl** | Conserva OCR actual y elimina el enlace vulnerable | El binario custom no aparece automáticamente en SBOM/Trivy; mantenimiento de fuente propio | **Candidato probado, sin promover** |

## Evidencia reproducible de la candidata

El archivo `apps/inspector/Dockerfile.ocr-candidate` construye una imagen **solo experimental**:

1. Utiliza el tarball de **Tesseract 5.5.4**, disponible de forma idéntica desde el archivo Debian y el tag oficial. SHA-256 observado y fijado: `a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4`.
2. Compila con `-DDISABLE_ARCHIVE=ON`, `-DDISABLE_CURL=ON`, `-DDISABLED_LEGACY_ENGINE=ON`, `-DBUILD_TRAINING_TOOLS=OFF` y `-DBUILD_TESTS=OFF`, con Leptonica del repositorio estable.
3. En una **nueva imagen derivada únicamente de la imagen local de Folio Cívico** ya verificada, APT purga `tesseract-ocr`, `libtesseract5`, `libarchive13t64` y `libxml2`, sin borrar ClamAV ni Poppler. No ejecuta `autoremove`.
4. Copia el binario y `libtesseract` personalizados; fija `TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata` para reutilizar `spa` y `eng`.
5. El build verifica la ausencia del archivo `libxml2.so.2`, la ausencia de los cuatro paquetes Debian y que `ldd` del nuevo ejecutable no tenga `libarchive`, `libcurl` ni `libxml2`.

Primero se probó Tesseract 5.5.0 con flags mínimos para demostrar la eliminación de dependencias, **pero esa versión no es aceptable** por los fallos de memoria publicados en 2026. La fuente se actualizó a la versión **5.5.4** antes de las pruebas finales; Debian registra la corrección de `CVE-2026-73066`, `73067` y `88047`–`88054` en `tesseract/5.5.4-1`. Los problemas de seguridad no cubiertos por ese listado requieren vigilancia.

La imagen **5.5.4** superó, usando solo archivos sintéticos y sin red, los mismos **6/6 escenarios PDF/ClamAV/OCR** y **4/4 controles HTTP** que la imagen original. Se descubrió y corrigió un primer fallo por ubicación de modelos `spa`/`eng`; no se relajaron los criterios OCR.

## Resultado del escaneo y limitación de seguridad

| Hallazgo Trivy | Imagen anterior | Candidata experimental |
| --- | ---: | ---: |
| CRITICAL | 1 | **0** |
| HIGH | 149 | **130** |
| UNKNOWN | 19 | **19** |
| Total de registros CVE | 634 | **586** |
| Componentes del SBOM CycloneDX | 186 | **182** |

La **ausencia de `libxml2` está probada** mediante APT, sistema de archivos y enlace dinámico. Pero **esta tabla NO demuestra que se hayan corregido los 19 HIGH de diferencia**: al compilar Tesseract desde fuente en una ubicación custom, Trivy deja de inventariar sus componentes `tesseract-ocr` y `libtesseract5`. Un escaneo de imagen con 0 críticos y menos registros puede ocultar un binario no rastreado. La propia documentación Trivy advierte que los paquetes compilados fuera de gestores del sistema pueden no detectarse.

El procedimiento `bash apps/inspector/validate_ocr_candidate.sh` exige preflight, build solo local, los 10 escenarios funcionales reales, Trivy y CycloneDX. **Siempre falla cerrado (exit 2) mientras el OCR personalizado no figure correctamente en el inventario y no exista una revisión de seguridad aprobada.** No hay despliegue, imagen publicada, VEX ni migraciones remotas. El gate operativo actual permanece sin excepciones.

## Condiciones de promoción futura

1. Integrar la compilación aislada y reproducible en el Dockerfile de producción **sin depender de una etiqueta mutable del host**, y preservar las firmas GPG verificadas de ClamAV.
2. Inventariar el binario, la biblioteca y la versión de fuente Tesseract 5.5.4 mediante **SBOM CycloneDX con PURL, SHA-256 de artefactos y procedencia**, y usar un análisis de avisos upstream que cubra software compilado desde fuente. No declarar `passed` mientras Trivy no lo vea.
3. Repetir el escaneo, comprobar fallos nuevos de memoria y mantener el bloqueo ante cualquier CRITICAL/HIGH/UNKNOWN que no tenga remediación o VEX formal aprobado.
4. Comparar OCR en español sobre un corpus ficticio representativo: páginas rotadas, escaneos de baja calidad, tablas, sellos, números de expediente, caracteres con tilde y documentos de varias páginas. Definir umbrales de precisión sin inventarlos ni liberar documentos automáticamente.
5. Repetir los 6+4 smokes, límites de tiempo/RAM, prueba de integridad y caducidad de firmas ClamAV con la imagen resultante. Para Preview se requieren autorizaciones separadas de seguridad, recursos, costos y Access/MFA.

## Fuentes y referencias

- [Debian: CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653).
- [Tesseract 5.5.0 CMake: DISABLE_ARCHIVE/DISABLE_CURL](https://sources.debian.org/src/tesseract/5.5.0-1/CMakeLists.txt).
- [Debian: parche Tesseract 5.5.4-1, bug 1147403](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1147403).
- [Tesseract: aviso GHSA-96jm-jc65-f968](https://github.com/tesseract-ocr/tesseract/security/advisories/GHSA-96jm-jc65-f968).
- [Trivy: cobertura de paquetes Debian y software compilado](https://trivy.dev/docs/dev/coverage/os/debian/).
- [ADR-013](ADR-013-inspector-sbom-cve-gate.md) · [ADR-014](ADR-014-native-zlib-signature-lifecycle.md) · [ADR-015](ADR-015-runtime-cve-triage.md).
