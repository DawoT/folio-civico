# Investigación R1.6 · Fontconfig es requisito de integridad documental

**Fecha:** 2026-11-19 (America/Lima)
**Estado:** variante sin Fontconfig **DESCARTADA**; no desplegable, no sustituye `validation`, `ocr-integrated` ni `poppler-experiment`.

## Hipótesis y resultado

El perfil Debian de Poppler 25.03.0-5+deb13u4 utiliza `libfontconfig`, que enlaza transitivamente `libexpat1` (4 HIGH y 2 UNKNOWN reportados por Trivy). Se comprobó si el backend oficial de Poppler `-DFONT_CONFIGURATION=generic` permitía desactivar Fontconfig y ese enlace sin sacrificar la extracción y el renderizado PDF.

Se compiló en **una imagen local completamente separada** denominada `folio-civico-inspector:poppler-generic-research`, preservando las tres imágenes anteriores. Builder desde `apt-get source poppler=25.03.0-5+deb13u4` con parches Debian, `ENABLE_LIBCURL/GPGME/NSS3=OFF`; el único cambio funcional respecto de la variante anterior es `FONT_CONFIGURATION=generic`. Se verificó ausencia de `libfontconfig` y `libexpat` en los enlaces de los cinco CLI PDF y `libpoppler.so.147` mediante `ldd`. **La ausencia de enlace no constituye un cierre de CVE** ni prueba ausencia de las bibliotecas en todas las capas OCI.

El experimento **compiló, pero falló** `bash apps/inspector/build_poppler_generic_research.sh` con exit **1**, reportando `real_engine_validation_failed`. La inspección por fases mostró extracción `pdftotext` válida para PDF sintético, creación del fichero raster, rechazo de PDFs negativos y detección antivirus EICAR, pero **OCR del PDF rasterizado rechazado** por `ReviewRequired`.

## Evidencia cuantitativa del defecto

Se ejecutó `pdftoppm -f 1 -l 1 -singlefile -gray -r 72` sobre el **mismo** `native_pdf()` sintético original, con página de 612 × 792 px y fuente PDF Base14 Helvetica no incrustada. Se contó como oscuro cada píxel gris con valor inferior a 230:

| Imagen local | Resultado de Poppler | Píxeles oscuros |
| --- | --- | ---: |
| `poppler-experiment`, backend Fontconfig | render completo, exit 0 | **1882** |
| `poppler-generic-research`, backend genérico | render en blanco, exit 0 | **0** |

Por tanto, comprobar únicamente que `pdftoppm` devuelve 0 es insuficiente. La imagen sin Fontconfig puede **eliminar contenido visual sin error de proceso**. Adicionalmente, `bash apps/inspector/compare_ocr_quality.sh --generic` terminó con exit **1** y `ReviewRequired: Empty, unsafe or oversized page text`. Este caso supera a la simple prueba de enlace y es un riesgo de integridad en documentos reales con fuentes no incrustadas.

## Mitigación incorporada al harness de aceptación

`apps/inspector/smoke_real_engines.py` ahora exige **tinta visible** al rasterizar el PDF sintético de texto antes de construir la muestra escaneada. `require_visible_synthetic_ink` valida dimensiones y número de píxeles, y rechaza páginas blancas o casi blancas con un umbral reproducible `max(64, width * height // 5000)` para `pixel < 230`. No registra texto, píxeles ni rutas. Se añadieron pruebas unitarias de páginas blancas, casi blancas, válidas y raster inválido. Este test no sustituye validaciones exhaustivas de documentos institucionales: evalúa una fixture original fija.

El Dockerfile original `Dockerfile.poppler-experiment` se refuerza con `-DFONT_CONFIGURATION=fontconfig` y comprobación explícita de `libfontconfig` en `ldd`. **No** se integró la variante genérica fallida en el diseño del inspector, ni se incorporó su Dockerfile/constructor al repositorio; la imagen de investigación local queda separada y no se publica.

`apps/inspector/verify_raster_guard.sh` permite ejecutar el **harness actualizado del repositorio** dentro del ID inmutable de la imagen experimental anterior, offline, sin mounts ni rebuild, para verificar la nueva aserción en motores reales.

## Decisión y próximos bloqueos

1. **Rechazar** la propuesta `FONT_CONFIGURATION=generic` como mitigación para la cadena Expat: rompe el renderizado de fuentes PDF Base14.
2. Conservar Fontconfig y obtener correcciones verificadas de **Expat para Debian Trixie**, con sus seis CVE analizados individualmente. Expat 2.10.0 resuelve cuatro, pero no los dos CVE posteriores; `unstable` no se introducirá en producción.
3. Mantener pendientes los CVE de Poppler desde fuente (incluidos `CVE-2026-107705` y `CVE-2026-93653`) y las siete alertas históricas de ClamAV 1.5.5 hasta aprobación técnica.
4. No debilitar `audit_image.py`: las imágenes candidata y experimental siguen **bloqueadas, exit 2**. Toda integración del código en `main` se somete a [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md). Sin Preview, deploy ni datos institucionales.

Fuentes externas: [Debian Expat tracker](https://security-tracker.debian.org/tracker/source-package/expat), [Debian Poppler tracker](https://security-tracker.debian.org/tracker/source-package/poppler), [dossier CVE R1.5](SECURITY_CVE_REVIEW_2026-11-19.md).
