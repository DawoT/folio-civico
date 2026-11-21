# R1.50 · Revisión obligatoria de páginas PDF con texto e imágenes (S05-02 / G4)

**Fecha:** 21-11-2026, America/Lima. **Base de trabajo:** `main@c5c9b880ce3b204367b7ce948913b6ee8ba9be17`. **Estado:** ingeniería y verificación local, NO RELEASE. **Dependencias:** G2 [#75](https://github.com/DawoT/folio-civico/issues/75), G4, flujo de revisión institucional.

## Hallazgo reproducido

`inspect_pdf()` usaba `pdftotext` por página y solo invocaba `pdftoppm`/Tesseract si el resultado quedaba vacío. Una página con texto digital y un XObject raster podía retornar `scanVerdict="clean"` y páginas firmadas sin representar el contenido visual. Ese estado es inadmisible como evidencia documental completa: texto seleccionable no acredita cobertura de imágenes.

Se creó `fixtures.mixed_pdf()` con **un único PDF sintético y determinista** que contiene texto seleccionable `EXPEDIENTE OBRA 2026` y una imagen con píxeles de caracteres originales `2026 OBRA`. No incorpora datos de personas o instituciones, imágenes externas ni documentos reales. En TDD, el test de inspección mixta falló (devolvía un manifiesto `clean` sin llamar a `pdfimages`); tras el cambio exige `ReviewRequired` sin emisión de manifiesto.

## Barrera y alcance

Después de las puertas existentes ClamAV, QPDF antiencriptación/check, ausencia de adjuntos y `pdfinfo`, el texto digital inválido, excesivo o con caracteres de control se rechaza antes de un segundo parser Poppler. **Solo en las páginas en que `pdftotext` entrega texto válido no vacío**, se ejecuta `pdfimages -f PAGE -l PAGE -list original.pdf`. El resultado se valida con el contrato de columnas, separador, filas exactas, página solicitada, índices de imagen no repetidos, campos numéricos y límite de 256 KiB. Una fila de imagen o cualquier informe ambiguo produce `ReviewRequired`, que se traduce al HTTP **422 sin manifest, firma o cita**. La ausencia física del binario, el fallo de lanzamiento o un timeout produce `ScannerUnavailable` / HTTP 503; un exit distinto de cero del parser (según el contrato compartido de `command`) se clasifica como `ReviewRequired` / HTTP 422. Startup y preflight exigen `pdfimages`. Ningún error concede `clean`.

El flujo de **solo texto sin imágenes** continúa devolviendo `clean`. El flujo **solo imagen sin texto** mantiene OCR con el preflight MediaBox/UserUnit y el control del PNG. No se ejecuta OCR indiscriminado sobre páginas mixtas ni se mezclan textos sin alineación/cobertura.

**Trade-off explícito:** incluso un logotipo, firma escaneada o una imagen decorativa junto a texto provoca 422. Es intencionalmente conservador mientras no exista un flujo revisado de OCR mixto y semántica visible de `needs_review`. `pdfimages` enumera imágenes reconocidas por Poppler; **no demuestra cobertura de contenido dibujado mediante vectores, patrones, anotaciones ni todos los mecanismos visuales PDF**. La presencia de una imagen no prueba que contenga texto; solo impide certificar que no lo hay. No es una evaluación integral de G4.

## Evidencia con motores reales, imagen experimental fija

**Imagen experimental local, no publicable:** `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a`, base de la investigación R1.48. El código actualizado `inspector.py` y la función generadora del corpus se montaron **solo lectura** y de modo explícito sobre un contenedor efímero (`--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, límites de CPU/RAM/pids y tmpfs). Sin despliegue ni documentos institucionales.

| Caso sintético | `pdftotext` | `pdfimages` | `inspect_pdf` real |
|---|---|---|---|
| Página nativa | Texto | Sin imágenes | `clean` |
| Página mixta | Texto | Imagen detectada | **`review_required`** |
| Página escaneada | Sin texto | Imagen detectada | `clean` tras OCR |

La prueba usó Poppler, QPDF, ClamAV y Tesseract **reales** de la imagen local, no sustitutos de motores para esta matriz. Código y fixture nuevos se pasaron en montajes read-only, no se alteró la imagen fijada.

**Identidad adicional:** `/opt/folio-poppler/bin/pdfimages` es un ELF regular de modo `0755`, SHA-256 `e1610ede59f8e67aff468ef8c45f3fda45fde1716184530bf79e24a4e88b90ba`, `ldd` exit 0, sin `not found` ni las bibliotecas prohibidas del perfil Poppler. Este hash medido es **identidad local**, no firma de proveedor, trazabilidad completa de compilación ni validación CVE; el inventario histórico `source_inventory.py` no incluía `pdfimages` entre los cinco ejecutables nativos atestados y su ampliación debe ser evaluada antes de G2.

## Seguridad, regresión y salida

Las pruebas unitarias adversariales exigen fail-closed ante salida vacía/malformada, filas duplicadas, página incorrecta, caracteres de control, longitud excesiva, binario ausente y rechazo de cifrados antes de cualquier parser Poppler. El estado final CI se registra contra commit/árbol exactos; no considerar esta documentación como su evidencia sustitutiva.

**Persisten G2 y G4 pendientes.** Trivy conserva, según la última validación R1.48, 55 HIGH y 15 UNKNOWN sin tratar; esta modificación no reparó CVE ni emitió VEX. Para un lanzamiento real se requiere análisis de procedencia del nuevo ejecutable, tratamiento de contenido mixto con segmentación, evaluación humana de fidelidad/cobertura, límites, y confirmación de transporte al estado visible de revisión. No publicar OCI ni usar Preview/producción, D1 remoto o PDFs institucionales.
