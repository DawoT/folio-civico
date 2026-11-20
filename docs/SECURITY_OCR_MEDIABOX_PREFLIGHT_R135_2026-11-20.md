# R1.35 · Barrera MediaBox por página antes de raster OCR (ingeniería sin release)

**Fecha:** 2026-11-20 (America/Lima). **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Rama:** `security/ocr-mediabox-preflight-r135`.

## Resultado implementado

`apps/inspector/inspector.py` ahora consulta `pdfinfo -f PAGE -l PAGE -box` **solo si una página necesita OCR** (`pdftotext` devuelve texto vacío) y ejecuta `require_ocr_raster_geometry` **antes de `pdftoppm -singlefile -r 180 -png`**.

- Requiere un inventario de páginas coincidente con el `pdfinfo` inicial y una línea completa por `size`, `rot`, `MediaBox` y `CropBox` de la página exacta. Rechaza duplicados, rotaciones inválidas, números no finitos, rectángulos sin área, texto truncado/inesperado, metadatos no ASCII y dimensiones o coordenadas excesivas.
- Calcula presupuesto sobre **MediaBox**, no sobre `Page size` (que Poppler reporta con el tamaño del `CropBox`). Usa `Decimal` y techo hacia arriba a 180 DPI, sumando 0.02 pt para compensar redondeos de las coordenadas textuales de `pdfinfo -box`.
- Las páginas solo texto **no incurren en una llamada adicional** a `pdfinfo` ni son rechazadas por este presupuesto OCR.
- Herencia de MediaBox: el resultado `pdfinfo -box` exhibe el MediaBox efectivo en los controles originales de R1.34. R1.35 valida la línea resultante por página; no parsea directamente la sintaxis o los objetos PDF.
- **QPDF mantiene la prioridad:** `qpdf --is-encrypted` y `qpdf --check` se ejecutan antes de cualquier invocación Poppler. Las fallas de validación producen `ReviewRequired` y nunca un manifiesto «clean»; un motor no disponible produce `ScannerUnavailable`.
- No cambia el formato de manifiesto, los servicios Cloudflare, el pipeline HMAC ni las versiones de los binarios.

## Presupuesto de admisión OCR inicial

| Parámetro | Límite |
| --- | ---: |
| DPI | 180 |
| Ancho y alto | hasta **8192 px cada uno** |
| Producto ancho × alto | hasta **32 000 000 píxeles** |
| Valor absoluto de coordenada MediaBox/CropBox | hasta **1 000 000 pt** |
| Tamaño máximo del reporte de metadatos | **65 536 bytes** |

Estas cotas se aplican por página **antes** de invocar el rasterizador. Documentos A1 (1684×2384 pt) y A2 (1191×1684 pt) pasan los presupuestos de las pruebas, así como el A4 estándar. A0 (2384×3370 pt) supera 8192 px en su lado largo y requiere revisión o un flujo de redimensionamiento separado, aún no implementado.

**Decisión provisional de producto:** se prioriza impedir asignaciones gigantes en el flujo OCR en vez de admitir silenciosamente todo tamaño. El rechazo de planos A0 puede ser un coste funcional real; debe confirmarse con propietarios del producto y mediciones de OCR de documentos **sintéticos o autorizados** antes de cualquier despliegue. `32 Mpx` no es una prueba de seguridad de memoria; la presión depende de las estructuras de Poppler, la profundidad de imagen, fuentes, contenidos PDF y cgroup. El límite anterior de 16 Mpx en R1.33 era solo diagnóstico; no se reutilizó como política porque rechazaba páginas A1.

## TDD y regresión

Se añadió `apps/inspector/tests/test_ocr_mediabox_preflight.py` con **15 pruebas** y **40 subtests**. Comenzó en **Red** (el preflight no existía); tras implementar y corregir el harness se obtuvo **Green**:

- Medición sobre MediaBox con CropBox más pequeño, incluidas cajas heredadas.
- Rotación 0/90/180/270, páginas heterogéneas, A1/A2 y rechazo A0/extremos (`536870919×1`).
- Metadata corrupta, ausente, duplicada, inconsistente, no finita y límites de tamaño.
- Integración del orden QPDF → `pdftotext` → `pdfinfo -box` → `pdftoppm` → Tesseract, con ausencia de raster al fallar el preflight.
- Ningún coste de preflight adicional en páginas únicamente textuales.

`test_inspector.py` actualiza el mock de `pdfinfo -box` a un inventario sintético con geometría correcta. La regresión Python completa del inspector: **379/379 pruebas, 499 subtests**, en la rama aislada.

## Límites explícitos de la evidencia

1. La imagen experimental de Poppler por ID SHA-256 de R1.33/R1.34 ya no está disponible en el daemon local. No se ejecutó el nuevo guard con el binario Poppler en su imagen definitiva ni el orquestador R1.34 con las nueve páginas. Los tests de mock no sustituyen una prueba real.
2. `pdfinfo -box` redondea coordenadas y no acredita la semántica de `UserUnit`, contenidos arbitrarios o memoria interna de `pdftoppm`. El guard es **defensa en profundidad**, no prueba universal de un límite de asignación de memoria.
3. R1.31 reprodujo el overflow en una ruta de laboratorio con flags distintos. R1.34 demostró el desacople de Page size/CropBox frente a MediaBox; ninguna de esas pruebas afirma que se alcanzó el mismo crash con los flags OCR reales.
4. Falta evaluar fidelidad OCR para geometrías grandes (A1/A0), fuentes y combinaciones UserUnit no triviales, contenido PDF hostil y equivalencia de ELF experimental frente a runtime.
5. Trivy/ADRs, evidencias de procedencia y aprobación del entorno siguen bloqueantes; **no** se modifica OCI, no se publica imagen, no se autoriza Cloudflare, D1 remoto ni producción, ni cierre de CVE o VEX.

## Estado de entrega

La barrera **se ha implementado en código** pero **no se declara validada en el runtime definitivo**. La integración del código en `main`, si supera CI y revisión, es distinta de habilitar el inspector, liberar una imagen o cerrar el Issue #68.

**release_authorized=false · cve_remediation_claimed=false · runtime_binary_smoke_verified=false**.
