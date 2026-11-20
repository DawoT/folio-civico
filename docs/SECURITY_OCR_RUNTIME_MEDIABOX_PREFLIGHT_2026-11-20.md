# S05 / R1.36 — Límite preliminar de MediaBox antes de OCR

**Fecha:** 2026-11-20. **Issue:** #68. **Estado:** protección operativa parcial implementada localmente; **NO** aprobación del inspector, imagen OCI ni tratamiento de documentos institucionales.

## Vulnerabilidad de disponibilidad reproducida

La ruta `inspect_pdf()` ya escaneaba PDF con ClamAV y comprobaba cifrado con qpdf antes de entrar en Poppler. Para páginas donde `pdftotext` no encontraba texto, ejecutaba directamente `pdftoppm -r 180 -png`. El chequeo de 32 MiB sobre PNG sucedía **después** de que `pdftoppm` intentara reservar memoria.

La investigación R1.34, registrada en `docs/SECURITY_OCR_MEDIA_CROP_BOX_DIFFERENTIAL_2026-11-20.md`, midió que `pdfinfo Page size` puede seguir `CropBox`, mientras `pdftoppm` sin `-cropbox` usa `MediaBox`. Es inseguro presupuestar el raster solo con `Page size`.

## Cambio acotado

En `apps/inspector/inspector.py`, justo antes de rasterizar **cada página que necesita OCR**:

1. Ejecutar `pdfinfo -f N -l N -box original.pdf` con el runner existente, aislamiento de variables, límites de tiempo y salida. No se invoca cuando el texto digital es suficiente.
2. Exigir un inventario inequívoco: `Pages`, `Encrypted: no`, una línea de tamaño, una de rotación y una de `MediaBox` para la página solicitada. Rechazar metadatos malformados, omitidos, duplicados, no ASCII, truncados, con números no finitos o coordenadas fuera de `±1.000.000` puntos.
3. Calcular un **límite conservador** sobre `MediaBox` con decimal exacto y +0,02 puntos por redondeo de Poppler; aplicar rotaciones 90/270. Exigir ancho y alto estimados no superiores a **8192 píxeles** y área total no superior a **16 millones de píxeles**, a 180 DPI. Los valores son **provisionales** de R1.33; se deben confirmar con documentos sintéticos representativos y experiencia de OCR.
4. Rechazar la página entera con `ReviewRequired` (sin `scanVerdict: clean`) si falla el preflight. Solo ejecutar `pdftoppm` si pasa. No se cambian las firmas HMAC ni admisión SQL ni se publica imagen derivada.

Esto es *defensa en profundidad* y no una demostración general de cota de memoria: el proceso `pdfinfo` todavía analiza contenido no confiable **después** del preflight qpdf/ClamAV; `UserUnit`, estados internos de Poppler, herencia de cajas, crop fuera de media y transformaciones no certificadas pueden alterar dimensiones reales. Mantener cgroups, tiempo máximo y límite de PNG posterior.

## Pruebas y trazabilidad TDD

- **RED:** 33 tests dirigidos; nueva prueba del MediaBox `536870919×1` con CropBox `100×1` llegó a invocar `pdftoppm`. Las pruebas del parser fallaban porque no existía el método.
- **GREEN:** 34/34 en `test_inspector.py` y 368/368 de `python3 -m unittest discover -s apps/inspector/tests` (en el snapshot de implementación).
- Negativas: MediaBox extremo oculto por CropBox, lados y área elevados, coordenadas fuera de presupuesto, MediaBox degenerado, rotación inválida, referencias cruzadas de página, registros incompletos y duplicados, números no finitos, Unicode de control y metadatos excesivos.
- Positivas: páginas sintéticas A4/rotadas/recortadas dentro de presupuesto; dos páginas OCR verifican preflight por página **antes** de la rasterización. La ruta de texto digital evita un parser adicional.
- **Motores reales NO disponibles en el host de pruebas:** `pdfinfo`, `pdftoppm`, `qpdf`, `clamscan` y `tesseract` se comprobaron ausentes mediante `shutil.which`. Los tests de esta entrega son simulados, no deben presentarse como smoke real. La imagen experimental fijada en R1.34 no estaba disponible en el último intento, por lo que no reconstruir ni improvisar un tag.
- CI integral y checks GitHub del SHA exacto: registrar resultados en el PR. Ninguno sustituye el gate Trivy/SBOM/CVE.

## Pendiente para cerrar #68 y liberar OCR

1. Verificar con imagen **por digest** el mismo `pdfinfo -box` y `pdftoppm -r 180 -png` (sin `-cropbox`) sobre A4, A3, páginas recortadas, rotadas, MediaBox extremo, `UserUnit` y cajas heredadas.
2. Resolver o **rechazar explícitamente** `UserUnit` no demostrable mediante un parser estructural verificado antes de renderizar; no usar grep de bytes del PDF como falsa prueba.
3. Comprobar geometría real de los PNG, su correspondencia con el presupuesto, consumo de CPU/memoria y tiempos en el recinto de contenedor aislado. Incluir regresiones de documentos sintéticos válidos y documentar falsos rechazos.
4. Verificar origen/reproducción de los ELF de Poppler y gate de seguridad de imagen (issue #75, ADR-023); test `pnpm test:inspector:docker` y `pnpm audit:inspector:image` sobre **el mismo digest**. Aprobación institucional independiente antes de habilitar Cloudflare.

**Restricciones mantenidas:** sin despliegue, VEX, excepciones de seguridad, migraciones, manipulación de datos reales o declaración de PDF limpio si el preflight no termina correctamente.
