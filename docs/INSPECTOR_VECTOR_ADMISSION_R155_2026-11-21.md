# R1.55 · G4 — Triage conservador de evidencia vectorial en el inspector

**Fecha:** 21-11-2026 · **Issue:** [#134](https://github.com/DawoT/folio-civico/issues/134) · **Base:** `origin/main@894eed91a30b14ccb4a4e8c066c0ac9a4bb912a0`.

**Alcance:** cambio de código candidato LOCAL, **sin PR/push/merge**, sin despliegue, no publicación OCI, no documento institucional. Sigue condicionado a #133 (WIP dos PR), revisión independiente #72, CI shell integral sobre commit exacto y G2 de seguridad del runtime. **G4 permanece bloqueado.**

## Hallazgo previo, reproducible

El inspector de R1.50 usa `pdftotext` y `pdfimages -list`; un PDF con texto digital y el valor `6002` dibujado como **67 rectángulos vectoriales** devolvía `scanVerdict="clean"` aunque el manifiesto omitía el valor visible. Los experimentos R1.53 y R1.54 reprodujeron la omisión sin usar PDF institucional ni suposiciones sobre imágenes raster.

**RED R1.55:** `tests/test_pdf_vector_admission_r155.py` añadió casos de comportamiento del inspector, con QPDF v2 simulado de forma determinista, sin cambiar el motor: cinco fallos entre cinco casos, incluidos falso `clean` vectorial, fuente Type3 y QPDF de verificación no disponible. El control positivo de texto seleccionable también exigía comprobar streams.

## Implementación acotada

`inspector.py` consulta los objetos estructurados QPDF **solo tras** la comprobación de cifrado `qpdf --is-encrypted`, `qpdf --check`, el antivirus y la inspección de adjuntos; `pdfimages` sigue rechazando primero una página mixta texto+raster. Para una página de texto sin raster:

1. Un único `qpdf --json --json-key=pages` por documento obtiene identificadores de página y stream en orden. Se reutiliza para el preflight de `/UserUnit` de páginas OCR sin texto.
2. `qpdf_scoped_gate_r155.py` solicita **solo objetos identificados** mediante `--json-key=qpdf --json-object=N,G`. Solo en el stream de contenido solicitado añade `--json-stream-data=inline --decode-level=all`. **Nunca descomprime inline todos los streams del PDF**. Verifica identidad QPDF v2, correspondencia del diccionario `/Contents`, y referencias de fuente. Evita un stream alternativo, falso o no relacionado.
3. `qpdf_paint_triage_r154.py` tokeniza bytes del **stream ya descomprimido por QPDF**, excluyendo texto entre paréntesis, escapes, comentarios, secuencias hex y arrays. Un operador de pintura vectorial, forma XObject, sombreado, transparencia, imagen inline, anotación, font Type3 o recurso ambiguo obliga a `ReviewRequired`, no a un manifiesto `clean`.
4. Datos QPDF ilegibles, identidad alterada, recursos heredados no resueltos, `/Contents` incompatible, stream no decodificable, presupuestos excedidos y excepciones ambiguas **no permiten `clean`**. Si falta el módulo obligatorio, se devuelve `ScannerUnavailable`. Si QPDF falla como proceso se propaga `ScannerUnavailable`. No se incluyen rutas, datos de página ni PDF en el mensaje de error.
5. Se mantiene `scanVerdict` y firma HMAC existentes sin inventar valores `extractionCoverage`: **la ausencia de operadores de pintura extra no demuestra cobertura integral de transcripción**. La puerta de revisión humana G4 continúa pendiente por región y tipo de contenido.

## Límites explícitos de seguridad y rendimiento

- Cada subprocess hereda `MAX_PROCESS_SECONDS=30`, entorno restringido y un stdout máximo de **2 MiB**. El parser QPDF rechaza JSON mayores de **1 MiB** y claves duplicadas. Máximo **16 streams** por página, **128 KiB** por stream decodificado, **256 KiB** por página y **256 consultas de objetos** por documento.
- Las fuentes admitidas en el subconjunto de texto ordinario son Type1 y TrueType con referencias directas válidas; fuentes compuestas/Type0, Type3 y datos no resueltos se derivan a revisión. Sin `/Resources` directo tampoco se aprueba. Este sesgo puede aumentar la revisión de documentos válidos, intencionadamente.
- El presupuesto de consultas no supone un límite universal de memoria interna de QPDF: el sandbox, seccomp, CPU/memoria del contenedor y validación de CVE continúan siendo obligatorios; no se acreditó un benchmark de 100 páginas o PDFs adversariales grandes.
- No se afirma que Type1/TrueType garantice mapeo Unicode correcto, ni que el lexer cubra todas las apariencias, fuentes, clipping, marked content, optional content, patrones, capas, tipografía engañosa o manipulación visual. **G4 sigue bloqueado incluso si una página sintética retorna `clean`.**
- El `Dockerfile` del candidato copia explícitamente los dos módulos Python nuevos. Se reprodujo además una incompatibilidad real de **arranque aislado**: `python3 -I` excluye la ruta de los scripts, de modo que la sola instrucción `COPY` **no bastaba** para importar los módulos. Nueva prueba RED de subprocess Python `-I` con `PYTHONPATH` malicioso ignorado: `ModuleNotFoundError: qpdf_scoped_gate_r155`; GREEN: `inspector.py` añade explícitamente **solo su propio directorio de imagen** a la ruta Python y, si se ejecuta como `__main__`, registra el mismo módulo bajo `inspector` para evitar inicialización doble. No reintroduce `cwd` ni rutas provistas por el usuario. Prueba focal de arranque **10/10 PASS**.
- **No se construyó ninguna imagen nueva** ni cambió el digest experimental usado en las contrapruebas. El expediente G2 (#75) necesita nueva evaluación de runtime, endurecimiento de la ruta de módulos bajo filesystem readonly y CVE antes de habilitar OCI.

## Pruebas y evidencia real

- RED inicial focalizado: **5/5 fallos** contra el inspector anterior, por omisión de la verificación.
- GREEN posterior: **5/5** de regresión inicial; corrección de simuladores existentes de QPDF para exponer exclusivamente objetos y streams que el nuevo contrato necesita, preservando sus tests previos.
- Regresión ampliada (9 casos R1.55): streams y fuentes corruptos, identificadores de página adulterados, ausencia del motor, Type3, selectividad `--json-object` y presencia de módulos en Dockerfile.
- Suite Python completa del inspector: **605/605** después de armonizar fixtures; se revalidará sobre commit exacto tras cualquier edición adicional.
- **Motores reales, imagen local inmutable** `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a` (`--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, módulos candidatos montados readonly, ningún dato institucional):
  - Muestra de control texto puro: `inspect_pdf` devuelve `clean` esperado.
  - Muestra texto+valor vectorial `6002`: `inspect_pdf` ahora emite **`ReviewRequired`**.
  - **Flate real**: un segundo PDF sintético con texto digital y trazo `re f` dentro de `/FlateDecode` fue validado por motores reales; `inspect_pdf` devolvió `ReviewRequired` (**exit 0 del test de rechazo**, sin manifest firmado, `release_authorized=false`). Ninguna búsqueda de bytes crudos habría bastado para admitir el resultado.
  - Probe: **exit 2 esperado** con `status=vector_evidence_review_required_release_blocked`, `qpdf_decoded_paint_detected=true`, `qpdf_native_text_control_drawing_detected=false`, `drawn_rectangles=67`, `visible_vector_dark_pixels=4288`, `g4_gate=blocked`, `release_authorized=false`.

## Pendientes obligatorios para integración

1. Ampliar pruebas con PDF multipágina real (incluido texto seguido de OCR), streams comprimidos y recursos heredados/anotaciones/Type0, midiendo falsos positivos sin relajar el fail-closed.
2. Ejecutar `sh scripts/ci.sh` **exclusivo** contra HEAD/árbol limpio exactos cuando estén libres los recursos compartidos; CI local no es autorización G2 ni de deploy. No paralelizar con BE-03 ni otros repos.
3. Cupo de PR **2/2** ocupado por #135 y #139: esperar liberación legítima conforme #133; después PR, revisión independiente y merge, con nueva CI postmerge.
4. Para G4 global diseñar y medir `extractionCoverage` por región, OCR parcial, revisión humana y reconciliación de documentos heterogéneos. **No** etiquetar ni publicar como solución completa.

**Estado final:** `release_authorized=false`, G2/G4 blocked, sin waiver/VEX ni operaciones remotas.
