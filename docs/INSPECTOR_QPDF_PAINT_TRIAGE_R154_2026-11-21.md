# R1.54 · G4 — prototipo de triage semántico de pintura PDF (NO RELEASE)

**Fecha:** 21-11-2026. **Base:** `main@894eed91a30b14ccb4a4e8c066c0ac9a4bb912a0` y corpus local R1.53 `ddc1e38fda196a983f8e4a87b80443d0606d3e44`. **Seguimiento:** [#134](https://github.com/DawoT/folio-civico/issues/134). **Estado:** investigación sintética; no conectado a `inspect_pdf`, al endpoint ni a un contrato de producción; no desbloquea G2/G4.

## Hipótesis y método

R1.50 detecta imágenes raster en páginas con texto, pero una página puede contener contenido vectorial relevante y recibir `scanVerdict=clean` mientras `pdftotext` omite información visible. El laboratorio R1.53 demostró el caso `EXPEDIENTE OBRA 2026` + `6002` dibujado con 67 rectángulos negros.

Este prototipo estudia **operadores PDF semánticos**, evitando expresiones regulares contra el archivo PDF sin procesar: primero el motor nativo QPDF valida objetos, localiza los streams de cada página y entrega JSON v2 con datos **descomprimidos y codificados en base64**:

```sh
qpdf --json --json-key=pages --json-key=qpdf \
  --json-stream-data=inline --decode-level=all synthetic.pdf
```

El módulo experimental `apps/inspector/qpdf_paint_triage_r154.py` consume ese JSON usando el parser estricto de QPDF ya disponible en el inspector. Verifica versiones y referencias, contenido decodificado con tamaño acotado, y tokeniza de manera conservadora el lenguaje de streams PDF: omite comentarios y operadores escritos *dentro de cadenas* (incluidas cadenas anidadas/escapadas, hex y arrays) y reconoce solo operadores de texto y estado gráfico no dibujante. Las primitivas de trazado/relleno, imágenes inline, formularios XObject, sombreado y cualquier operador no reconocido causan `True` (pintura potencialmente no transcrita). Sintaxis ilegible, recursos irresolubles y presupuestos excedidos producen `ReviewRequired`, nunca una atestación de cobertura.

Las apariencias de anotaciones y los recursos `/Pattern`, `/Shading`, `/XObject`, `/ExtGState` obligan a revisión. Se examinan las fuentes del diccionario de recursos: `/Type3` y familias no reconocidas derivan a revisión porque la propia definición de cada glifo puede ejecutar operadores visuales. Font references inválidas o ausentes producen `ReviewRequired`. Estos controles reducen falsos negativos evidentes, **sin certificar exhaustividad del intérprete PDF**.

## Contrapruebas con ejecutables reales, sin datos externos

Imagen Docker local exacta `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a`, QPDF 12.2.0 / Poppler 25.03.0, `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`; recursos/pids acotados. Entraron solo scripts Python montados readonly. Los documentos se generaron y eliminaron en tmpfs.

| PDF sintético | QPDF `--json-stream-data=inline --decode-level=all` | Evaluación del prototipo |
|---|---|---|
| Texto seleccionable Helvetica | exit 0; stream resuelto | `False`: no operadores adicionales observados |
| Mismo contenido digital comprimido con `/FlateDecode` | exit 0; QPDF lo decodificó | `False`: mismo resultado sin leer bytes comprimidos como texto |
| Texto digital + `6002` dibujado en 67 rectángulos | exit 0; streams resueltos | `True`: operadores de pintura detectados |

El probe completo R1.53, ahora con **cuarto módulo montado** `qpdf_paint_triage_r154.py`, pasó con `exit 2` **esperado** y respuesta `status=vector_evidence_gap_reproduced_release_blocked`, `visible_vector_dark_pixels=4288`, `qpdf_decoded_paint_detected=true`, `qpdf_native_text_control_drawing_detected=false`, `visual_value_omitted_from_manifest=true`, `g4_gate=blocked`, `release_authorized=false`.

Pruebas unitarias del módulo cubren texto puro, strings que contienen letras equivalentes a operadores (`f`, `Do`, etc.) sin dibujar, comentarios, hexadecimal, arrays, trazos, imágenes inline, Form XObjects, `gs`, anotaciones, Type3, recursos falsos, referencias repetidas, base64 malformado, streams múltiples, límites de tokens y errores de sintaxis. Las rutas de error no contienen datos de documentos.

## Riesgos y pendientes para la integración real

1. **No convertir un `False` en `clean`:** la implementación solo identifica un subconjunto sintáctico conocido; los flujos pueden referenciar fuentes con métricas extrañas, apariencias, contenidos opcionales y otras estructuras del estándar PDF. Los recursos se rechazan de modo conservador y faltan controles de `ToUnicode`, mapas de glifos, composición, clipping, páginas con múltiples recursos heredados y pérdida de texto que no implique pintura extra.
2. **No ampliar la superficie de ataque de forma silenciosa:** pedir `--json-stream-data=inline` puede exigir a QPDF descomprimir streams adicionales (no solo el de la página investigada) y elevar CPU/RAM. El prototipo es offline, pero una futura integración debe resolver únicamente las referencias necesarias, reutilizar límites por página, evitar buffers gigantes y añadir medición de latencia/recursos.
3. **Tasas de falsos positivos pendientes:** algunos PDFs legítimos con vectores decorativos, tablas, marcas, firmas o fuentes complejas serán revisados. Probar corpus estratificado y registrar reglas de derivación humanas antes de bloquear masivamente PDFs nativos.
4. **Contrato documental:** separar `scanVerdict` (AV/archivo) de `extractionCoverage` (fidelidad e incertidumbre). Un `review_required` no reemplaza OCR regional ni revisión humana; no liberar G4 con un simple parser de operadores.

**Situación de integración:** Solo se modifica la investigación local `test/vector-evidence-gap-r153`. Sin PR, push ni merge por WIP=2 de #133 (PR #135 y #139). No cambió `apps/inspector/inspector.py`, código productivo, Dockerfiles ni configuración de CI/Cloudflare. El CI integral no se ejecutó mientras otras tareas reservaron el runner local. **G2 y G4 permanecen BLOQUEADOS; sin publicación OCI, Preview/producción, D1 remoto, datos institucionales ni VEX.**
