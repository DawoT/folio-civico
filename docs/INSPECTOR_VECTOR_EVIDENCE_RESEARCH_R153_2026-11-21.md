# R1.53 · G4 — Reproducción persistente de evidencia PDF vectorial omitida

**Fecha:** 2026-11-21 (America/Lima). **Issue:** [S05-02 / G4 #134](https://github.com/DawoT/folio-civico/issues/134). **Base:** `main@894eed91a30b14ccb4a4e8c066c0ac9a4bb912a0`. **Naturaleza:** investigación / TDD de contrato, **NO corrección de producción ni RELEASE**. No sustituye la evaluación de G2.

## Defecto observable

En R1.50 `inspect_pdf()` hace `pdftotext` para texto nativo y `pdfimages -list` para identificar XObjects raster, rechazando las páginas mixtas con imagen. **No detecta evidencia visual dibujada mediante rutas vectoriales**. Ya se documentó el fallo en [#134, reproducción original](https://github.com/DawoT/folio-civico/issues/134#issuecomment-7065369288): texto `EXPEDIENTE OBRA 2026` y valor `6002` dibujado como segmentos rectangulares, ausente del texto seleccionable. El inspector real emitió un manifiesto `clean` sin ese dato gráfico.

Esta rama de investigación introduce `apps/inspector/probe_vector_evidence_r153.py`: corpus sintético original **recreado en memoria**, validación de fuentes/ink y contrato de resultados estrictamente **bloqueados**. No se cambia `apps/inspector/inspector.py`, su API, los tests de producción existentes, Dockerfile, datos ni configuración de despliegue.

## Contrato reproducible

El script genera **un PDF de una página sin XObject raster**. Contiene un texto de control `EXPEDIENTE OBRA 2026` y el número **`6002`** dibujado con 67 rectángulos PDF (`re f`) en una zona distinta del texto. Luego:
1. Interroga **Poppler real** `pdftotext` para verificar que el valor gráfico NO está en la capa digital, y `pdfimages -list` para demostrar que no existe imagen raster declarada.
2. Renderiza a **72 DPI en escala de grises** usando `pdftoppm` y cuenta los píxeles oscuros de la región gráfica exacta, bajo un límite fijo de bytes y dimensiones; exige al menos 1.000. Un raster en blanco, inesperado o corrupto no pasa por evidencia suficiente.
3. Ejecuta `inspect_pdf` **real** con una muestra nativa de control positivo (`clean` + texto esperado), y con la muestra vectorial. Registra los parsers alcanzados (sin copiar contenido ni rutas privadas). No intercepta ni simula la salida de motores.
4. Si el inspector da `clean` con solo el texto digital, devuelve `status=vector_evidence_gap_reproduced_release_blocked`; si una corrección futura fuerza revisión, `status=vector_evidence_review_required_release_blocked`. Ambos producen **exit 2** y `release_authorized=false` — el segundo tampoco prueba cobertura visual integral. Prueba ilegible/incompleta => **exit 3** con diagnóstico genérico sin paths de origen.

Las ocho pruebas en `apps/inspector/tests/test_vector_evidence_probe_r153.py` verifican determinismo, corpus no raster, aislamiento de tinta, entradas/PPM adversariales, resultados esperados sin aprobación y ausencia de fugas en errores. El script requiere ejecución **manual explícita** con motores locales; `scripts/ci.sh` no lo ejecuta ni debe entender un exit 2 como éxito de release.

### Reproducción offline, imagen local exacta

Imagen **de investigación** `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a`, sin OCI publicado, red, PDFs institucionales ni dependencias externas nuevas.

Desde la raíz del worktree R1.53, ejecutar en un entorno con Docker local y esa imagen ya disponible:

```bash
ROOT="$(pwd)/apps/inspector"
IMAGE="sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a"
docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --mount "type=bind,source=$ROOT/inspector.py,target=/probe/inspector.py,readonly" \
  --mount "type=bind,source=$ROOT/fixtures.py,target=/probe/fixtures.py,readonly" \
  --mount "type=bind,source=$ROOT/probe_vector_evidence_r153.py,target=/probe/probe_vector_evidence_r153.py,readonly" \
  --entrypoint python3 "$IMAGE" -I -c \
  "import sys;sys.path.insert(0,'/probe');import probe_vector_evidence_r153 as p;raise SystemExit(p.main())"
```

**Ejecución observada** (Poppler, QPDF, ClamAV reales; sandbox no privilegiado y sin red, montajes read-only): `exit 2`, `drawn_rectangles=67`, `visible_vector_dark_pixels=4288`, `raster_xobject_detected=false`, `vector_value_selectable=false`, `visual_value_omitted_from_manifest=true`, `status=vector_evidence_gap_reproduced_release_blocked`, `g4_gate=blocked`, `release_authorized=false`. Las pruebas unitarias solo comprueban la lógica y la forma del corpus; **esta ejecución real** acredita el comportamiento concreto, no la completitud de Poppler ni la aplicabilidad de CVE.

## Próximo contrato de aceptación para G4 (no implementado)

- Añadir un test RED en el **pipeline de inspección** con esta muestra. La condición de éxito es **no producir un manifiesto `clean` firmado** hasta verificar el tratamiento de gráficos en una página mixta.
- Diseñar un modelo diferenciado `scanVerdict` (seguridad del archivo/AV) y `extractionCoverage` (fidelidad/alcance del contenido visible). Evitar que una clasificación `clean` del AV se presente como transcripción completa.
- Resolver de modo semántico los operadores PDF —incluidos streams comprimidos, Form XObjects, anotaciones, patrones y contenido opcional— o, ante incertidumbre, derivar a revisión humana. **No usar regex sobre bytes de PDF como salvaguarda.**
- Añadir estratos sin regresión: texto puro, logo decorativo, firma escaneada, tablas raster, texto vectorial, contenido duplicado y PDF heterogéneo; medir omisión, CER/WER, falsos positivos y límites de RAM/latencia sobre material sintético o autorizado.
- Mantener G2 y G4 bloqueados; no solicitar excepciones, publicaciones OCI, Preview/producción ni D1 remoto a partir de este experimento.

**Gobierno / WIP:** #133 limita a dos PR de código activos. Al crear este trabajo estaban abiertos **#135 (G2) y #139 (BE-01)**; otros carriles FE/CI también tenían commits. Esta rama R1.53 **permanece local, sin PR ni push** hasta contar con cupo y revisión independiente. No se ejecuta CI shell pesada junto con los otros carriles. Ninguna limpieza de ramas o worktrees ajenos.
