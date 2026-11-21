# R1.51 — Atestación local de `pdfimages` en inventario nativo del inspector (NO RELEASE)

**Fecha:** 2026-11-21, America/Lima. **Issue:** [#75](https://github.com/DawoT/folio-civico/issues/75) / G2. **Contrato:** [#133](https://github.com/DawoT/folio-civico/issues/133). **Base:** `origin/main@894eed91a30b14ccb4a4e8c066c0ac9a4bb912a0`. **Estado de release:** `release_authorized=false`.

## Problema reproducido

Tras PR #132, `inspect_pdf()` invoca `pdfimages -list` para detectar XObjects raster sobre páginas con texto digital. `apps/inspector/source_inventory.py` y `apps/inspector/audit_image.py` todavía exigían solo cinco binarios Poppler, sin el nuevo `pdfimages`. De esta manera, un reporte omitía su identidad ELF/DSO aunque el parser influye en `clean` frente a `review_required`. No es evidencia de una explotación; es una brecha de atribución necesaria para cualquier análisis G2.

## TDD y alcance

**RED, candidato aislado, antes de editar el código:** `python3 -m unittest discover -s apps/inspector/tests -p test_source_inventory.py` → exit 1, 2 fallos (inventario no exige `pdfimages` y no lo contabiliza). `... -p test_image_audit.py` → exit 1, 1 error (inventario de seis herramientas rechazado por la expectativa antigua de cinco). La prueba adversarial exige rechazar la ausencia de `pdfimages` y su ausencia en un reporte supuestamente completo.

**GREEN:** `POPPLER_TOOLS` contiene ahora `pdfimages` además de los cinco binarios originales. El inventario verifica ELF SHA-256 y dependencias dinámicas (ldd, sin enlaces no resueltos o prohibidos); `audit_image.py` reutiliza esa lista, de modo que un registro que omite `pdfimages` falla cerrado. Los fixtures del gate de advisories y del comparador Poppler se actualizan al contrato completo. No se cambia el inspector HTTP, los límites OCR, política CVE/UNKNOWN, motores instalados, imágenes, dependencias ni configuración de deployment.

**GREEN observado:** `python3 -m unittest discover -s apps/inspector/tests` → **581/581, exit 0** sobre worktree aislado.

## Contraprueba con motor real, mismo objeto de imagen

`folio-civico-inspector:privileged-cli-pruned-research-r148`, ID Docker local exacto `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a`, Debian 13.7, `linux/amd64`; origen de laboratorio R1.47 `sha256:c506a8b40953167ee4f6486cb90217298a39ce680f0bdd5fdc3a8b9638ddb92d`. Contenedor efímero: `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --cpus 1 --memory 4g`; script de inventario actualizado transmitido por argumento `python3 -I -c`, sin volumen de host y sin documentos de terceros. **Exit 0**.

Inventario `mode=experiment`: dos motores desde fuente (`tesseract 5.5.4` y `poppler 25.03.0-5+deb13u4`); seis ejecutables Poppler con SHA-256. SHA-256 de `pdfimages` **`e1610ede59f8e67aff468ef8c45f3fda45fde1716184530bf79e24a4e88b90ba`**. `source_cve_coverage=unassessed`, `automated_cve_coverage=not_verified` para ambos componentes. El resultado acredita identidad local y enlaces observados, **no** firma vendor, equivalencia fuente→ELF, CVE aplicabilidad ni cobertura de parsers visuales completa.

## Escaneo G2 renovado, sin aprobación

`bash apps/inspector/scan_privileged_cli_research.sh` ejecutado después de comprobar `origin/main` y PR #132: **exit 2 esperado**. Trivy 0.76.2, DB `UpdatedAt=2026-11-20T18:59:53Z`, escaneo ~2026-11-21 15:42 UTC, CycloneDX/Trivy diferencial de R1.47→R1.48. R1.48: **0 CRITICAL, 55 HIGH, 15 UNKNOWN**, 32 HIGH util-linux, 15 entrypoints físicos removidos, 0 mutaciones ajenas, ELF/modelos iguales, `cve_remediated=false`, `vendor_package_attested=false`, `vex=not_issued`. Esta mejora solo completa la observabilidad del ejecutable `pdfimages`; no altera esos findings ni avala una imagen para ejecución.

## Gobierno y riesgo residual

El contenedor local carece de autorización operativa; los hashes y CVE son medidos en una imagen experimental, **no** en un release publicado ni en el Dockerfile principal. G2: `blocked_runtime_release`. G4: sin cierre general para vectores/anotaciones/patrones ni cobertura humana de páginas mixtas. Cualquier PR debe tener revisión independiente, CI local y remota verde, merge y CI postmerge de `main` antes de contarse como integrado. No VEX, excepciones, publicación OCI, Cloudflare, Preview/producción o documentos institucionales.
