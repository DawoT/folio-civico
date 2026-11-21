# R1.51 · Procedencia ELF adicional para `pdfimages` (G2 / S05-02)

**Fecha:** 21-11-2026 (America/Lima). **Alcance:** investigación local **sin build, release, OCI ni datos institucionales**. **Antecedentes:** [#75](https://github.com/DawoT/folio-civico/issues/75), [#134](https://github.com/DawoT/folio-civico/issues/134), R1.50 / PR #132. **Seguridad:** `scanner_gate=blocked`, `release_authorized=false`.

## Causa y decisión de compatibilidad

R1.50 hizo obligatorio `pdfimages -list` para rechazar `clean` en páginas con texto digital e imágenes raster. El inventario `source_inventory.py` (`folio-local-elf-provenance-v1`) medía **cinco** CLI Poppler: `pdfinfo`, `pdftotext`, `pdftoppm`, `pdfdetach` y `pdfattach`. El sexto ejecutable quedó **fuera de ese contrato**. Una observación aislada de SHA-256 de `pdfimages` no verificaba su vínculo con el resto del runtime.

**No se modificó `source_inventory.py` ni se reinterpretaron sus cinco claves**: su contenido Python está asociado por SHA-256 a la evidencia R1.40/R1.42 del candidato, por lo que cambiarlo invalidaría la comparación histórica. Tampoco se reescribió un manifiesto firmado, un archivo de snapshot ni los resultados previos de Trivy.

Se añadió `pdfimages_elf_provenance.py` bajo el contrato nuevo `folio-r151-pdfimages-elf-provenance-v1`, independiente de la v1 histórica. En la **misma raíz de imagen local inmutable** recompone y valida primero el inventario previo completo a través de `audit_image.verify_native_source_inventory`, identifica la biblioteca Poppler ya hasheada y **entonces** exige: `pdfimages` regular, modo exacto `0755`, un solo hardlink, 4 KiB–64 MiB, cabecera ELF, SHA-256, versión `25.03.0` y `ldd` sin bibliotecas prohibidas/ausentes ni ambigüedad. El enlace dinámico debe resolver a `/opt/folio-poppler/lib/libpoppler.so.147` exactamente; la symlink SONAME de CMake se permite solo si resuelve a un ELF no modificable dentro de ese prefijo y su hash coincide con el inventario anterior.

## Identidad medida de la única imagen admitida

| Evidencia | Valor |
|---|---|
| Imagen Docker local admitida | `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a` |
| Imagen y lineage | R1.48, base R1.47 source-built Poppler `25.03.0-5+deb13u4` |
| Sexto binario | `/opt/folio-poppler/bin/pdfimages` |
| SHA-256 de `pdfimages` | `e1610ede59f8e67aff468ef8c45f3fda45fde1716184530bf79e24a4e88b90ba` |
| SHA-256 de `libpoppler.so.147` | `3ca61c1d42c8a040e47f01524d0bc3d45d73bc3e7981fe79a46b9cf9cb8dfe3b` |
| SHA-256 de metadatos de fuente Poppler | `6f3a346c62da304ed1e0e9f77b65c0a65db1c7797f7163b2e2727ff333e459b1` |
| Cinco CLI previas | Digests independientes conservados en `other_poppler_tools_sha256` |
| SHA-256 del inspector legado `source_inventory.py` | `6effc14e9267f507e1d54b6fab71b2709737414eba952e812133c460de772d2c` |
| Resultado esperado de ejecución | **exit 2** = identidad local verificada, release BLOQUEADO |
| Evidencia corrupta, ausente o ambigua | **exit 3** = sin atestación, release BLOQUEADO |

La ejecución real de `bash apps/inspector/scan_pdfimages_elf_provenance_r151.sh` fue **exit 2** con JSON válido y todos los campos anteriores concordantes, `same_poppler_library_link_verified=true`, `source_cve_coverage=unassessed`, `source_to_elf_reproducible_build_attested=false` y `release_authorized=false`. Se ejecutó `docker run --pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges` con CPU/memoria/pids acotados, solo tres fuentes Python montadas readonly, comprobando ID de Docker antes y después. Sin copias de PDF ni datos del usuario, sin Docker build, sin nuevas capas ni contacto de red.

## Negativos y limitaciones

Siete pruebas TDD cubren falta de `pdfimages`, symlink, hardlink, archivo writable/no ELF, imagen/ID equivocados, inventario histórico incompleto, versión alterada, fallo CLI, `ldd` ausente, dependencia de red, doble enlace Poppler y biblioteca compartida distinta, incluyendo enlace SONAME escapado o writable. Además, `python3 -m unittest discover -s apps/inspector/tests` terminó **587/587** y una ejecución del script con argumento no admitido dio **exit 3** sin revelar rutas ni artefactos. **No se trata de una firma de compilación**, reproducibilidad de build, escaneo SBOM archivo-a-archivo, auditoría de función de parsing, análisis de todos los CVE de Poppler ni autorización de publicar. Los contadores Trivy del último cotejo R1.48 siguen **55 HIGH y 15 UNKNOWN**; R1.51 no los reduce ni los reevalúa.

### Requisitos antes de G2

La imagen candidata de release —que puede ser distinta de esta investigación R1.48— requiere **su propio digest, inventario completo de los seis binarios realmente ejecutados, SBOM, Trivy en snapshot común, verificación ELF/source-to-build y revisión individual de CVE y dependencias nativas**, sin falsos VEX ni bypass por hashes heredados. La barrera R1.50 aún tiene falsos positivos intencionales para logos y carece de cobertura OCR mixta; G4 [#134](https://github.com/DawoT/folio-civico/issues/134) permanece abierto. La rama y el PR deben pasar CI sobre el árbol exacto, además de revisión independiente conforme al carril G0 [#133](https://github.com/DawoT/folio-civico/issues/133). **No se modifica el Dockerfile operativo, ni Cloudflare, ni D1 remoto, ni Preview/producción.**
