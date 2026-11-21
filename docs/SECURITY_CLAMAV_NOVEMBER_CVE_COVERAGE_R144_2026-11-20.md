# R1.44 · ClamAV 1.5.5 y los diez CVE del boletín de noviembre

**Fecha de revisión:** 2026-11-20, America/Lima. **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Decisión:** investigación local integrable, NO RELEASE, sin VEX.

## Fuentes y superficies funcionales

El [aviso oficial Cisco PSIRT del 18-11-2026](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-multi-e93M3vdA) y la [nota oficial de ClamAV 1.5.5](https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html) identifican **diez CVE corregidos en 1.5.5**, con rangos afectados hasta 1.5.4.

| CVE | Subsistema del escáner y problema citado |
|---|---|
| CVE-2026-76411 | URL / phishcheck; longitud de canonicalización, escritura fuera de límites |
| CVE-2026-76414 | CHM; recorrido circular y DoS |
| CVE-2026-76415 | ejecutables PE / yC; lectura fuera de límites |
| CVE-2026-76416 | InstallShield; bucle de worker |
| CVE-2026-76417 | OLE2; recursión y agotamiento de pila |
| CVE-2026-76421 | CHM / LZX; escritura fuera de límites |
| CVE-2026-76422 | Rust→C logging; cadena de formato, corrupción de memoria |
| CVE-2026-76430 | PE / UPX; acceso fuera de límites |
| CVE-2026-76515 | OLE2; límites de tiempo y CPU |
| CVE-2026-76516 | XAR/GZIP; límites de extracción y espacio temporal |

El flujo real `inspector.py:inspect_pdf` ejecuta `clamscan` **antes** de `qpdf`. Por ello, que Folio Cívico acepte PDF no demuestra que los parsers CHM/PE/OLE2/XAR o archivos embebidos sean inaccesibles: ClamAV procesa el archivo recibido antes de validar la estructura PDF. Las restricciones del sandbox reducen las consecuencias, pero no reparan por sí mismas los CVE.

## Evidencia real R1.44

**Imagen exacta:** `folio-civico-inspector:expat-experiment`, Docker ID `sha256:3447fed5e20f4c7f31110403738ffba08ab6b203141cea1b2158f60ef3ed5731`.

**Ejecución:** `bash apps/inspector/scan_clamav_november_coverage_r144.sh` → **exit 2 esperado (release bloqueado)**.

- Se descargó el paquete Talos `clamav-1.5.5.linux.x86_64.deb` y su firma GPG, sin instalación; `clamav_vendor_evidence.py` verificó la firma contra la huella primaria fijada `5BADCA2665EF59DCF8A23D8B707F0DB480836771`.
- `clamav_runtime_inventory.py` se ejecutó dentro del ID exacto, no root, sin red, con FS read-only y capacidades Linux retiradas. Verificó `ClamAV 1.5.5`, paquete `1.5.5-1`, `dpkg -V clamav` limpio y vínculo `clamscan → libclamav.so.12.1.0`. **16/16 archivos nativos tienen SHA-256 idéntico a los bytes del paquete firmado**, incluyendo binarios ELF y código Rust.
- Trivy actualizó una vez su base de vulnerabilidades. El escaneo JSON y CycloneDX se hizo con `--skip-db-update` sobre esa misma imagen, con identidad y datos de paquete estrictamente validados. El inventario conserva las alertas históricas y nunca genera VEX.

| Resultado | Conteo |
|---|---:|
| CVE de julio 2026 todavía HIGH en Trivy | **7/7** |
| CVE de julio todavía MEDIUM | **6/6** |
| CVE del boletín de noviembre presentes en Trivy | **0/10** |
| CVE ClamAV visibles en Trivy | **13** |
| Imagen completa CRITICAL / HIGH / UNKNOWN | **0 / 70 / 15** |
| Total bloqueante | **85** |
| Integridad Talos y hashes nativos | **16/16, PASS** |
| Gate de investigación | **BLOCKED / exit 2** |

**Interpretación:** los diez avisos del fabricante que no aparecen en Trivy representan una **brecha de visibilidad del escáner**, no diez HIGH adicionales inventados ni diez CVE automáticamente clasificados como corregidos. Talos documenta las correcciones en 1.5.5, y la firma/hashes prueban que el runtime instalado corresponde a esos bytes oficiales. **No prueban por sí solos el parche concreto de cada función, alcanzabilidad, reproducibilidad de compilación, resistencia a exploits ni una decisión VEX aprobada.**

El validador `clamav_november_coverage_r144.py` exige el catálogo público exacto, que los siete HIGH y seis MEDIUM previos sigan visibles, identidad SBOM/ID, firma y hashes nativos. Informa cualquier aviso nuevo de noviembre que aparezca en una futura base. Incluso con evidencia idéntica, **exit 2**; información inválida/incompleta o discrepancias: **exit 3**.

## Pruebas y próximos riesgos

TDD Red→Green: `test_clamav_november_coverage_r144.py` valida catálogo, nuevas entradas, CLI exit 2/3, firma/ELF/Trivy/SBOM manipulados, cambio de ID y protección del script; **5 pruebas y 18 subtests** aprobados antes de la auditoría. Se ejecuta además la suite Python inspector y el CI integral de repositorio antes de integrar.

Permanece pendiente la revisión funcional de los diez CVE y su procedencia por commit, cobertura de Poppler/Tesseract/Expat, los 85 hallazgos bloqueantes, la calidad sobre PDFs adversariales y la rotación de firmas. La imagen R1.43 tiene capas históricas OCI y no está aprobada para distribuirse.

`trivy_release_gate_passed=false`, `clamav_cve_applicability_approved=false`, `vex_issued=false`, `release_authorized=false`.

**Issue #68 abierto. Sin OCI publicado, despliegue Cloudflare/Preview/producción, cambios D1 remotos, VEX ni documentos institucionales.**
