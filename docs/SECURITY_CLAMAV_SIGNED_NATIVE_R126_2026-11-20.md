# R1.26 · ClamAV: paquete firmado y equivalencia de código nativo

**Fecha:** 2026-11-20 UTC. **Rama:** security/clamav-provenance-r126, derivada de security/expat-regression-r125. **Estado:** investigación local, NO RELEASE, NO VEX, sin despliegue.

## Hallazgo

Trivy atribuye a clamav 1.5.5-1 **7 HIGH + 6 MEDIUM**, sin FixedVersion. El fabricante documenta las correcciones de los siete HIGH en **ClamAV 1.5.3**; cinco MEDIUM en **1.5.4** y un MEDIUM en **1.5.2**. Esto justifica una investigación de la clasificación del escáner, pero **no permite suprimir CVE ni emitir VEX automáticamente**.

| Severidad | CVE | Versión corregida según fabricante |
| --- | --- | --- |
| HIGH, 7 | CVE-2026-20213, 20214, 20215, 20216, 20217, 20243, 20244 | 1.5.3 |
| MEDIUM, 5 | CVE-2026-20339, 20345, 20346, 20347, 20348 | 1.5.4 |
| MEDIUM, 1 | CVE-2026-20031 | 1.5.2 |

Fuentes primarias:
- [ClamAV 1.5.3, julio 2026](https://blog.clamav.net/2026/07/clamav-153-and-145-security-patch.html)
- [ClamAV 1.5.4, agosto 2026](https://blog.clamav.net/2026/08/clamav-154-and-146-security-patch.html)
- [ClamAV 1.5.2, marzo 2026](https://blog.clamav.net/2026/03/clamav-152-and-144-security-patch.html)
- [ClamAV 1.5.5, noviembre 2026](https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html)
- [ClamAV: verificación GPG de paquetes oficiales](https://docs.clamav.net/manual/Installing.html)

## Operación de auditoría

Se implementaron tres módulos nuevos: apps/inspector/clamav_vendor_evidence.py, apps/inspector/clamav_runtime_inventory.py y apps/inspector/clamav_signed_gate.py; un script apps/inspector/scan_clamav_signed_vendor.sh; y cinco pruebas TDD en apps/inspector/tests/test_clamav_signed_vendor.py.

1. El verificador **descarga solamente material público** del release oficial 1.5.5 x86_64: paquete .deb, firma detached .sig y clave Talos. Utiliza HTTPS y un directorio temporal; no guarda ni instala los archivos del fabricante.
2. GPG valida GOODSIG y VALIDSIG y exige la huella primaria independiente y fijada: **5BADCA2665EF59DCF8A23D8B707F0DB480836771**. Se comprueba también Package=clamav, Version=1.5.5-1, Architecture=amd64. La firma es válida para el .deb descargado, **no** para la imagen OCI final.
3. La extracción es **solo lectura** mediante dpkg-deb --fsys-tarfile, sin escribir entradas TAR al disco. El hash SHA-256 del archivo .deb completo es **fff17fb1f8917d1ea1308c9736dabe376077458aba000a5dadcce7193a8c538c**. El contenido del paquete se recorre y se hashean los ELF regulares y bibliotecas estáticas .a pertenecientes a /usr/local/bin, /usr/local/sbin y /usr/local/lib.
4. Se compara con los hashes calculados **dentro de la imagen inmutable**, con --network none, --read-only, --cap-drop ALL, UID 65534 y no-new-privileges. La imagen de origen no se modifica. Se comprueba dpkg -V clamav con salida vacía, clamscan --version y el enlace efectivo a libclamav.so.12.1.0.
5. El comparador exige **igualdad exacta de rutas y SHA-256** y la persistencia de los **13 registros de CVE** para ClamAV, reconciliando Trivy JSON, CycloneDX, versión y digest de imagen. Evidencia alterada produce exit 3; evidencia íntegra produce **exit 2 / blocked**. Sin suppressions, VEX, waiver o aprobación.

## Resultado verificado

| Métrica | Resultado |
| --- | --- |
| Firma detached Cisco Talos | Verificada |
| SHA-256 del .deb firmado | fff17fb1f8917d1ea1308c9736dabe376077458aba000a5dadcce7193a8c538c |
| Archivos de código compilado coincidentes con el .deb | **16 / 16** |
| Incluye | clamscan, clamd, libclamav.so.12.1.0, libclamav_rust.a |
| Integridad del paquete instalado | dpkg -V clamav exit 0 |
| ID local de imagen | sha256:e79cf1ad4dc960cf892d1bb267297f3ce8563abf4ee7749753aa4e8338626d4e |
| Trivy total | **0 CRITICAL, 59 HIGH, 19 UNKNOWN** |
| ClamAV | **7 HIGH, 6 MEDIUM** |
| Release | **No autorizado; exit 2** |

En la primera ejecución real el comparador devolvió **exit 3** por los **seis MEDIUM** que no estaban en el contrato inicial. Se amplió el conjunto de CVE exigidos, se repitieron las pruebas TDD y la auditoría completa pasó con **exit 2** previsto, sin eliminar ningún hallazgo.

## Alcance y límites

La firma garantiza que los 16 artefactos de código nativo medidos coinciden con los distribuidos en el .deb firmado por Talos. No demuestra por sí misma que todas las rutas asociadas a los 13 CVE sean inalcanzables, ni constituye evaluación de explotación por CVE. La verificación dpkg cubre además el manifiesto instalado, pero esto no equivale a una atestación de la imagen OCI completa, un SBOM de todas las cadenas de compilación o reconstrucción reproducible. Los CVE de util-linux, Expat, Poppler y Tesseract siguen pendientes. No se han ejecutado pruebas con documentos institucionales ni alterado recursos remotos.

**Reproducción:** ejecutar python3 -m unittest discover -s apps/inspector/tests -p test_clamav_signed_vendor.py -v, luego bash apps/inspector/scan_clamav_signed_vendor.sh (exit 2 previsto) y sh scripts/ci.sh.
