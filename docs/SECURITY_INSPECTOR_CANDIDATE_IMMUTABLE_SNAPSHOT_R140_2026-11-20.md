# R1.40 — Auditoría reproducible de imagen local del inspector (NO RELEASE)

**Fecha UTC de captura:** 2026-11-20 22:49:41. **Proyecto:** Folio Cívico, S03-01 / gate G2. **Objeto:** imagen **local existente** `folio-civico-inspector:ocr-integrated`; no se ha construido, instalado, publicado ni desplegado ningún contenedor en esta investigación.

## Identidad y alcance preciso

| Identidad | Valor |
| --- | --- |
| Etiqueta local de consulta | `folio-civico-inspector:ocr-integrated` |
| **ID inmutable de imagen local Docker** | `sha256:b5aadc6c3bfc60471070095c60f756552f83452989017581081e341e0b9adb8a` |
| Creada en Docker | 2026-11-20 22:39:20 UTC |
| Base OS detectada por Trivy | Debian **13.7** |
| Trivy | **v0.76.2**, DB esquema **v2** |
| Base de vulnerabilidades Trivy (UpdatedAt) | **2026-11-20 18:59:53 UTC**; descargada 2026-11-20 22:41:41 UTC; siguiente actualización indicada 2026-11-21 18:59:53 UTC |
| Modo de auditoría | `candidate` sin modificación, usando la etiqueta solo para leer y comprobando el ID inmutable después de cada fase |
| Registros originales | carpeta privada del laboratorio `/tmp/folio-r140-candidate-20261120a` (0700; todos los archivos 0600; **no incorporados al Git**) |

**Atención:** el ID `sha256:b5…` es el **ID local Docker**, no un digest OCI de manifiesto publicado en registro. No se ha creado ni verificado un digest de registry; sería incorrecto utilizar esta evidencia como autorización de despliegue por digest.

## Resultado: gate correctamente BLOQUEADO

Se ejecutaron dos comprobaciones reales e independientes:

1. `bash apps/inspector/audit_image.sh --candidate --advisories` → **exit 2** esperado. El script existente ejecuta Trivy, CycloneDX, inventario nativo no privilegiado y el gate `audit_image.py`.
2. `python3 apps/inspector/snapshot_candidate_image.py --output-dir /tmp/folio-r140-candidate-20261120a` → **exit 2** esperado; conservó los cuatro reportes originales y el manifiesto final fijando SHA-256. El análisis de cada reporte se realizó con las funciones ya existentes `evaluate_image_audit()` y `targeted_advisories()`, sin supresión de findings. Una verificación offline posterior releyó y rehasheó todos los reportes y comparó el resultado re-evaluado: **exit 2**, `independently_verified_research_release_blocked`.

| Métrica real en la imagen indicada | Conteo |
| --- | ---: |
| Componentes inventariados en SBOM | **166** |
| Findings totales (incluidos MEDIUM y LOW) | **535** |
| CRITICAL | **0** |
| HIGH | **128** |
| UNKNOWN | **15** |
| MEDIUM | 189 |
| LOW | 203 |
| **Findings bloqueantes (HIGH + CRITICAL + UNKNOWN)** | **143** |
| Componentes nativos construidos desde fuente sin cobertura CVE acreditada | **1** (Tesseract 5.5.4) |
| Estado oficial del gate | **`blocked`** |

El inventario muestra además **13 findings bloqueantes** seleccionados por el diagnóstico específico (ClamAV 7 HIGH, `libexpat1` 6 HIGH/UNKNOWN); los restantes siguen bloqueando igualmente. No se deben sumar los findings de informes auxiliares como si fueran CVE adicionales.

La distribución es a nivel de paquete binario y no de CVE único: Trivy emite los cuatro `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409` y `CVE-2026-78410` contra **nueve paquetes relacionados con util-linux** por CVE (36 registros), todos HIGH. La lista oficial de Debian para Trixie continúa vulnerable para los cuatro CVE; upstream/Red Hat consideran el CVE-2026-78409 no aplicable a la rama 2.41, discrepancia que **no se traduce en un waiver local**.

**Importante:** la imagen auditada **todavía contiene la versión Debian sin parche** `util-linux`, `libmount1`, `libuuid1`, `libblkid1` **`2.41.5-0+deb13u1`**. No contiene los binarios experimentales reproducibles `2.41.6-0+folio2~deb13u1` de R1.37. Los escaneos de esta imagen no acreditan el estado de los paquetes `folio2` y los binarios `folio2` no acreditan la seguridad de la imagen. **No existe un vínculo de release aprobado entre ambos.**

## Evidencia privada y hashes verificables

La captura usa etiqueta sólo como selector de lectura; verifica el mismo ID Docker inicial tras cada Trivy scan, tras la inspección nativa, tras el gate y al finalizar. El inventario nativo se ejecuta **por ID inmutable**, en contenedor `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`, sin volúmenes del host y con límites de memoria/procesos. Trivy usa la base actual disponible sin `--ignore-unfixed`, `--skip-db-update` ni supresiones.

| Archivo de evidencia bajo `/tmp/folio-r140-candidate-20261120a/` | SHA-256 |
| --- | --- |
| `trivy-vulnerabilities.json` | `4071a7affc923e7605e2e488cd902ebaa8aa8f2424b26e894c8489e15bed12b0` |
| `trivy-cyclonedx.json` | `f0e1837d7246e696cae1d53e4e015e544e18adbfec58f527f6346baa41541836` |
| `native-source-inventory.json` | `52cc43773dfc59e818f76520b390729293ff23bde53b4281093adca8483ea36f` |
| `advisories.json` | `6227da6c8833f1288ab8f433d57665458c16b69b60d38e26809b435dcd9f52e3` |
| `SNAPSHOT_RESEARCH_ONLY.json` | `4f4e42a6a8ea15aec6aff3599f208259cee1f41d0c46b32ec9f5f8ab975f27a2` |

Verificación independiente, sin Docker ni red:

```bash
python3 apps/inspector/snapshot_candidate_image.py \
  --output-dir /tmp/folio-r140-candidate-20261120a --verify-only
# Exit 2: bloqueado; 143 findings bloqueantes;
# 5 hashes comprobados y gate/advisory recalculado con resultados idénticos
```

El verificador rechaza cualquier alteración de JSON, SHA, versión de inspector de fuentes, contenido extra, archivo o directorio no privado, tag mutado durante escaneo, imagen sin ID SHA-256, reporte Trivy incompleto o discrepancia entre gate y advisories. El expediente privado es sólo **evidencia de investigación**, no una firma ni attestation distribuible. Una captura abortada mantiene `UNVERIFIED_INCOMPLETE.txt` en vez de crear una aprobación aparente.

## Implicaciones y siguiente puerta de trabajo

Las prioridades de remediación de esta **imagen exacta** son: **(1)** eliminar/actualizar rutas de dependencia realmente prescindibles con comprobación de ldd y tests de PDF/OCR/AV, **(2)** revisar el paquete ClamAV firmado por Cisco Talos y sus advisories individualmente, **(3)** inspeccionar el árbol de dependencias Kerberos/GSSAPI por necesidad real, **(4)** resolver `libexpat1` y **(5)** acreditar cobertura CVE del Tesseract compilado desde fuente. No se debe asumir que actualizar `util-linux` eliminará los **143** bloqueos. Cualquier nueva imagen exige nuevo escaneo exacto, inventario, pruebas funcionales reales y autorización explícita de seguridad.

**G2 permanece `blocked_runtime_release`**. Sin VEX, waiver, eliminación de findings, instalación de `.deb`, build/push/deploy de imagen, secretos, documentos reales o cambios en Cloudflare.

## Referencias oficiales consultadas

- [Debian: estado actual de util-linux en Trixie](https://security-tracker.debian.org/tracker/source-package/util-linux).
- [Debian: CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) y [aviso upstream GHSA-8f2p-47x3-43mv](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv).
- Dossier R1.39: `docs/SECURITY_UTIL_LINUX_CVE_78409_APPLICABILITY_R139_2026-11-20.md`; ticket de seguridad [S03-01 / G2](https://github.com/DawoT/folio-civico/issues/75).
