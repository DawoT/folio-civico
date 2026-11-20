# R1.41 · Tesseract 5.5.4: trazabilidad de 14 CVE a los parches upstream (NO RELEASE)

**Fecha:** 2026-11-20. **Seguimiento:** S03-01 / G2, [issue #75](https://github.com/DawoT/folio-civico/issues/75). **Alcance:** examen de la fuente upstream de Tesseract usada en el `Dockerfile` del inspector. No se ha reconstruido ni sustituido ninguna imagen.

## Hallazgo principal: 10 de 14 con postimagen completa y 4 aún sin acreditar

El inspector actual contiene un Tesseract 5.5.4 compilado desde fuente en la etapa `ocr_builder`. El `Dockerfile` fija la suma SHA-256 del tarball `tesseract_5.5.4.orig.tar.gz` en `a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4`. **No instala** el paquete binario `tesseract 5.5.4-1` de Debian unstable.

El tracker Debian lista **14 CVE del paquete fuente `tesseract`**: Trixie (`5.5.0-1`) aparece vulnerable, y forky/sid (`5.5.4-1`) aparecen corregidas. Las descripciones y commits upstream de cada CVE están enlazados desde el [tracker Debian](https://security-tracker.debian.org/tracker/source-package/tesseract). Esta clasificación de paquetes **no certifica por sí sola** el ELF compilado manualmente por Folio Cívico.

Se creó `apps/inspector/tesseract_554_source_patch_probe.py`, un comparador fail-closed que:

1. Comprueba que los **14 CVE** coinciden exactamente con el inventario preexistente de `native_advisory_ledger.py`; ninguna entrada se descarta para simplificar el resultado.
2. En un contenedor Docker efímero de Python **sin privilegios** (UID/GID 65534, `--cap-drop ALL`, `--read-only`, límites de CPU, memoria y procesos, **sin volúmenes del host**), descarga solamente el tarball oficial vía HTTPS y los parches `.patch` de **14 commits completos de upstream**, por sus URL fijas. La red se usa **solo para adquirir evidencia**, no para escanear PDFs ni para modificar la imagen del inspector.
3. Rechaza el tarball si su SHA-256 no coincide con el del `Dockerfile`, y cada patch si su SHA-256 no coincide con la suma registrada durante la revisión. Los archivos fuente se leen directamente del `tar.gz` sin extraer rutas en el filesystem del host.
4. Busca exactamente la **postimagen de cada hunk de código fuente** (líneas de contexto y adiciones de la versión corregida) dentro de los archivos reales del tarball fijado. No confunde modificaciones en tests/Makefiles con guardas de `src/`. Un cambio posterior de contexto se clasifica como **parcial/no resuelto**, no como falta probada de corrección. Los hunks que **solo eliminan código** se contabilizan expresamente como **no resueltos**: no se omiten para producir un falso resultado positivo.
5. Emite un expediente privado con la identidad de 14 commits, SHA de cada patch y estado de cada comparación. Un verificador **sin Docker ni red** recalcula recuentos, pertenencia al inventario, hashes fijados, estado bloqueado, identidad del verificador y rechaza un resultado inflado o una autorización de release falsificada.

### Resultado real del laboratorio

| Categoría | Resultado |
| --- | ---: |
| Archivo `tesseract_5.5.4.orig.tar.gz` admitido por SHA-256 | Sí |
| CVE revisados con commits y parches específicos fijados | **14/14** |
| Hunks de código `src/` contrastados | **61** |
| Hunks cuya postimagen se encuentra exactamente en la fuente | **49/61** |
| CVE cuyos **todos** los hunks de código coinciden | **10/14** |
| CVE con uno o más hunks no coincidentes | **4/14** |
| Explotaciones ejecutadas contra el motor o modelos maliciosos | **0** |
| Componentes nativos declarados seguros por el gate | **0** |

| CVE pendiente de evidencia adicional | Hunks coincidentes | Archivos afectados por discrepancia |
| --- | ---: | --- |
| `CVE-2026-119341` | 1/3 | `src/classify/adaptive.cpp` (hunks de eliminación sin postimagen comprobable) |
| `CVE-2026-73067` | 1/2 | `src/dict/dawg.cpp` |
| `CVE-2026-88052` | 1/2 | `src/ccutil/unicharset.cpp` |
| `CVE-2026-88053` | 18/26 | `src/classify/adaptive.cpp`, `adaptive.h`, `adaptmatch.cpp`, `classify.h` |

Para los otros **10 CVE**, todas las postimágenes de los parches revisados coinciden exactamente con el tarball. **Esto es evidencia fuerte de incorporación de cambios fuente seleccionados, pero no un certificado de remediación CVE:** faltan el vínculo reproducible fuente→ELF del candidato, pruebas semánticas de parsers/modelos hostiles y revisión de posibles rutas alternativas. Para los cuatro casos parciales, es necesaria una inspección de las diferencias con commits posteriores de upstream; **no se afirma que sean vulnerables ni que estén corregidos**.

### Reproducibilidad y confidencialidad

La ejecución real de la nueva herramienta devolvió `exit 2` (evidencia válida, **release bloqueado**) y conservó el JSON original **fuera de Git**:

| Identidad | Valor |
| --- | --- |
| Archivo privado (0600) | `/tmp/folio-r141-tesseract-20261120e.json` |
| SHA-256 del expediente | `3ae4679b26c8c21a16176abdaa4769797795451b922b8b83ca270237197821a2` |
| SHA-256 de fuente upstream | `a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4` |
| ID local del contenedor de adquisición de pruebas | `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` |
| SHA-256 del verificador R1.41 | `7b6e863b3a2a1cec929b528dbde80a7824a70e462e9935b6d970a7b13e2512b5` |
| Estado | `security_gate=blocked`, `release_authorized=false`, `vex=not_issued` |

```bash
# Obtención de evidencia fuente: solo lectura, Docker local con red HTTPS,
# sin bind mounts ni modificaciones del inspector; exit 2.
python3 apps/inspector/tesseract_554_source_patch_probe.py \
  --output /tmp/folio-r141-tesseract-nueva.json

# Reevaluación sin contenedor ni red: exit 2 mientras G2 esté bloqueado.
python3 apps/inspector/tesseract_554_source_patch_probe.py \
  --verify-only /tmp/folio-r141-tesseract-20261120e.json
```

La herramienta no instala `.deb`, no reconstruye ni publica imágenes, no ejecuta payloads CVE, no procesa PDFs institucionales y no emite VEX/waiver. Los commits y los hashes de patch están en código para que los resultados negativos no puedan omitirse sin cambios revisables.

## Priorización paralela del runtime

**ClamAV.** La imagen contiene **ClamAV 1.5.5** firmado por Cisco Talos según el pipeline actual. Los **siete CVE** seleccionados por Trivy (CVE-2026-20213..20217 y CVE-2026-20243..20244) están asociados a la [corrección oficial 1.5.3 de julio de 2026](https://blog.clamav.net/2026/07/clamav-153-and-145-security-patch.html); Cisco publicó además [ClamAV 1.5.5 el 18 de noviembre de 2026](https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html), corrigiendo **otros diez CVE**. Por tanto, el inventario Trivy Debian sobre ese `.deb` firmado no es suficiente por sí solo para evaluar qué correcciones vendor están incorporadas: hace falta cotejo binario/procedencia/advisory específico. **No se suprimió ningún CVE ni se cambió el gate.**

**Expat.** La imagen conserva `libexpat1 2.9.0-1~deb13u1`; [Debian registra aún vulnerabilidades en Trixie](https://security-tracker.debian.org/tracker/source-package/expat), incluida denegación de servicio y comprobaciones de límites. No se debe sustituir automáticamente por una versión de Debian sid/unstable ni afirmar que está corregida sin nueva imagen y auditoría.

**Kerberos/GSSAPI.** La imagen auditada en R1.40 contenía **56 findings bloqueantes** repartidos entre `libgssapi-krb5-2`, `libk5crypto3`, `libkrb5-3` y `libkrb5support0` (14 por paquete). Este trabajo no altera esas dependencias: existe una investigación concurrente `security/kerberos-poppler-prune-r141`, que debe verificarse por separado antes de atribuir resultados. No se debe sumar una reducción hipotética al recuento real de 143.

## Cierre de alcance

La imagen local R1.40 sigue identificada por el ID Docker `sha256:b5aadc6c3bfc60471070095c60f756552f83452989017581081e341e0b9adb8a`, con **143 findings bloqueantes**, 1 motor nativo sin cobertura CVE acreditada y sin digest de registro autorizado. **Este trabajo no modifica ese resultado.**

Las comprobaciones de R1.41 reducen la incertidumbre sobre procedencia de parches upstream de Tesseract; **no levantan G2, no convierten ninguno de los 14 CVE en `not_affected` ni en `fixed` dentro del ledger, no autorizan una imagen para producción y no justifican un VEX.**

Próximo control: revisar semánticamente los doce hunks no coincidentes, atestar el vínculo de fuentes a ELF realmente compilado y repetir Trivy, CycloneDX, smoke OCR/PDF/AV y gate sobre una **nueva imagen candidata identificada por digest exacto**, sujeto a aprobación humana para cualquier riesgo residual.
