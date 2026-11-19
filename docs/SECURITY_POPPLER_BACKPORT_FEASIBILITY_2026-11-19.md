# R1.12 · Viabilidad textual de siete parches CVE Poppler Debian

**Corte:** 2026-11-19 (America/Lima). **Estado:** evaluación offline de compatibilidad de texto, **no un backport ni remediación**. Ninguna imagen fue reconstruida, etiquetada, liberada o desplegada.

## Pregunta de seguridad

¿Los parches identificados por Debian en Poppler `26.07.0-4` pueden aplicarse, sin alterar su contenido, al código Debian Trixie `25.03.0-5+deb13u4` fijado en R1.11? Esto **no** evalúa si el parche es semánticamente correcto para esa versión ni si existe una reproducción explotable del CVE en el binario exacto.

Se descargaron y verificaron de forma independiente los tres artefactos fuente R1.11 (SHA-256 de `.dsc`, `.orig.tar.xz` y `.debian.tar.xz`). El verificador de R1.11 confirmó `dpkg-source -x`, los nueve parches Debian ya presentes y las seis huellas de código fuente. Se obtuvieron por separado **siete parches** del [árbol oficial Debian Poppler 26.07.0-4](https://sources.debian.org/patches/poppler/26.07.0-4/); sus bytes se fijaron por SHA-256 en `poppler_backport_feasibility.py`.

## Resultado real de patch --dry-run

Se examinó **cada parche por separado** contra **el mismo árbol Trixie sin modificar**, con `patch --dry-run --batch --forward --fuzz=0 -p1`. Los offsets de línea del parche no son equivalentes a cambios semánticos.

| CVE | SHA-256 del parche Debian 26.07.0-4 | Resultado | Observación |
| --- | --- | --- | --- |
| CVE-2026-102620 | `cfff904cfed96fb47975fb236eba0f4940bc1aaa2bb2cc5a78b32782c8653f34` | **aplicable textualmente**, exit 0 | `fofi/FoFiTrueType.cc`, offset +31 |
| CVE-2026-102621 | `8d33455999b9d49906c9e109accab4a1bcda6ec6215f3db2b36f4c7d4d6d9b41` | **revisión manual**, exit 1 | `splash/SplashClip.cc`, 2/2 hunks fallidos |
| CVE-2026-93311 | `43c10135f98931c28def154de201fecd4e51c57f2b349fe0a4807415d0f7524a` | **aplicable textualmente**, exit 0 | `poppler/Function.cc`, offset −3 |
| CVE-2026-93312 | `0bc3ce062218e3d111cfbed5b475a7e9fa6b352a03f7ace667db515534b76299` | **revisión manual**, exit 1 | `poppler/JBIG2Stream.cc`, 1/1 hunk fallido |
| CVE-2026-93313 | `2a6d8fb05bb1c49cfa287f849db15260a8f582275a4618a30b3f8ef26471ae88` | **revisión manual**, exit 1 | `poppler/JBIG2Stream.cc`, 1/1 hunk fallido |
| CVE-2026-93314 | `f317b24cbe18193903093a03c5308fe873f04f8cce3cddac8351799cabf4c3a4` | **revisión manual**, exit 1 | `fofi/FoFiTrueType.cc`, 1/2 hunks fallidos |
| CVE-2026-107705 | `6cdbfa5e7611ac5870de95275f8dd72a2e72d6225087566d8dbd159a6bafe68e` | **revisión manual**, exit 1 | `poppler/Decrypt.cc`, 8/12 hunks fallidos |

**Total: dos aplicables textualmente y cinco con cambios que requieren backport manual.** No se ejecutaron patches reales, no se compilaron binarios parcheados y no se probó su comportamiento funcional ni de seguridad. Los tres CVE seleccionados restantes (`CVE-2026-93653`, `CVE-2019-9545`, `CVE-2019-9543`) **carecen de parche en este conjunto de siete**: no se clasifican como corregidos, no afectados ni mitigados.

Los siete parches son de **otra versión base** de Debian. Que hayan sido publicados en `26.07.0-4` no convierte toda la versión posterior en un candidato automático de producción, y la existencia de una ruta `patch` no autoriza copiar archivos sin revisión.

## Verificador incorporado

`apps/inspector/poppler_backport_feasibility.py` es estrictamente **offline** y recibe dos directorios:

- `--source-directory`: exactamente los tres artefactos fuente Debian fijados por R1.11.
- `--fix-directory`: los siete archivos `CVE-xxxx-xxxxx.patch` descargados de [Debian Sources](https://sources.debian.org/data/main/p/poppler/26.07.0-4/debian/patches/).

El probe verifica los hashes de **todos** los archivos; el mapeo CVE → fichero fuente; los headers de diff (aceptando backports Debian sin `diff --git`); y verifica de nuevo la identidad de los seis archivos fuente antes y después de cada `--dry-run`. Todos los controles operan en un temporal privado y el probe no abre PDFs ni ejecuta red. Un error de hash, extracción, herramienta, ruta, modificación del árbol o resultado contradictorio devuelve **exit 3**, no un resultado favorable.

El proceso con resultados válidos devuelve **exit 0** aunque cinco parches requieran revisión: el cero significa únicamente **informe de investigación completado**. Su JSON tiene siempre `selected_cve_fixes_verified=false`, `binary_equivalence_verified=false`, `backport_approved=false`, `complete_source_advisory_coverage=false`, `release_authorized=false`. No modifica la lógica de `audit_image.py` ni las excepciones CVE.

### Reproducción

```sh
# Obtener los 3 artefactos de Debian identificados en R1.11 (y verificar sus SHA-256).
# Descargar los 7 parches del índice Debian 26.07.0-4, sin editar sus bytes.
python3 apps/inspector/poppler_backport_feasibility.py \
  --source-directory /ruta/artefactos-fijados \
  --fix-directory /ruta/7-parches-debian

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_backport_feasibility.py' -v

sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories  # exit 2 esperado
```

## Siguiente trabajo y puertas de decisión

1. **Backports:** revisar semánticamente primero los dos candidatos de aplicación limpia y preparar los cinco que fallan, mediante ramas o builders de investigación aislados, con pruebas negativas y sanitizadores pertinentes. Los casos JBIG2/Splash/Decrypt requieren atención especial. La salida de `patch` por sí sola no acredita una corrección.
2. **Cobertura incompleta:** `CVE-2026-93653` continúa vulnerable para Debian Trixie y no queda cubierto por el parche previo de `CVE-2026-10118`; investigar solución específica. Revisar los dos CVE históricos JBIG2 y el inventario completo de avisos nuevos. Estado `no-dsa/ignored` no es `not_affected`.
3. **Release:** aún pendientes equivalencia ELF, trazabilidad de cada corrección, corpus realista sintético/adversario, Expat, ClamAV y demás 70 HIGH / 19 UNKNOWN. Mantener gate de imágenes `exit 2`, sin VEX, cambios Cloudflare, Preview, producción, D1 remoto ni datos institucionales. Véase [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md).

**Alcance del incremento:** utilidades offline, pruebas y documentación integrables en `main`. Nada de esto modifica la imagen Poppler ni autoriza su liberación.
