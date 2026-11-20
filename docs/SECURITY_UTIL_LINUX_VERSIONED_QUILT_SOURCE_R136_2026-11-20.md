# R1.36 — Paquete fuente Debian Trixie versionado, con parche `quilt` integrado (NO RELEASE)

**Fecha:** 2026-11-20. **Base:** `main` 6a311923 (PR #88/R1.35; CI posterior al merge aprobada). **Alcance:** fuente experimental sin firma, sin build binario nuevo, sin instalación, sin VEX ni autorización de release.

## Decisión

R1.35 reconstruyó 43 paquetes Debian reproducibles con `util-linux 2.41.6`, pero aplicó un parche adicional **fuera del descriptor fuente `.dsc`**. Ese desacoplamiento impedía atribuir los binarios a un único paquete fuente Debian.

R1.36 introduce `apps/inspector/util_linux_versioned_quilt_source.py`, que genera un paquete fuente **nuevo, versionado y separado**, desde los tres archivos verificados y fijados por SHA-256 de R1.34. Se conserva íntegro el tarball upstream autenticado y los diez parches quilt anteriores; se incorpora `upstream/folio-r136-openat2-header.patch` como parche número **11**. No reemplaza ni modifica los artefactos fuente de R1.34.

- Versión previa: `2.41.6-0+folio1~deb13u1`.
- Nueva versión local: `2.41.6-0+folio2~deb13u1`, confirmada como mayor con `dpkg --compare-versions`.
- Formato: Debian `3.0 (quilt)`, `UNRELEASED`; `.dsc` **SIN FIRMA**. El descriptor original Debian se verificó criptográficamente en R1.33/R1.34, pero esto no convierte el derivado en un paquete firmado por Debian.
- Parche adicional SHA-256: `cf8166e6d0cc5472bf7e78753f81e7c6b68f43a5784668c1a748baed4508a179`.
- Archivo `libmount/src/hook_idmap.c` antes de R1.36: `f6fc59c0ffa7e4d1a9adfc2b0811e64e9c146dc7f625297031fa9666523ab374`; después: `e12678246515279507185598710821dc23387b08b84b4eeb9b4977e733e391c1`.
- `sys-utils/nsenter.c` conserva el SHA-256 posterior al backport verificado R1.33 y las comprobaciones semánticas de CVE-2026-78408.

## Controles de generación

El procedimiento es offline, no-root y sin Docker, apt, instalación ni publicación. Solo admite el handoff privado R1.34 mediante `validate_handoff`, que comprueba los **tres hashes fuente fijos** y estado de seguridad bloqueado. Rechaza destinos preexistentes, rutas relativas, rutas con symlinks y destinos superpuestos. Trabaja en un directorio efímero privado y exporta exclusivamente `.orig.tar.xz`, `.debian.tar.xz`, `.dsc` y `UNSIGNED_VERSIONED_SOURCE_ONLY.json` con permisos `0700/0600`.

El paquete fuente inicial se extrae mediante `dpkg-source --no-check -x` **solo después** de verificar la identidad y hashes de R1.34. Antes de aplicar el parche adicional, exige la serie anterior exacta, el hash de `nsenter.c` y el hash no modificado de `hook_idmap.c`. Un `git apply --check` comprueba la aplicación únicamente hacia delante, seguido de `dpkg-source --before-build`. Una nueva extracción de `.dsc` verifica por separado la serie de once parches, changelog, hashes fuente, semántica CVE y la identidad y los hashes de los archivos declarados en `Checksums-Sha256`. No se generan binarios.

## Ejecución real local

Se ejecutó dos veces el siguiente flujo sobre un handoff R1.34 previamente autenticado y privado:

```bash
python3 apps/inspector/util_linux_versioned_quilt_source.py \
  --source-dir /ruta/privada/r134 \
  --output-dir /ruta/privada/nueva-r136
```

Ambas ejecuciones devolvieron **exit 2 deliberado** (fuente validada, release bloqueado); ninguna produjo `.deb`, ni alteró la fuente original. Las copias `*.tar.xz`, el `.dsc` y el manifiesto privado presentan hashes **idénticos en ambas ejecuciones**:

| Artefacto | SHA-256 |
| --- | --- |
| `util-linux_2.41.6.orig.tar.xz` | `e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed` |
| `util-linux_2.41.6-0+folio2~deb13u1.debian.tar.xz` | `204326e759e7b81b03b23eae8b43a65567512eccaf862dcf2426212c05145288` |
| `util-linux_2.41.6-0+folio2~deb13u1.dsc` | `a0301270ca8ca6f9000bf48097f0b51a29aa07b9d7dc0182f486f59fe85439b6` |
| `UNSIGNED_VERSIONED_SOURCE_ONLY.json` | `df73d8bf958fb9feeefe859112cdeccc7e20102c47fc5cd55bbe0fdf0514561a` |

La protección del directorio de evidencia se comprobó de forma efectiva: `0700` para las carpetas y `0600` para sus archivos. **No se incluye ese material en el repositorio ni se publica como paquete o release**.

Pruebas nuevas: 13 casos TDD sobre versión, orden de series, procedencia del parche, controles de destino, alteración de fuente/metadata, fallo cerrado y ausencia de publicación. Suite completa del inspector sobre esta rama: **377/377** pruebas Python aprobadas; `py_compile` también pasó.

## Restricciones y siguientes gates

- **Fuente firmada:** la firma OpenPGP original es de los insumos externos previamente validados; el `.dsc` local `folio2` no tiene firma de mantenedor Debian y **no es un artefacto oficial**.
- **Build binario para `folio2`: pendiente.** Los 43 `.deb` reproducibles de R1.35 fueron generados con un parche adicional externo al descriptor `folio1`; no deben reutilizarse como binarios oficialmente derivados de este `.dsc` nuevo.
- **ABI:** pendientes comparación de símbolos/compatibilidad y pruebas de librerías en consumidores Debian Trixie, no solo las comprobaciones SONAME estáticas de R1.35.
- **CVE:** los hallazgos del Security Tracker en Trixie no quedan cerrados por una compilación local. Requiere regresiones específicas de CVE-2026-76642, CVE-2026-78408, CVE-2026-78409 y CVE-2026-78410 y una nueva evidencia de imagen.
- **Runtime:** pendientes nueva imagen aislada, SBOM CycloneDX y Trivy sobre su digest exacto, PDF/OCR/AV/HTTP reales y autorización independiente.

**Security gate: BLOCKED. `release_authorized=false`; `cve_remediated=false`; `vex=not_issued`. Ningún deploy ni cambio de imagen productiva.**
