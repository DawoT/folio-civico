# R1.39 — Aplicabilidad real de CVE-2026-78409 en util-linux 2.41.6 (`folio2`)

**Fecha:** 2026-11-20. **Base:** R1.38 / PR #101; versión fuente `util-linux 2.41.6-0+folio2~deb13u1`. **Decisión:** no realizar un backport de 2.42 al árbol 2.41.6 sin necesidad probada; corregir primero el falso positivo del verificador.

## Corrección de una conclusión de R1.38

R1.38 describió la falta de `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH` en `libmount/src/hook_subdir.c` como falta de remediación de **CVE-2026-78409**. Esa conclusión confundió **ausencia de la guarda de una ruta introducida posteriormente** con **presencia de la ruta vulnerable**.

Fuentes oficiales consultadas:

- [GHSA-8f2p-47x3-43mv — aviso upstream de util-linux](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv): afectadas las versiones **2.42 a 2.42.2**; el fallo se refiere al fast path **detached-tree X-mount.subdir** agregado a `hook_mount.c`, que usa `api->subdir` con `open_tree(... AT_SYMLINK_NOFOLLOW ...)`. Lista 2.41.6 entre las versiones de referencia reparadas pese a que la ruta original no estaba presente en 2.41.
- [Red Hat — CVE-2026-78409](https://access.redhat.com/security/cve/cve-2026-78409): afirma expresamente que las versiones anteriores a 2.42, incluidas **2.40 y 2.41, no están afectadas**; el fast path fue introducido por `ae19f7546ccb` el 15 de abril de 2025 y publicado por primera vez en **2.42**. La explotación SUID restringida requiere Linux 6.15 o posterior.
- [Commit upstream de la corrección `ed072cf2297b68f86af8e08209907f605dd42e5d`](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/ed072cf2297b68f86af8e08209907f605dd42e5d%5E!/): parchea **`hook_mount.c` con `api->subdir`** y normaliza la ruta en `hook_subdir.c`; no coincide con la ruta de ejecución histórica exclusiva para root de la rama 2.41.6.
- [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-78409): **sigue marcando Trixie 2.41.5-0+deb13u1 como vulnerable**. Existe por tanto **discrepancia de clasificación entre upstream/Red Hat y Debian**. Esta investigación no modifica ni resuelve el estado oficial de Debian.

## Inspección de la ruta real en el paquete fuente fijado por SHA-256

Se aplicó el verificador R1.39 sobre las dos copias privadas verificadas de la fuente `folio2` de R1.36, validadas mediante tres hashes SHA-256 de los archivos `.orig.tar.xz`, `.debian.tar.xz` y `.dsc` antes de `dpkg-source -x`. El código fuente **no se cambió**.

El alcance de ejecución queda delimitado por estos hechos simultáneos:

1. `libmount/src/context.c`: `mnt_context_target_fd_required(cxt)` **devuelve `mnt_context_is_restricted(cxt)`**.
2. `libmount/src/hook_subdir.c`: `hook_prepare_target()` registra `hook_mount_pre()` para la etapa `MNT_STAGE_MOUNT_PRE`.
3. `hook_mount_pre()` contiene `if (mnt_context_target_fd_required(cxt)) return -ENOTSUP` **antes de `tmptgt_unshare(hsd)`** y antes de registrar la etapa `MNT_STAGE_MOUNT_POST`.
4. `hook_mount_post()` es el único llamador de `do_mount_subdir()` en esa fuente; el paso posterior sólo se registra después de superar el rechazo temprano del usuario restringido.
5. `hook_mount.c` **no contiene `api->subdir` ni otra ruta de fast path detached `X-mount.subdir`** introducida en 2.42.

Así, la llamada heredada `open_tree(api->fd_tree, subdir, ...)` existente en `hook_subdir.c` **no es, por sí sola, evidencia de la misma vulnerabilidad**: queda situada en el flujo temporal de namespace que rechaza a usuarios restringidos. Esto **no acredita que todos los escenarios de montaje con privilegios estén auditados**, sólo acota esta CVE conforme al aviso upstream.

Hashes fuente relevantes (SHA-256):

| Archivo del árbol `folio2` | SHA-256 |
| --- | --- |
| `libmount/src/hook_subdir.c` | `5a832d08ed196100f1f53f4badb2b9c09fe79f371c9b1bcf5ee273d852c302bc` |
| `libmount/src/hook_mount.c` | `099733e68154f3e0cc2a90be731dc323adad0e393861e55a3f54f1738256cf79` |
| `libmount/src/context.c` | `77c2ba367a3c21dea0e73d5a76448780fb8e69726547ffec763beb522426a4a7` |

## Verificador modificado: resultado informativo sin excepción de seguridad

Se amplió `apps/inspector/util_linux_folio2_cve_regression.py` para diferenciar tres situaciones al examinar CVE-2026-78409:

- `hardened_detached_fast_path`: se ha localizado el fast path moderno y las protecciones `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH` esperadas.
- `not_affected_detached_fast_path_absent`: se ha demostrado mediante la cadena de funciones completa que el código del fast path no existe y **la ruta heredada rechaza al usuario restringido antes de actuar**.
- `unresolved`: no se ha acreditado una de esas dos condiciones, por ejemplo si falta el rechazo, se altera el orden de etapas, existe otro llamador del montaje de subdirectorio o aparece `api->subdir` sin protección. **Falla con `exit 3`**.

Se incorporaron pruebas TDD negativas que eliminan `-ENOTSUP`, falsifican `mnt_context_target_fd_required()`, eliminan registros de hooks, colocan la denegación después del `unshare`, crean un segundo llamador a `do_mount_subdir()` o introducen el fast path 2.42 inseguro. El reconocimiento de funciones descarta comentarios C para no aceptar falsas pruebas.

Comando reproducible:

```bash
python3 apps/inspector/util_linux_folio2_cve_regression.py \
  --source-dir /ruta/privada/de/source-folio2
# Exit 2: evidencia estática de no aplicabilidad a esta ruta,
#          no una aprobación de seguridad ni de release.
```

**Evidencia de ejecución:** se inspeccionaron los dos handoffs `folio2` independientes de R1.36; ambos devolvieron `exit 2` informativo, `applicability=not_affected_detached_fast_path_absent` y `release_authorized=false`. La suite Python completa del inspector sobre `main` incorporado aprobó **467/467** casos, incluidos **11 nuevos** casos de alcance R1.39. `py_compile` de verificador y tests finalizó con `exit 0`.

En ambas fuentes reales el informe contiene simultáneamente:

```json
{
  "status": "pre_2_42_cve_78409_not_applicable_static_scope_release_blocked",
  "source_cve_paths_accounted_for": true,
  "all_source_guards_present": false,
  "source_scope_not_applicable": ["CVE-2026-78409"],
  "unresolved_cve_paths": [],
  "upstream_scope_conflicts_debian_tracker": true,
  "cve_remediated": false,
  "runtime_cve_regressions_passed": false,
  "release_authorized": false,
  "security_gate": "blocked",
  "vex": "not_issued"
}
```

`missing_source_guards` sigue identificando la guarda que sólo existe en el fast path de 2.42; **no se transforma artificialmente en `source_guard_present=true`**. El resultado aclara la semántica de aplicabilidad, no sustituye una revisión upstream/downstream de Debian.

## Decisión de producto y siguientes controles

**No se ha creado `folio3`, ni aplicado un parche nuevo a `folio2`, ni reconstruido los 43 `.deb` ya reproducibles.** Un backport no pertinente a la rama 2.41.6 agregaría riesgo de regresión y código innecesario. Se conservan las dos reconstrucciones originales `folio2` R1.37 y sus pruebas dinámicas R1.38.

Permanece **G2 BLOQUEADO**: Debian sigue señalando cuatro CVE para Trixie y no se ha obtenido dictamen downstream sobre la discrepancia de 78409; no hay prueba de explotación dinámica con un fstab de usuario restringido (no se intentó), análisis ABI global, auditoría SBOM/Trivy de una nueva imagen por digest, permiso de publicación ni VEX. No se instalaron `.deb`, no se publicaron imágenes y no se desplegó nada.

**Siguiente control propuesto:** esclarecer con Debian la diferencia en la clasificación 78409, validar los otros CVE y la procedencia del candidato de imagen, y mantener escaneo/CI independientes. Ninguna clasificación local debe convertirse automáticamente en una excepción a Trivy o a la política G2.
