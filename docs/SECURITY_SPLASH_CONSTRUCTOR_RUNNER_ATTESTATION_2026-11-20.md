# R1.28 · Integridad del ejecutor de investigación R1.27

**Fecha:** 2026-11-20, America/Lima. **Alcance:** endurecimiento de la cadena de custodia de un experimento local Poppler; ninguna modificación al runtime ni al conjunto de CVE.

## Hallazgo reproducido

La investigación R1.27 compila la biblioteca estática completa de Poppler Debian `25.03.0-5+deb13u4` bajo ASan/UBSan y prueba **ambos constructores reales** de `Splash` con un bitmap Mono1 de una fila realmente asignado. La fuente C++ del harness estaba identificada por SHA-256, pero el script `research_patches/run_splash_aa_width_constructor.sh` se verificaba mediante **cadenas obligatorias**, no mediante digest.

Un actor capaz de alterar el script sin eliminar dichas cadenas podía introducir comandos que cambiasen la compilación o generasen archivos falsos bajo `/results`, mientras `check_prototypes()` seguía aceptando el script. El aislamiento Docker (`--network none`, rootless, read-only, límites de recursos) reduce el impacto operativo, pero **no convierte en auténtico un resultado experimental fabricado por el propio ejecutor**.

## Implementación

`apps/inspector/poppler_splash_aa_constructor_probe.py` fija también el SHA-256 del runner completo:

```
f0fdf334902ccaa9ab2e576fb98ebca8464a423a0843ae15d372da132c5e48db
```

`check_prototypes()` lee los bytes, comprueba SHA-256 antes de interpretar su contenido y rechaza cualquier divergencia con `ValueError`. Mantiene el chequeo de los marcadores de seguridad y la huella ya existente del archivo C++. El reporte incorpora `research_runner_script_sha256` para auditar exactamente el experimento ejecutado.

**Compatibilidad:** el script original no se modifica; la compilación experimental y los casos ASan/UBSan R1.27 mantienen su semántica. Toda modificación futura del runner exige revisión explícita y actualización conjunta del digest y los tests.

## Evidencia Red → Green

Se añadió una prueba que hace una copia aislada de los dos archivos R1.27, valida la copia intacta, añade un comando sintético al final del shell —sin alterar ninguna cadena obligatoria— y exige el rechazo.

- **Red:** 12/13 pruebas pasaron y la nueva falló porque el script adulterado se aceptaba.
- **Green:** 13/13 pruebas pasaron. El mismo script adulterado ahora se rechaza mediante SHA-256.
- La prueba usa únicamente archivos sintéticos y no ejecuta los comandos añadidos.

## Verificación ejecutada y dependencia externa

- **13/13 unitarias específicas** (incluyendo el nuevo caso negativo) y
  **223/223 Python del inspector**: exit 0.
- El script de compilación original conserva su contenido y
  `bash -n` terminó en exit 0.
- **CI integral local de esta rama: exit 1**, no aprobado. El bloqueo
  está en **cuatro pruebas Vitest de dos archivos**:
  `apps/api/src/processing-pipeline.e2e.test.ts` (1) y
  `packages/data/src/quarantine-audit.test.ts` (3).
  En el resto de la batería Vitest: 475/479 pruebas pasaron.
  La ejecución no llegó a una aprobación integral de Chromium y D1.
- Se reprodujeron **los mismos cuatro fallos** ejecutando solamente
  esos dos archivos en la rama R1.27 **sin este cambio**: 4 fallidas de
  17. Por tanto, la regresión no fue introducida por la nueva
  comparación de SHA-256.
- La rama independiente `fix/local-ci-clock-fixtures` contiene un
  ajuste de relojes sintéticos: sobre ella **17/17 pruebas específicas
  pasaron**. No se integró ni se modificó desde R1.28; sigue pendiente
  completar la integración y el CI sobre una base que incluya la
  corrección.
- **Auditoría de seguridad actual: exit 2, BLOQUEADO**. Trivy informó
  **0 CRITICAL, 70 HIGH, 15 UNKNOWN y 85 bloqueos**; dos componentes
  nativos permanecen sin cobertura CVE suficiente. Las cifras anteriores
  de 19 UNKNOWN no corresponden al resultado de esta ejecución.

## Limitaciones y gobierno

- El hash protege los bytes observados por `check_prototypes()`. **No** es una firma de un proveedor ni elimina por sí solo posibles carreras si un tercero con acceso al host modifica los archivos entre comprobación y montaje; el control de acceso al worktree y los montajes Docker siguen siendo necesarios.
- No demuestra que el desbordamiento de R1.27 pueda alcanzarse desde un PDF ni que exista una explotación. No reinterpreta la corrección o alcance de ningún CVE.
- La cadena de investigación todavía **no equivale a procedencia source→ELF del inspector operativo**; tampoco modifica su auditoría Trivy, que continúa bloqueando el release.
- Conforme a ADR-023, el cambio solo incluye código de investigación, tests y documentación. Prohibidos despliegues, migraciones D1 remotas, publicaciones/retags OCI, VEX y cambios de imágenes operativas.

## Verificación

```sh
python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_splash_aa_constructor_probe.py' -v
python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'
sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

**Integración:** este cambio debe fusionarse **después** de la rama de investigación R1.27, que introduce el runner. No reemplaza sus ocho casos C++ originales ni habilita un release.
