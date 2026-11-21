# Integración local y saneamiento Git — Folio Cívico

**Ámbito:** repositorio local y GitHub como historial de revisión. **No** implica despliegue de Cloudflare ni desbloqueo del inspector.

## Fuente de verdad del CI

El gate **obligatorio** es `sh scripts/ci.sh`, ejecutado en el **árbol exacto que se pretende integrar** (rama actualizada o integración temporal con `origin/main`). GitHub Actions no es una dependencia operativa: sus checks pueden ser orientativos, estar deshabilitados o no estar disponibles. Ni un check remoto verde sustituye al exit code 0 del script ni un check remoto ausente justifica omitir el gate.

Antes de fusionar:

1. `git fetch origin`; comprobar HEAD, `origin/main` y la divergencia. No reescribir historia ni hacer push forzado.
2. Construir un worktree **temporal** desde `origin/main`, aplicar el cambio candidato y comprobar que el resultado es exactamente el que se integrará. No ejecutar pruebas concurrentes que compartan puertos o artefactos.
3. Ejecutar `sh scripts/ci.sh` en ese worktree; registrar commit base, commit probado, hora, código de salida y gates ejecutados. **Exit distinto de 0 bloquea** la fusión. Asegurar además `git diff --check` y árbol limpio respecto al commit candidato.
4. Integrar mediante PR o avance rápido controlado y volver a comprobar que `main` local y remota son coherentes. No ignorar commits de terceros aparecidos mientras corría el CI: si cambió `origin/main`, repetir la validación de la integración.
5. Mantener independientes los gates de seguridad del inspector (`pnpm audit:inspector:image` y prueba real Docker); aprobar el CI shell solo autoriza integrar **código**, no liberar runtime, recursos, migraciones remotas ni datos reales.

## Inventario de ramas y worktrees

Desde cualquier directorio:

```sh
pnpm audit:git-hygiene
node scripts/git-hygiene.mjs --json
```

El comando es **solo lectura** y no necesita GitHub Actions, `gh`, red, credenciales ni una rama `main` activa en el checkout actual. Compara las ramas locales con `origin/main`, muestra la divergencia de `main` y revisa el estado de cada worktree registrado. La referencia remota debe actualizarse aparte con `git fetch origin` cuando exista autorización y conectividad.

**Precaución:** *antecesora de origin/main* no prueba que un worktree sea prescindible. *No antecesora* tampoco demuestra trabajo sin fusionar: los PR con squash, cherry-pick, merge u otros commits de sincronización pueden producir SHA distintos. Para esas ramas, cotejar PR, diff efectivo y equivalencia de parches (`git cherry`) antes de decidir. El campo `divergentBranchSnapshots[].matchingBaseCommit` identifica una coincidencia **exacta de árbol** con algún commit accesible desde `origin/main`, incluso si `main` avanzó después. `null` solo indica que no hay coincidencia en la historia local disponible; una coincidencia tampoco autoriza eliminar la rama ni acredita que sus commits individuales estén compartidos. La clasificación es exclusivamente de lectura y no realiza limpieza.

## Política de limpieza

- **Protegidos:** worktrees con archivos modificados o no seguidos, ramas abiertas en PR, investigación activa, ramas divergentes sin clasificación y cualquier ubicación con artefactos locales ignorados que aún deban conservarse.
- **Candidatos, no autorizaciones:** worktrees limpios cuya rama es antecesora de `origin/main`, y ramas cuyo contenido esté plenamente consolidado después de revisar su PR.
- **Limpieza irreversible:** requiere aprobación específica de qué paths y ramas retirar. No usar `git worktree remove --force`, `git clean -fdx`, `git branch -D` ni borrado masivo por prefijos. Si se aprueba, hacer inventario actualizado, eliminar un worktree con `git worktree remove` y luego considerar `git branch -d` solo si Git confirma integración; validar `git worktree list` y `git status` después de cada lote.
- Un worktree limpio puede contener **archivos ignorados** (cachés o evidencias); revisar espacio y retención antes de borrarlo.

El checkout raíz puede tener una rama de investigación, mientras `main` está en otro worktree. No realizar merges ni cambios de rama en el checkout raíz suponiendo que está en `main`.
