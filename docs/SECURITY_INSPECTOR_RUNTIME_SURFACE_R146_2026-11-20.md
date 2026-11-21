# R1.46 · Poda real de superficie de runtime X11 / mount / ncurses (NO RELEASE)

**Corte:** 20 noviembre 2026, America/Lima; ejecución técnica 21 noviembre UTC. **Seguimiento:** [G2 #75](https://github.com/DawoT/folio-civico/issues/75). **Objeto:** reducción incremental de paquetes innecesarios de una imagen local de investigación, con pruebas de funcionalidad real y seguridad diferencial. **No reemplaza la imagen operativa de inspector ni permite Preview/despliegue.**

## Datos verificados y decisión

La imagen aplanada R1.45 aún contenía `mount` (aunque el inspector corre como UID 65534 sin capacidades), X11/Cairo (aunque Poppler se compila con `ENABLE_CAIRO=OFF`, sin GUI) y `libncursesw6`/pinentry (aunque la CLI del inspector no solicita terminal interactiva ni firmas GPG). La simulación APT confirmó que solicitar la retirada **solo** de `mount`, `libx11-6`, `libx11-data`, `libxrender1` y `libncursesw6` implicaba la baja exacta de ocho paquetes, **sin advertencias** y sin tocar QPDF/ClamAV/Poppler/Tesseract/Fontconfig. Se rechazan desviaciones del conjunto y no se ejecuta `apt autoremove`.

No se elimina `login` por estar marcado `Protected` en Debian; tampoco `ncurses-bin` ni `ncurses-base` por estar marcados `Essential`. `libsqlite3-0` es una dependencia transitiva obligatoria de `util-linux → liblastlog2-2`; `libtiff6`, `libopenjp2-7` y `libexpat1` se utilizan en motores y fuentes instaladas. No se alteraron para ocultar alertas.

| Identidad local Docker | Valor |
|---|---|
| Base exigida R1.45 | `folio-civico-inspector:gnupg-pruned-research-r145` |
| SHA ID de base | `sha256:8e3bba6979ed0664531db7bd7fd55124afa7bb8afadae5df8b4d849f1c9ac3d2` |
| Imagen experimental R1.46 | `folio-civico-inspector:surface-pruned-research-r146` |
| SHA ID experimental | `sha256:c0011755a54a4af8c749ef60a2d0f40be5a186dbb071ea19d760e34a7d8360ee` |
| Build | Local, sin red, con pin exacto de fuente y `FROM scratch`; no OCI publicado |

El Dockerfile experimental exige las ocho bajas de paquetes exactas. Conserva usuario no-root, comandos, variables y puertos. Produce una imagen aplanada sin heredar capas OCI antiguas; el comparador controla **cero DiffID no vacíos** heredados, metadata operacional idéntica y hash byte-a-byte idéntico de ejecutables/librerías Poppler/Tesseract, modelos OCR y procedencia. Este último control **no** es atestación de build reproducible ni prueba de ausencia de vulnerabilidades nativas.

## Escaneo real diferencial y resultado

`bash apps/inspector/scan_surface_pruned_research.sh` refresca Trivy una sola vez, escanea ambas imágenes con el mismo snapshot de base de datos y genera CycloneDX. Se rechazan findings nuevos, desaparición de findings ajenos a los ocho paquetes, deriva de SBOM, cambio de ID Docker, metadata operativa y ELF. El resultado para evidencia válida es deliberadamente **exit 2 / release bloqueado**; evidencia insuficiente o alterada devuelve **exit 3**.

| Trivy | R1.45 base | R1.46 poda | Cambio |
|---|---:|---:|---:|
| CRITICAL | 0 | 0 | 0 |
| HIGH | **63** | **55** | **−8** |
| UNKNOWN | **15** | **15** | 0 |
| HIGH+CRITICAL+UNKNOWN | **78** | **70** | **−8** |

Las ocho alertas HIGH eliminadas corresponden a `mount` (4), X11 (3) y `libncursesw6` (1). La poda también retira tres dependencias indirectas sin abrir rutas nuevas. La comparación estricta confirma **ocho paquetes desinstalados** (`libcairo2`, `pinentry-curses`, `libncursesw6`, `libxext6`, `libxrender1`, `libx11-6`, `libx11-data`, `mount`). No atribuir esta reducción a parches de código fuente: los paquetes desaparecieron del filesystem y del inventario.

**Progreso acumulado medido:** R1.42 = 70 HIGH + 15 UNKNOWN = 85 bloqueantes; R1.45 = 63 + 15 = 78; R1.46 = 55 + 15 = 70. Se compararon imágenes de investigación de la misma línea de procedencia, no la candidata de producción ni un OCI publicado.

## Funcionalidad validada y reproducibilidad

`bash apps/inspector/build_surface_pruned_research.sh` → **exit 2 esperado** tras construir la imagen local y pasar smokes en contenedor `--network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, límites de memoria/procesos y fixtures exclusivamente sintéticos:
- ClamAV identifica EICAR; PDF cifrado, con adjuntos o malformado es rechazado.
- PDF válido / extracción nativa y OCR pasan; variables de host aisladas.
- API HTTP sanitaria y manifiesto sin firma pasan; token inválido y SHA falsificado se rechazan.
- Firmas ClamAV vigentes pasan; prueba de firma sintética >72h bloquea.
- La ausencia de librerías necesarias en `ldd` y la ausencia de comandos esperados por el runtime provocarían fallo de build, no una aprobación parcial.

`bash apps/inspector/scan_surface_pruned_research.sh` → **exit 2 esperado**; las alertas no se suprimen y no se genera VEX. El corpus comparativo de cuatro PDFs sintéticos OCR se contrasta por hashes de texto y error de caracteres entre imágenes. Las pruebas unitarias TDD cubren tampering de advisory/CVE, CycloneDX, hash nativo, modelos, metadata, capas, pin de imagen y CLI fail-closed.

```bash
# Solo en host de laboratorio local con imágenes exactas y Docker/Trivy.
bash apps/inspector/build_surface_pruned_research.sh
# exit 2: build y smokes correctos, siempre release bloqueado

bash apps/inspector/scan_surface_pruned_research.sh
# exit 2: diferencia válida y G2 bloqueado; exit 3: evidencia inválida

bash apps/inspector/compare_surface_pruned_quality.sh
# exit 0 únicamente si los hashes/textos OCR de los casos son iguales
```

## Riesgo residual / criterio de cierre de G2

**G2 permanece bloqueado**. Las **55 HIGH y 15 UNKNOWN** son hallazgos no acreditados como resueltos, incluyendo ClamAV, Expat, paquetes `util-linux`, bibliotecas de imagen e infraestructura. Tesseract y Poppler compilados desde fuente aún no tienen acreditación exhaustiva de advisories ni una reproducción/atestación completa por digest publicado. Los advisories ClamAV del boletín de noviembre exigen revisión individual aunque Trivy todavía no los refleje correctamente; la firma de paquete no equivale a prueba CVE por función. No hay VEX aprobado ni justificación para filtrar UNKNOWN.

La autorización final requiere remediation/actualización o eliminación real de todo blocker aplicable, verificación por advisory con fuente/ELF, escaneo Trivy+CycloneDX actualizado sobre el **artefacto definitivo exacto**, corpus adversarial/representativo, firmas actualizadas y decisión humana explícita sobre riesgos residuales. **Sin deploy, Preview, documentos institucionales, cambios remotos D1 ni publicación de imágenes.**
