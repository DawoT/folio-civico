# R1.13 · RESEARCH ONLY — NO RUNTIME PATCH INSTALLATION

Estos **tres prototipos** son adaptaciones textuales de parches Debian
`26.07.0-4` a la fuente Debian Trixie `25.03.0-5+deb13u4`. Solo se
ejecutan sobre un árbol fuente temporal, verificado por SHA-256. **No
integrarlos en `Dockerfile.poppler-experiment`, no publicarlos ni
declararlos correcciones CVE sin revisión independiente.**

- `CVE-2026-102621-trixie-prototype.patch`: adapta SplashClip a la API
  antigua; persiste el cálculo sin guardia de `yMaxAA`.
- `CVE-2026-93312-trixie-prototype.patch`: aproxima el guard JBIG2
  `rewind` a la ruta `reset()` anterior; no prueba equivalencia.
- `CVE-2026-93313-trixie-prototype.patch`: adapta resta comprobada
  y devolución a `readCodeTableSeg(...)` antiguo (`void`).
- `check_numeric_boundaries.cc`: micro-harness independiente sobre
  `goo/GooCheckedOps.h` **del árbol Debian SHA-pinned**. Debe compilarse
  externamente con `-fsanitize=undefined`; no ejercita Poppler completo.

Toda verificación, SHA y sus límites están en
[el informe R1.13](../../../docs/SECURITY_POPPLER_SEMANTIC_PROTOTYPES_2026-11-19.md).
