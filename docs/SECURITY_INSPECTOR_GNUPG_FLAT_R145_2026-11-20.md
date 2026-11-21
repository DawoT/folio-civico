# R1.45 · Eliminación verificada de GnuPG en Poppler plano (NO RELEASE)

**Fecha de investigación:** 2026-11-20 (America/Lima; ejecución técnica 2026-11-21 UTC). **Seguimiento de seguridad:** [issue #68](https://github.com/DawoT/folio-civico/issues/68). **Alcance:** reducción real de superficie de paquetes en una **imagen local exclusivamente experimental**. No se sustituyen `Dockerfile`, `validation`, `ocr-integrated`, imágenes de producción ni configuraciones Cloudflare.

## Razón técnica y procedencia

Poppler R1.41 se compiló desde fuente Debian 25.03.0-5+deb13u4 con `ENABLE_GPGME=OFF`, `ENABLE_LIBCURL=OFF` y `ENABLE_NSS3=OFF`. Su imagen aplanada R1.42 todavía conservaba GnuPG del runtime base. Se verificó que una simulación APT (`apt-get -s purge`) de las **siete órdenes solicitadas** solo proponía retirar los nueve paquetes exactos de GnuPG, incluidos `libgpgme11t64` y `libgpgmepp6t64`. No se autoriza `autoremove`, ya que podría retirar Fontconfig u otras bibliotecas imprescindibles.

| Identidad Docker local | Valor |
|---|---|
| Base de R1.42 | `folio-civico-inspector:poppler-flat-research` |
| ID de base exigido | `sha256:a68bce319afff0a0f50d50f5a717e077061dbe1eb93c9465910d7f002ba23f18` |
| Imagen experimental R1.45 | `folio-civico-inspector:gnupg-pruned-research-r145` |
| ID experimental observado | `sha256:8e3bba6979ed0664531db7bd7fd55124afa7bb8afadae5df8b4d849f1c9ac3d2` |
| Distribución | Debian 13.7, infraestructura Docker local |
| Publicación en registro | **Ninguna** |

La construcción utiliza una etiqueta derivada del ID de base, sin acceso de red de Docker, y `FROM scratch` con la copia del filesystem resultante de la poda. Así no se transporta la capa histórica con GnuPG. La comparación verifica exactamente **dos DiffID por imagen**, de los cuales uno es la capa vacía canónica; **cero capas no vacías compartidas** y **metadatos de ejecución equivalentes** (`USER=65534:65534`, comando, variables, directorio y puerto).

## Resultado comparativo, sin atenuantes de escaneo

Se escanearon ambas imágenes con **la misma base de datos Trivy**, descargada una sola vez, y CycloneDX. No se usaron exclusiones, `--ignore-unfixed`, severidades filtradas ni VEX. El comparador exige identidad de ambos IDs inmutables y diferencia exacta de nueve paquetes; cualquier paquete o CVE ajeno que aparezca o desaparezca devuelve **exit 3**.

| Hallazgos de Trivy | R1.42 antes | R1.45 después | Cambio |
|---|---:|---:|---:|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 70 | **63** | **−7** |
| UNKNOWN | 15 | **15** | 0 |
| MEDIUM | 146 | 139 | −7 |
| LOW | 141 | 120 | −21 |
| **Bloqueantes (CRITICAL + HIGH + UNKNOWN)** | **85** | **78** | **−7** |

Las siete alertas HIGH retiradas corresponden a GnuPG; no desaparece ningún advisory de los paquetes de OCR, Poppler, ClamAV, util-linux o Expat. **Esto es una reducción real de paquetes presentes, no siete CVE reparados en código fuente.**

## Evidencias funcionales y límites

- `Dockerfile.gnupg-prune-research` hizo efectiva la simulación APT acotada a exactamente los nueve paquetes. Construcción offline exit 0; ninguna imagen anterior fue modificada.
- Los **cinco binarios de utilidad Poppler**, Tesseract y `libtesseract.so.5.5.4` siguen presentes y sin dependencias `not found`. Fontconfig y los modelos OCR `eng`/`spa` permanecen.
- `smoke_real_engines.py` (con motores reales): exit 0; EICAR detectado, extracción nativa/OCR aprobados, PDF cifrado/adjuntos/malformado rechazados y entorno de parser aislado.
- `smoke_http_real.py`: exit 0; salud, manifiesto, token inválido y hash falsificado dentro del contrato sintético.
- `smoke_signature_freshness.py`: exit 0; firmas frescas admitidas y firmas >72h simuladas bloqueadas.
- `scan_gnupg_flat_research.sh`: **exit 2 deliberado**; la reducción 85→78, 9 paquetes, metadatos de imagen, hashes de Poppler/Tesseract/modelos y capas pasaron comparación. Imagen inmutable: se rechaza cualquier sustitución durante el escaneo.
- El comparador no convierte hashes idénticos en evidencia de auditoría CVE completa de fuentes C/C++, ni una reducción de paquetes en excepción de vulnerabilidades.

Reproducción local manual, **solo en equipo con Docker/Trivy y recursos suficientes**:

```bash
bash apps/inspector/build_gnupg_flat_research.sh
# exit 2: smokes correctos, release sigue bloqueado

bash apps/inspector/scan_gnupg_flat_research.sh
# exit 2: reducción CVE validada, release sigue bloqueado
# exit 3: evidencia o identidad insuficiente
```

## Riesgos restantes y criterio real de desbloqueo

**G2 CONTINÚA BLOQUEADO: 63 HIGH + 15 UNKNOWN = 78 registros** en la imagen experimental; además permanecen **dos componentes compilados desde fuente cuya cobertura CVE completa no está acreditada** (Poppler/Tesseract). Hay dependencias directamente cargadas como `libexpat1`, `libtiff6` y ClamAV; la ausencia de vínculo `ldd` en otros paquetes **no prueba no alcanzabilidad**. Los diez CVE del boletín de noviembre de ClamAV, todavía no visibles en el escáner de R1.44, exigen tratamiento por advisory; la firma del paquete 1.5.5 no sustituye la revisión funcional de cada ruta. <https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html>

Para considerar una imagen de release hay que: actualizar o reconstruir los paquetes afectados con fuentes verificadas y parches de proveedor; demostrar aplicabilidad por advisory o emitir únicamente VEX técnicamente justificados y aprobados por el responsable; confirmar ELF, SBOM, scanner actual, corpus adversarial OCR/PDF y smokes reales sobre la **misma imagen final por digest**; y obtener autorización de Preview/producción separada. El escáner de Debian sigue listando CVE de Poppler sin parches disponibles en Trixie para varios casos. <https://security-tracker.debian.org/tracker/source-package/poppler>

**No se ha desplegado, liberado, publicado, procesado PDFs institucionales ni alterado el gate G2.** Los éxitos de CI general o de esta investigación no reemplazan el gate real de liberación.
