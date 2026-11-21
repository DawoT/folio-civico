"""R1.42 TDD: scratch-only filesystem copy cannot mask CVE/SBOM/native drift."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps" / "inspector"))

from poppler_flat_comparison import (  # noqa: E402
    SOURCE, FLAT, EMPTY_LAYER, PUBLIC_BUILD_GPG_KEY, verify_flat_poppler,
)

SOURCE_ID = "sha256:" + "a" * 64
FLAT_ID = "sha256:" + "b" * 64


def fixture():
    vulnerabilities = [
        {"PkgName": "clamav", "InstalledVersion": "1.5.5-1",
         "VulnerabilityID": "CVE-2026-20213", "Severity": "HIGH"},
        {"PkgName": "libexpat1", "InstalledVersion": "2.9.0",
         "VulnerabilityID": "CVE-2026-124317", "Severity": "UNKNOWN"},
        {"PkgName": "libuuid1", "InstalledVersion": "1.0",
         "VulnerabilityID": "CVE-2026-30001", "Severity": "MEDIUM"},
    ]
    def scan(name):
        return {
            "ArtifactName": name, "ArtifactType": "container_image",
            "Results": [{"Target": "debian 13.7", "Type": "debian",
                         "Vulnerabilities": copy.deepcopy(vulnerabilities)}],
        }
    def sbom(name, id_):
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"component": {"name": name, "type": "container",
                           "properties": [{
                               "name": "aquasecurity:trivy:ImageID",
                               "value": id_,
                           }]}},
            "components": [
                {"type": "library", "name": n, "version": "1.0",
                 "purl": f"pkg:deb/debian/{n}@1.0?arch=amd64"}
                for n in ["clamav", "libexpat1", "libuuid1"]
            ] + [{"type": "operating-system", "name": "debian",
                  "version": "13.7"}],
        }
    env = [
        "PATH=/opt/folio-poppler/bin:/opt/folio-ocr/bin:/usr/bin",
        "LANG=C.UTF-8", PUBLIC_BUILD_GPG_KEY,
        "TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata",
        "CLAMAV_DB_DIR=/opt/clamdb", "FOLIO_INSPECTOR_BIND=0.0.0.0",
    ]
    def meta(id_, *, flat):
        return {
            "Id": id_, "Os": "linux", "Architecture": "amd64",
            "RootFS": {
                "Type": "layers",
                "Layers": (
                    ["sha256:" + "c"*64, EMPTY_LAYER] if flat
                    else ["sha256:" + f"{i:064x}" for i in range(1, 17)]
                ),
            },
            "Config": {
                "User": "65534:65534",
                "Env": [x for x in env if not (flat and x == PUBLIC_BUILD_GPG_KEY)],
                "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
                "WorkingDir": "/srv/folio-inspector", "Entrypoint": None,
                "ExposedPorts": {"8789/tcp": {}}, "Volumes": None,
                "Healthcheck": None, "StopSignal": None,
            },
        }
    h = "a" * 64
    def native():
        return {
            "source": "folio-local-elf-provenance-v1",
            "mode": "experiment",
            "source_cve_coverage": "unassessed",
            "components": [
                {"name": "tesseract", "library_sha256": h,
                 "executable_sha256": h, "provenance_sha256": h,
                 "automated_cve_coverage": "not_verified",
                 "cve_assessment": "required",
                 "model_sha256": {"eng": h, "spa": h},
                 "tool_sha256": {}},
                {"name": "poppler", "library_sha256": h,
                 "executable_sha256": h, "provenance_sha256": h,
                 "automated_cve_coverage": "not_verified",
                 "cve_assessment": "required",
                 "model_sha256": {},
                 "tool_sha256": dict.fromkeys((
                     "pdfinfo", "pdftotext", "pdfimages", "pdftoppm", "pdfdetach", "pdfattach",
                 ), h)},
            ],
        }
    return [
        scan(SOURCE), scan(FLAT), sbom(SOURCE, SOURCE_ID), sbom(FLAT, FLAT_ID),
        meta(SOURCE_ID, flat=False), meta(FLAT_ID, flat=True),
        native(), native(),
    ]


class PopplerFlatEvidenceTests(unittest.TestCase):
    def test_exact_layer_and_native_preservation_never_authorizes_release(self):
        report = verify_flat_poppler(*fixture())
        self.assertEqual(report["source_layers"], 16)
        self.assertEqual(report["flat_layers"], 2)
        self.assertEqual(report["inherited_nonempty_layer_ids"], 0)
        self.assertEqual(report["trivy_blocking_findings"], 2)
        self.assertEqual(report["trivy_high"], 1)
        self.assertEqual(report["trivy_unknown"], 1)
        self.assertEqual(report["native_components_without_verified_cve_coverage"], 2)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["poppler_native_cve_coverage_verified"])
        self.assertTrue(report["native_elf_model_hashes_unchanged"])

    def test_fail_closed_on_drift_and_incomplete_layer_or_cve_evidence(self):
        variants = [
            lambda x: x[5]["RootFS"]["Layers"].__setitem__(0, x[4]["RootFS"]["Layers"][0]),
            lambda x: x[5]["RootFS"].update(Layers=x[4]["RootFS"]["Layers"]),
            lambda x: x[5]["RootFS"].update(Layers=[EMPTY_LAYER]),
            lambda x: x[5].update(Id=x[4]["Id"]),
            lambda x: x[5].update(Architecture="arm64"),
            lambda x: x[5]["Config"].update(User="root"),
            lambda x: x[5]["Config"]["Env"].append(PUBLIC_BUILD_GPG_KEY),
            lambda x: x[5]["Config"]["Env"].append("NEW_UNAPPROVED=true"),
            lambda x: x[5]["Config"].update(Cmd=["/bin/sh"]),
            lambda x: x[3]["components"].pop(0),
            lambda x: x[3]["metadata"]["component"]["properties"][0].update(value=SOURCE_ID),
            lambda x: x[1]["Results"][0]["Vulnerabilities"].pop(0),
            lambda x: x[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "clamav", "InstalledVersion": "1.5.5-1",
                "VulnerabilityID": "CVE-2026-20214", "Severity": "HIGH"}),
            lambda x: x[7]["components"][0].update(library_sha256="b"*64),
            lambda x: x[7]["components"][1]["tool_sha256"].pop("pdfinfo"),
            lambda x: x[7].update(source_cve_coverage="assessed"),
        ]
        for i, modify in enumerate(variants):
            with self.subTest(case=i):
                data = copy.deepcopy(fixture())
                modify(data)
                with self.assertRaises((ValueError, TypeError)):
                    verify_flat_poppler(*data)

    def test_cli_returns_blocking_exit_two_and_corrupt_evidence_exit_three(self):
        keys = ("before-scan", "after-scan", "before-sbom", "after-sbom",
                "before-inspect", "after-inspect", "before-native", "after-native")
        with tempfile.TemporaryDirectory() as folder:
            files = []
            args = ["python3", "apps/inspector/poppler_flat_comparison.py"]
            for key, data in zip(keys, fixture()):
                file = Path(folder) / (key + ".json")
                file.write_text(json.dumps(data), encoding="utf-8")
                files.append(file)
                args.extend(("--" + key, str(file)))
            good = subprocess.run(args, cwd=ROOT, capture_output=True,
                                  text=True, timeout=10, check=False)
            self.assertEqual(good.returncode, 2)
            self.assertFalse(json.loads(good.stdout)["release_authorized"])
            files[-1].write_text("{}", encoding="utf-8")
            bad = subprocess.run(args, cwd=ROOT, capture_output=True,
                                 text=True, timeout=10, check=False)
            self.assertEqual(bad.returncode, 3)
            self.assertEqual(json.loads(bad.stdout)["status"], "error")

    def test_research_only_build_and_scan_scripts_disallow_release_shortcuts(self):
        d = (ROOT / "apps/inspector/Dockerfile.poppler-flat-research").read_text()
        build = (ROOT / "apps/inspector/build_poppler_flat_research.sh").read_text()
        scan = (ROOT / "apps/inspector/scan_poppler_flat_research.sh").read_text()
        self.assertIn("FROM scratch", d)
        self.assertIn("COPY --from=source / /", d)
        self.assertIn("POPPLER_FLAT_SOURCE", d)
        self.assertIn("USER 65534:65534", d)
        self.assertNotIn("ENV GPG_KEY=", d)
        quality = (ROOT / "apps/inspector/compare_poppler_flat_quality.sh").read_text()
        for script in (build, scan, quality):
            self.assertIn("sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f", script)
            self.assertIn("unapproved_poppler_source_id", script)
            self.assertIn("set -euo pipefail", script)
            self.assertIn("--network none", script)
            self.assertIn("--pull never", script)
            self.assertIn("poppler-flat-research", script)
            for forbidden in (
                "docker push", "wrangler deploy", "--publish",
                "--ignore-unfixed", "--ignorefile", "docker system prune",
            ):
                self.assertNotIn(forbidden, script)
        self.assertIn("RootFS", build)
        self.assertIn("source_inventory.py", scan)
        self.assertIn("poppler_flat_comparison.py", scan)
        for script in ("build_poppler_flat_research.sh",
                       "scan_poppler_flat_research.sh",
                       "compare_poppler_flat_quality.sh"):
            result = subprocess.run(
                ["bash", "apps/inspector/" + script, "--invalid"],
                cwd=ROOT, capture_output=True, text=True, timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 3)


if __name__ == "__main__":
    unittest.main()
