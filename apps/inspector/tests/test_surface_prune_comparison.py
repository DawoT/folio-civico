"""TDD: R1.46 removes only unused mount/X11/ncurses packages, not CVE gates."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps" / "inspector"))

from runtime_prune_comparison import SURFACE_REMOVED_PACKAGES
from test_advisory_inventory import source_inventory as native_inventory
from surface_prune_comparison import (
    BASE, CANDIDATE, PINNED_BASE_ID, EMPTY_LAYER, compare_surface_prune,
)

REMOVED = (
    "libcairo2", "pinentry-curses", "libncursesw6", "libxext6",
    "libxrender1", "libx11-6", "libx11-data", "mount",
)


def fixture():
    before_id = PINNED_BASE_ID
    after_id = "sha256:" + "b" * 64
    issues = [
        {
            "PkgName": name, "InstalledVersion": "1.0",
            "VulnerabilityID": "CVE-2026-" + str(i + 10000),
            "Severity": "HIGH",
        }
        for i, name in enumerate(("mount", "libx11-6", "libx11-data",
                                  "libxrender1", "libncursesw6"))
    ]
    issues += [
        {"PkgName": "libc6", "InstalledVersion": "2.41",
         "VulnerabilityID": "CVE-2026-77777", "Severity": "UNKNOWN"},
        {"PkgName": "clamav", "InstalledVersion": "1.5.5-1",
         "VulnerabilityID": "CVE-2026-20213", "Severity": "HIGH"},
    ]
    scan_before = {"ArtifactName": BASE, "ArtifactType": "container_image", "Results": [
        {"Type": "debian", "Target": "debian 13.7", "Vulnerabilities": issues},
    ]}
    scan_after = copy.deepcopy(scan_before)
    scan_after["ArtifactName"] = CANDIDATE
    scan_after["Results"][0]["Vulnerabilities"] = issues[-2:]
    def bom(image, image_id, extra):
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"component": {"type": "container", "name": image,
                "properties": [{"name": "aquasecurity:trivy:ImageID", "value": image_id}]}},
            "components": [
                {"type": "library", "name": name, "version": "1.0",
                 "purl": "pkg:deb/debian/" + name + "@1.0?arch=amd64"}
                for name in list(extra) + ["clamav", "libc6"]
            ] + [{"type": "operating-system", "name": "debian", "version": "13.7"}],
        }
    cfg = {
        "User": "65534:65534",
        "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
        "Entrypoint": None,
        "WorkingDir": "/srv/folio-inspector",
        "Env": ["PATH=/opt/folio-poppler/bin:/opt/folio-ocr/bin"],
        "ExposedPorts": {"8789/tcp": {}},
    }
    before_inspect = {"Id": before_id, "RootFS": {
        "Type": "layers", "Layers": ["sha256:" + "c" * 64, EMPTY_LAYER]
    }, "Config": cfg}
    after_inspect = copy.deepcopy(before_inspect)
    after_inspect["Id"] = after_id
    after_inspect["RootFS"]["Layers"][0] = "sha256:" + "d" * 64
    native = native_inventory()
    return [
        scan_before, scan_after, bom(BASE, before_id, REMOVED),
        bom(CANDIDATE, after_id, ()), before_id, after_id,
        before_inspect, after_inspect, native, copy.deepcopy(native),
    ]


class SurfacePruneTests(unittest.TestCase):
    def test_exact_removed_packages_preserve_remaining_unknown_and_gate(self):
        self.assertEqual(SURFACE_REMOVED_PACKAGES, frozenset(REMOVED))
        result = compare_surface_prune(*fixture())
        self.assertEqual(result["removed_high"], 5)
        self.assertEqual(result["high_before"], 6)
        self.assertEqual(result["high_after"], 1)
        self.assertEqual(result["unknown_after"], 1)
        self.assertEqual(set(result["removed_packages"]), set(REMOVED))
        self.assertEqual(result["nonempty_base_layers_reused"], 0)
        self.assertEqual(result["source_elf_identity"], "unchanged")
        self.assertFalse(result["release_authorized"])

    def test_unexpected_cve_drift_or_package_deletion_rejected(self):
        changes = (
            lambda a: a[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "clamav", "InstalledVersion": "1.5.5-1",
                "VulnerabilityID": "CVE-2026-NEW", "Severity": "HIGH",
            }),
            lambda a: a[1]["Results"][0]["Vulnerabilities"].clear(),
            lambda a: a[3]["components"].pop(-2),
            lambda a: a[2]["components"].pop(-2),
            lambda a: a[3]["metadata"]["component"]["properties"][0].update(value="wrong"),
            lambda a: a[0].update(ArtifactName="other"),
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                data = fixture()
                change(data)
                compare_surface_prune(*data)

    def test_native_binary_drift_and_runtime_metadata_prohibited(self):
        changes = (
            lambda a: a[9]["components"][0].update(library_sha256="f" * 64),
            lambda a: a[9]["components"][1]["tool_sha256"].update(pdfinfo="f" * 64),
            lambda a: a[9]["components"][0]["model_sha256"].update(eng="f" * 64),
            lambda a: a[7]["Config"].update(User="0:0"),
            lambda a: a[7]["Config"]["Env"].append("DEBUG=1"),
            lambda a: a[7]["RootFS"]["Layers"].__setitem__(0, a[6]["RootFS"]["Layers"][0]),
            lambda a: a[7]["RootFS"]["Layers"].append("sha256:" + "e" * 64),
            lambda a: a[6].update(Id="sha256:" + "f" * 64),
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                data = fixture()
                change(data)
                compare_surface_prune(*data)

    def test_cli_valid_evidence_remains_blocked_and_tampering_errors(self):
        rows = fixture()
        names = (
            "before-scan", "after-scan", "before-sbom", "after-sbom",
            "before-inspect", "after-inspect", "before-native", "after-native",
        )
        with tempfile.TemporaryDirectory() as d:
            cmd = [sys.executable, "apps/inspector/surface_prune_comparison.py"]
            paths = {}
            for i, name in enumerate(names):
                path = Path(d) / (name + ".json")
                path.write_text(json.dumps(rows[i if i < 4 else i + 2]))
                paths[name] = path
                cmd.extend(("--" + name, str(path)))
            cmd.extend(("--before-id", rows[4], "--after-id", rows[5]))
            ok = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(ok.returncode, 2, ok.stderr)
            self.assertFalse(json.loads(ok.stdout)["release_authorized"])
            paths["after-native"].write_text("{}")
            denied = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(denied.returncode, 3)
            self.assertEqual(json.loads(denied.stdout)["status"], "error")

    def test_build_scripts_lock_immutable_source_and_prevent_release(self):
        dockerfile = (ROOT / "apps/inspector/Dockerfile.surface-pruned-research").read_text()
        self.assertIn("FROM scratch", dockerfile)
        self.assertIn("COPY --from=pruner / /", dockerfile)
        self.assertIn("apt-get -s purge", dockerfile)
        self.assertIn("libcairo2", dockerfile)
        self.assertIn("libncursesw6", dockerfile)
        self.assertIn("libfontconfig1", dockerfile)
        self.assertIn("libopenjp2-7", dockerfile)
        for cmd in ("docker push", "wrangler deploy", "apt-get autoremove",
                    "--allow-remove-essential"):
            self.assertNotIn(cmd, dockerfile)
        for name in ("build_surface_pruned_research.sh", "scan_surface_pruned_research.sh"):
            code = (ROOT / "apps/inspector" / name).read_text()
            self.assertIn("set -euo pipefail", code)
            self.assertIn(PINNED_BASE_ID, code)
            self.assertIn("docker image inspect", code)
            executable = "\n".join(
                line for line in code.splitlines() if not line.lstrip().startswith("#")
            )
            for cmd in ("docker push", "wrangler deploy", "docker system prune",
                        "--ignore-unfixed", "--ignorefile"):
                self.assertNotIn(cmd, executable)
            bad = subprocess.run(["bash", "apps/inspector/" + name, "--bad"],
                                 cwd=ROOT, capture_output=True, text=True, timeout=8)
            self.assertEqual(bad.returncode, 3)


if __name__ == "__main__":
    unittest.main()
