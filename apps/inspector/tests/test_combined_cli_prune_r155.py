"""R1.55 RED/GREEN: no CVE suppression or unintended native filesystem change."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
from combined_cli_prune_r155 import (  # noqa: E402
    BASE, CANDIDATE, BASE_ID, CANDIDATE_ID, compare,
)
from clamav_cli_surface import DENY
from gnupg_flat_prune_comparison import EMPTY_LAYER
from runtime_executable_surface_inventory import DOCKER_INJECTED, EXCLUDED_TOP_LEVEL
from source_inventory import POPPLER_TOOLS

H = "a" * 64
DIFFERENT = "b" * 64
CLAM_CODE = (
    "/usr/local/bin/clamscan",
    "/usr/local/lib/libclamav.so.12.1.0",
    "/usr/local/lib/libclamav_rust.a",
    "/usr/local/lib/libclammspack.so.0.8.0",
    "/usr/local/lib/libclamunrar.so.12.1.0",
    "/usr/local/lib/libclamunrar_iface.so.12.1.0",
    "/usr/local/lib/libfreshclam.so.4.0.0",
)
# The other nine ELF commands are removed; clamav-config is a script.
CLAM_REMOVED_CODE = tuple(sorted(set(DENY) - {"/usr/local/bin/clamav-config"}))


def fixture():
    cfg = {
        "User": "65534:65534", "Entrypoint": None,
        "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
        "WorkingDir": "/srv/folio-inspector", "ExposedPorts": {"8789/tcp": {}},
        "Env": ["CLAMAV_DB_DIR=/opt/clamdb"],
    }

    def image(ident, layer):
        return {
            "Id": ident, "Os": "linux", "Architecture": "amd64",
            "Config": copy.deepcopy(cfg),
            "RootFS": {"Type": "layers", "Layers": [layer, EMPTY_LAYER]},
        }

    def scan(label):
        entries = [
            {"PkgName": "clamav", "InstalledVersion": "1.5.5-1",
             "VulnerabilityID": f"CVE-2026-{10000 + n}", "Severity": "HIGH"}
            for n in range(55)
        ] + [
            {"PkgName": "libexpat1", "InstalledVersion": "2.9.0",
             "VulnerabilityID": f"CVE-2026-{20000 + n}", "Severity": "UNKNOWN"}
            for n in range(15)
        ]
        return {"ArtifactName": label, "ArtifactType": "container_image",
                "Results": [{"Target": "debian 13.7", "Type": "debian",
                             "Vulnerabilities": entries}]}

    def sbom(label, ident):
        return {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {
                "type": "container", "name": label,
                "properties": [{"name": "aquasecurity:trivy:ImageID", "value": ident}],
            }},
            "components": [
                {"type": "library", "name": "clamav", "version": "1.5.5-1",
                 "purl": "pkg:deb/debian/clamav@1.5.5-1?arch=amd64"},
                {"type": "operating-system", "name": "debian", "version": "13.7"},
            ],
        }

    def source_component(name):
        tools = {key: H for key in POPPLER_TOOLS} if name == "poppler" else {}
        models = {"eng": H, "spa": H} if name == "tesseract" else {}
        return {
            "name": name, "version": ("25.03.0-5+deb13u4" if name == "poppler" else "5.5.4"),
            "executable_sha256": H, "library_sha256": H, "provenance_sha256": H,
            "tool_sha256": tools, "model_sha256": models,
            "automated_cve_coverage": "not_verified", "cve_assessment": "required",
        }

    native = {"source": "folio-local-elf-provenance-v1", "mode": "experiment",
              "components": [source_component("tesseract"), source_component("poppler")],
              "source_cve_coverage": "unassessed"}
    root = {"/": {"kind": "directory", "mode": "0o755"},
            "/usr/local/bin/clamscan": {"kind": "file", "mode": "0o755", "sha256": H}}
    root.update({path: {"kind": "file", "mode": "0o755", "sha256": H} for path in DENY})
    fs = {"schema": "folio-r148-complete-runtime-filesystem-v1",
          "excluded_top_level": sorted(EXCLUDED_TOP_LEVEL),
          "excluded_docker_injected": sorted(DOCKER_INJECTED),
          "paths": root}
    next_fs = copy.deepcopy(fs)
    for path in DENY:
        del next_fs["paths"][path]

    before_code = [{"path": p, "sha256": hashlib.sha256(p.encode()).hexdigest()}
                   for p in sorted((*CLAM_CODE, *CLAM_REMOVED_CODE))]
    after_code = [copy.deepcopy(row) for row in before_code if row["path"] not in DENY]
    base_clam = {
        "source": "folio-clamav-installed-native-v1",
        "package": "clamav", "package_version": "1.5.5-1",
        "architecture": "amd64", "clamscan_version": "ClamAV 1.5.5",
        "dpkg_verify_clean": True, "shared_library_linked": True,
        "files": before_code, "release_authorized": False,
    }
    new_clam = {
        "source": "folio-clamav-minimal-native-v1",
        "package": "clamav", "package_version": "1.5.5-1",
        "architecture": "amd64", "clamscan_version": "ClamAV 1.5.5",
        "expected_absent": sorted(DENY),
        "dpkg_verified_expected_removals": True, "shared_library_linked": True,
        "files": after_code, "release_authorized": False,
    }
    return [
        scan(BASE), scan(CANDIDATE),
        sbom(BASE, BASE_ID), sbom(CANDIDATE, CANDIDATE_ID),
        image(BASE_ID, "sha256:" + "c" * 64),
        image(CANDIDATE_ID, "sha256:" + "e" * 64),
        copy.deepcopy(native), copy.deepcopy(native),
        fs, next_fs, base_clam, new_clam,
    ]


class CombinedResearchGateTests(unittest.TestCase):
    def test_exact_ten_paths_and_identical_native_cve_sbom_stay_blocked(self):
        result = compare(*fixture())
        self.assertEqual(result["removed_total"], 10)
        self.assertEqual(result["removed_paths"], sorted(DENY))
        self.assertEqual(result["added_paths"], 0)
        self.assertEqual(result["changed_paths"], 0)
        self.assertEqual(result["suid_sgid_after"], 0)
        self.assertEqual(result["clamav_retained_code_after"], 7)
        self.assertEqual(result["cve_counts"], {"CRITICAL": 0, "HIGH": 55, "UNKNOWN": 15})
        self.assertTrue(result["native_model_inventory_equal"])
        self.assertTrue(result["same_trivy_records"])
        self.assertTrue(result["same_sbom"])
        self.assertEqual(result["scanner_gate"], "blocked")
        self.assertFalse(result["release_authorized"])

    def test_unexpected_fs_creation_or_mutation_fails_closed(self):
        for mutation in ("python_pycache", "modified_binary", "unexpected_removed", "suid"):
            values = fixture()
            root = values[9]["paths"]
            if mutation == "python_pycache":
                root["/usr/local/lib/python3.12/__pycache__/argparse.cpython-312.pyc"] = {
                    "kind": "file", "mode": "0o644", "sha256": H}
            elif mutation == "modified_binary":
                root["/usr/local/bin/clamscan"]["sha256"] = DIFFERENT
            elif mutation == "unexpected_removed":
                root.pop("/usr/local/bin/clamscan")
            else:
                root["/usr/local/bin/clamscan"]["mode"] = "0o4755"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                compare(*values)

    def test_image_config_layer_identity_or_architecture_fails_closed(self):
        changes = [
            lambda v: v[5]["Config"].update(User="root"),
            lambda v: v[5]["RootFS"]["Layers"].__setitem__(0, v[4]["RootFS"]["Layers"][0]),
            lambda v: v[5].update(Architecture="arm64"),
            lambda v: v[5].update(Id=BASE_ID),
            lambda v: v[5]["RootFS"]["Layers"].append("sha256:" + "d"*64),
        ]
        for index, change in enumerate(changes):
            values = fixture()
            change(values)
            with self.subTest(case=index), self.assertRaises(ValueError):
                compare(*values)

    def test_native_model_or_source_coverage_change_is_rejected(self):
        values = fixture()
        values[7]["components"][1]["tool_sha256"]["pdfinfo"] = DIFFERENT
        with self.assertRaises(ValueError):
            compare(*values)
        values = fixture()
        values[6]["source_cve_coverage"] = "verified"
        values[7]["source_cve_coverage"] = "verified"
        with self.assertRaises(ValueError):
            compare(*values)

    def test_cve_suppression_or_severity_change_is_rejected(self):
        changes = [
            lambda v: v[1]["Results"][0]["Vulnerabilities"].pop(),
            lambda v: v[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda v: v[1]["Results"].clear(),
            lambda v: v[1].update(ArtifactName="different"),
        ]
        for index, change in enumerate(changes):
            values = fixture()
            change(values)
            with self.subTest(case=index), self.assertRaises(ValueError):
                compare(*values)

    def test_sbom_loss_or_mismatched_digest_is_rejected(self):
        for mutator in (
            lambda v: v[3]["components"].clear(),
            lambda v: v[3]["metadata"]["component"]["properties"][0].update(
                value="sha256:" + "0"*64),
            lambda v: v[3]["components"][0].update(version="1.5.4-1"),
        ):
            values = fixture()
            mutator(values)
            with self.assertRaises(ValueError):
                compare(*values)

    def test_signed_code_or_expected_dpkg_removals_fail_closed(self):
        changes = [
            lambda v: v[11]["files"][0].update(sha256=H),
            lambda v: v[11]["expected_absent"].pop(),
            lambda v: v[11].update(dpkg_verified_expected_removals=False),
            lambda v: v[10].update(dpkg_verify_clean=False),
            lambda v: v[11]["files"].pop(),
        ]
        for index, change in enumerate(changes):
            values = fixture()
            change(values)
            with self.subTest(case=index), self.assertRaises(ValueError):
                compare(*values)

    def test_research_runner_requires_no_network_no_cloud_no_release(self):
        scripts = [
            (ROOT / "apps/inspector/build_combined_cli_r155_research.sh").read_text(),
            (ROOT / "apps/inspector/scan_combined_cli_r155_research.sh").read_text(),
            (ROOT / "apps/inspector/Dockerfile.combined-cli-r155-research").read_text(),
        ]
        self.assertIn("--network=none", scripts[0])
        self.assertIn("--pull=false", scripts[0])
        self.assertIn("-B -I", scripts[2])
        self.assertIn("FROM scratch", scripts[2])
        self.assertIn("--skip-db-update", scripts[1])
        self.assertIn("--cap-drop ALL", scripts[1])
        self.assertIn("combined_cli_prune_r155.py", scripts[1])
        for code in scripts:
            for forbidden in ("docker push", "wrangler deploy", "--ignore-unfixed",
                              "release_authorized=true", "--ignorefile", "docker system prune"):
                self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
