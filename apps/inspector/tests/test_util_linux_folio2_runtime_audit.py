"""R1.47 TDD: unsigned folio2 integration never hides or waives Debian CVEs."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps" / "inspector"))

from test_advisory_inventory import source_inventory as native_fixture
from util_linux_folio2_binary import SOURCE_HASHES, SOURCE_VERSION
from util_linux_folio2_runtime_audit import (
    BASE, NEW, EXPECTED_VERSIONS, CVES, BASE_ID, EMPTY_LAYER,
    compare_folio2_runtime,
)


def fixture():
    before_id = BASE_ID
    after_id = "sha256:" + "b" * 64
    pkgs = list(EXPECTED_VERSIONS)
    before_versions = {
        name: (
            "1:4.16.0-2+really2.41.5-0+deb13u1" if name == "login" else
            "1:2.41.5-0+deb13u1" if name == "bsdutils" else
            "2.41.5-0+deb13u1"
        )
        for name in pkgs
    }
    def sbom(tag, digest, versions):
        comps = [
            {
                "type": "library", "name": name, "version": version,
                "purl": (
                    "pkg:deb/debian/" + name + "@" +
                    quote(version.split(":")[-1], safe="~") +
                    "?arch=amd64&distro=debian-13.7" +
                    ("&epoch=1" if version.startswith("1:") else "")
                ),
            }
            for name, version in versions.items()
        ]
        comps.extend([
            {"type": "library", "name": "clamav", "version": "1.5.5",
             "purl": "pkg:deb/debian/clamav@1.5.5?arch=amd64"},
            {"type": "operating-system", "name": "debian", "version": "13.7"},
        ])
        return {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"type": "container", "name": tag,
                "properties": [{"name": "aquasecurity:trivy:ImageID", "value": digest}]}},
            "components": comps,
        }
    def scan(tag, versions):
        rows = [
            {
                "PkgName": pkg, "InstalledVersion": ver,
                "VulnerabilityID": cve, "Severity": "HIGH",
            }
            for pkg, ver in versions.items() for cve in CVES
        ]
        rows.append({
            "PkgName": "clamav", "InstalledVersion": "1.5.5",
            "VulnerabilityID": "CVE-2026-LOCAL-TEST", "Severity": "UNKNOWN",
        })
        return {
            "ArtifactName": tag, "ArtifactType": "container_image",
            "Results": [{"Type": "debian", "Target": "Debian 13.7",
                         "Vulnerabilities": rows}],
        }
    cfg = {
        "User": "65534:65534",
        "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
        "Entrypoint": None, "WorkingDir": "/srv/folio-inspector",
        "Env": ["PATH=/opt/folio-poppler/bin:/opt/folio-ocr/bin"],
        "ExposedPorts": {"8789/tcp": {}},
    }
    def inspect(image_id, layer):
        return {
            "Id": image_id, "Config": copy.deepcopy(cfg),
            "RootFS": {"Type": "layers", "Layers": [layer, EMPTY_LAYER]},
        }
    source = {
        "source_version": SOURCE_VERSION,
        "source_handoff_validated": True,
        "source_sha256": dict(SOURCE_HASHES),
        "source_cve_paths_accounted_for": True,
        "unresolved_cve_paths": [],
        "source_scope_not_applicable": ["CVE-2026-78409"],
        "cve_guard_results": {
            name: {"source_guard_present": name != "CVE-2026-78409",
                   **({
                       "applicability": "not_affected_detached_fast_path_absent",
                       "legacy_restricted_user_path_rejected": True,
                       "affected_detached_fast_path_present": False,
                   } if name == "CVE-2026-78409" else {})}
            for name in CVES
        },
        "runtime_cve_regressions_passed": False,
        "cve_remediated": False,
        "release_authorized": False,
    }
    native = native_fixture()
    privilege = {"/usr/bin/su": "0o4755", "/usr/bin/chfn": "0o4755"}
    return [
        scan(BASE, before_versions), scan(NEW, EXPECTED_VERSIONS),
        sbom(BASE, before_id, before_versions),
        sbom(NEW, after_id, EXPECTED_VERSIONS),
        before_id, after_id,
        inspect(before_id, "sha256:" + "c" * 64),
        inspect(after_id, "sha256:" + "d" * 64),
        native, copy.deepcopy(native), source,
        privilege, copy.deepcopy(privilege),
    ]


class Folio2RuntimeTests(unittest.TestCase):
    def test_exact_eight_upgrades_and_all_four_cves_still_block_release(self):
        report = compare_folio2_runtime(*fixture())
        self.assertEqual(report["updated_package_count"], 8)
        self.assertEqual(report["util_high_before"], 32)
        self.assertEqual(report["util_high_after"], 32)
        self.assertEqual(report["high_after"], 32)
        self.assertEqual(report["unknown_after"], 1)
        self.assertEqual(report["nonempty_base_layers_reused"], 0)
        self.assertEqual(report["source_elf_identity"], "unchanged")
        self.assertEqual(report["new_privileged_paths"], 0)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["cve_remediated"])
        self.assertEqual(report["scanner_gate"], "blocked")

    def test_fails_on_missing_or_altered_cve_evidence(self):
        cases = [
            lambda a: a[1]["Results"][0]["Vulnerabilities"].pop(0),
            lambda a: a[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda a: a[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "clamav", "InstalledVersion": "1.5.5",
                "VulnerabilityID": "CVE-2026-ADDED", "Severity": "HIGH",
            }),
            lambda a: a[3]["components"].pop(-2),
            lambda a: a[3]["components"][0].update(version="2.41.5"),
            lambda a: a[3]["components"][0].update(purl="pkg:deb/unknown/x@2.41.6"),
            lambda a: a[2]["metadata"]["component"]["properties"][0].update(value="wrong"),
        ]
        for change in cases:
            a = fixture()
            change(a)
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                compare_folio2_runtime(*a)

    def test_rejects_bad_source_guard_or_unsigned_provenance_confusion(self):
        cases = [
            lambda a: a[10].update(source_handoff_validated=False),
            lambda a: a[10].update(source_sha256={}),
            lambda a: a[10].update(source_cve_paths_accounted_for=False),
            lambda a: a[10].update(unresolved_cve_paths=["CVE-2026-78410"]),
            lambda a: a[10]["cve_guard_results"]["CVE-2026-78408"].update(source_guard_present=False),
            lambda a: a[10]["cve_guard_results"]["CVE-2026-78409"].update(applicability="unresolved"),
            lambda a: a[10]["cve_guard_results"]["CVE-2026-78409"].pop("legacy_restricted_user_path_rejected"),
            lambda a: a[10]["cve_guard_results"]["CVE-2026-78409"].update(affected_detached_fast_path_present=True),
            lambda a: a[10].update(release_authorized=True),
            lambda a: a[10].update(cve_remediated=True),
        ]
        for change in cases:
            a = fixture()
            change(a)
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                compare_folio2_runtime(*a)

    def test_rejects_new_privileges_or_changed_native_engines(self):
        cases = [
            lambda a: a[12].update({"/usr/bin/new-helper": "0o4755"}),
            lambda a: a[12].update({"/usr/bin/su": "0o0755"}),
            lambda a: a[9]["components"][0].update(library_sha256="f" * 64),
            lambda a: a[7]["Config"].update(User="0:0"),
            lambda a: a[7]["RootFS"]["Layers"].__setitem__(0, a[6]["RootFS"]["Layers"][0]),
            lambda a: a[7].update(Id="sha256:" + "f" * 64),
        ]
        for change in cases:
            a = fixture()
            change(a)
            with self.subTest(change=change), self.assertRaises(ValueError):
                compare_folio2_runtime(*a)

    def test_cli_good_evidence_is_exit_two_tampered_exit_three(self):
        rows = fixture()
        fields = ("before-scan", "after-scan", "before-sbom", "after-sbom",
                  "before-inspect", "after-inspect", "before-native",
                  "after-native", "source-report", "before-privileges",
                  "after-privileges")
        with tempfile.TemporaryDirectory() as d:
            cmd = [sys.executable, "apps/inspector/util_linux_folio2_runtime_audit.py"]
            paths = {}
            for index, field in enumerate(fields):
                item = Path(d) / (field + ".json")
                item.write_text(json.dumps(rows[index if index < 4 else index + 2]))
                paths[field] = item
                cmd.extend(("--" + field, str(item)))
            cmd.extend(("--before-id", rows[4], "--after-id", rows[5]))
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertFalse(json.loads(p.stdout)["release_authorized"])
            paths["after-native"].write_text("{}")
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 3)
            self.assertFalse(json.loads(p.stdout)["release_authorized"])

    def test_scripts_enforce_immutable_offline_research_and_no_waiver(self):
        dockerfile = (
            ROOT / "apps/inspector/Dockerfile.util-linux-folio2-runtime-research"
        ).read_text()
        for phrase in (
            "FROM scratch", "COPY --from=installer / /",
            "COPY --from=folio2_debs", "sha256sum --check",
            "dpkg --audit", "libblkid1",
        ):
            self.assertIn(phrase, dockerfile)
        self.assertLess(dockerfile.index("dpkg --install --force-confold /tmp/folio2/lib*.deb"),
                        dockerfile.index("dpkg --install --force-confold /tmp/folio2/bsdutils*.deb"))
        for forbidden in (
            "apt-get autoremove", "--force-depends", "apt-get -f install",
            "docker push", "wrangler deploy", "--allow-remove-essential",
        ):
            self.assertNotIn(forbidden, dockerfile)

        scripts = (
            "build_util_linux_folio2_runtime_research.sh",
            "scan_util_linux_folio2_runtime_research.sh",
            "compare_util_linux_folio2_quality.sh",
        )
        for script in scripts:
            content = (ROOT / "apps/inspector" / script).read_text()
            self.assertIn("set -euo pipefail", content)
            self.assertIn(BASE_ID, content)
            executable = "\n".join(
                row for row in content.splitlines()
                if not row.lstrip().startswith("#")
            )
            for forbidden in (
                "docker push", "wrangler deploy", "docker system prune",
                "--ignore-unfixed", "--ignorefile", "--force-depends",
            ):
                self.assertNotIn(forbidden, executable)
            invalid = subprocess.run(
                ["bash", "apps/inspector/" + script, "--bad"],
                cwd=ROOT, capture_output=True, text=True, timeout=8,
            )
            self.assertEqual(invalid.returncode, 3)



if __name__ == "__main__":
    unittest.main()
