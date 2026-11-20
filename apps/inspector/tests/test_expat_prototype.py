"""TDD guards for an isolated Expat mitigation prototype, never a release."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
IMAGE = "folio-civico-inspector:expat-experiment"
PIN = "b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f"


class ExpatPrototypePolicyTests(unittest.TestCase):
    def test_signed_debian_source_revision_is_pinned_before_compilation(self):
        source = (ROOT / "apps/inspector/Dockerfile.expat-experiment").read_text()
        for token in (
            "FROM debian:trixie-slim AS expat_builder",
            "EXPAT_VERSION=2.10.0",
            PIN,
            "sha256sum --check",
            "EXPAT_DEBIAN_VERSION=2.10.0-1",
            "expat_${EXPAT_DEBIAN_VERSION}.dsc",
            "expat_${EXPAT_DEBIAN_VERSION}.debian.tar.xz",
            "8c4623c101959b8709a3f0a10c06a40d413dc7a6f5ffad3bc9d0cd010d850956",
            "9be65c3ff79ca0508590970422de0a55f117bb7134a0274dd1ed3261f85631dc",
            "dpkg-source -x",
            "dpkg-buildpackage",
            "dpkg -i",
            "dpkg-query -W",
            "https://deb.debian.org/debian/pool/main/e/expat/",
            "EXPAT_BUILD_TOOLS=OFF",
            "EXPAT_BUILD_TESTS=ON",
            "EXPAT_SHARED_LIBS=ON",
            "ctest --test-dir",
            "COPY --from=expat_builder",
            "FROM folio-civico-inspector:poppler-experiment",
            "ldconfig",
            "libexpat.so.1",
            "USER 65534:65534",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        for forbidden in ("--allow-unauthenticated", "apt-get install -t sid",
                          "FROM folio-civico-inspector:validation"):
            self.assertNotIn(forbidden, source)

    def test_manual_runner_is_offline_and_proves_all_parser_linkage(self):
        script = (ROOT / "apps/inspector/build_expat_experiment.sh").read_text()
        for token in (
            "set -euo pipefail",
            "preflight.py --mode build",
            "Dockerfile.expat-experiment",
            IMAGE,
            "poppler-experiment",
            'docker image inspect "$BASE"',
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "XML_ExpatVersion",
            "ldd",
            "smoke_real_engines.py",
            "smoke_http_real.py",
        ):
            with self.subTest(token=token):
                self.assertIn(token, script)
        for forbidden in ("docker push", "--publish", "wrangler deploy",
                          "docker system prune", "apt-get install -t sid"):
            self.assertNotIn(forbidden, script)
        result = subprocess.run(
            ["bash", "apps/inspector/build_expat_experiment.sh", "--bad-flag"],
            cwd=ROOT, timeout=5, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("unsupported_experiment_option", result.stdout)

    def test_experimental_trivy_snapshot_is_never_a_release_gate(self):
        script = (ROOT / "apps/inspector/scan_expat_experiment.sh").read_text()
        for token in ("set -euo pipefail", "folio-civico-inspector:expat-experiment",
                      "trivy image --scanners vuln", "--format json",
                      "docker image inspect", "image_changed_during_scan",
                      "expat_prototype_scan.py"):
            with self.subTest(token=token):
                self.assertIn(token, script)
        for forbidden in ("--ignore-unfixed", "--skip-db-update", "--ignorefile",
                          "docker push", "wrangler deploy"):
            self.assertNotIn(forbidden, script)
        proc = subprocess.run(
            ["bash", "apps/inspector/scan_expat_experiment.sh", "--bad"],
            cwd=ROOT, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(proc.returncode, 3)

    def test_experimental_scan_never_passes_even_when_trivy_counts_are_zero(self):
        import json
        import tempfile
        scan = {
            "ArtifactName": IMAGE, "ArtifactType": "container_image",
            "Results": [{"Target": "debian", "Type": "debian", "Vulnerabilities": []}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            for input_scan, expected_code in (
                (scan, 2), ({**scan, "ArtifactName": "other"}, 3),
                ({**scan, "Results": []}, 3),
            ):
                path.write_text(json.dumps(input_scan))
                proc = subprocess.run(
                    ["python3", "apps/inspector/expat_prototype_scan.py",
                     "--input", str(path), "--image", IMAGE],
                    cwd=ROOT, capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(proc.returncode, expected_code)
                self.assertEqual(json.loads(proc.stdout)["status"],
                                 "blocked" if expected_code == 2 else "error")

    def test_scan_reports_real_package_version_without_waiving_advisories(self):
        import json
        import tempfile
        scan = {
            "ArtifactName": IMAGE, "ArtifactType": "container_image",
            "Results": [{"Target": "debian", "Type": "debian", "Vulnerabilities": [{
                "Severity": "HIGH", "VulnerabilityID": "CVE-2026-113351",
                "PkgName": "libexpat1", "InstalledVersion": "2.10.0-1",
            }]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(json.dumps(scan))
            proc = subprocess.run(
                ["python3", "apps/inspector/expat_prototype_scan.py",
                 "--input", str(path), "--image", IMAGE],
                cwd=ROOT, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(proc.returncode, 2)
            report = json.loads(proc.stdout)
            self.assertEqual(report["expat_installed_version"], "2.10.0-1")
            self.assertEqual(report["expat_high"], 1)
            self.assertFalse(report["release_authorized"])

    def test_research_does_not_authorize_release_or_hide_remaining_cves(self):
        report = (ROOT / "docs/SECURITY_EXPAT_PROTOTYPE_2026-11-19.md").read_text()
        for token in (
            "CVE-2026-113351", "CVE-2026-115506", "CVE-2026-117610",
            "CVE-2026-118370", "CVE-2026-124317", "CVE-2026-128241",
            "NO AUTORIZA", "sin VEX", "gate", "2.10.0",
        ):
            with self.subTest(token=token):
                self.assertIn(token, report)


if __name__ == "__main__":
    unittest.main()
