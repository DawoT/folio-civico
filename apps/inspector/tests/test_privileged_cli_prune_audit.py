"""R1.48: adversarial fixture tests against unsafe CVE/OCI/file evidence."""
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
sys.path.insert(0, str(ROOT / "apps" / "inspector" / "tests"))

from test_util_linux_folio2_runtime_audit import fixture
from privileged_cli_prune_audit import (
    BASE, CANDIDATE, PINNED_BASE_ID, SUID_SGID_MODES,
    NON_PRIVILEGED_CLI, SYMLINK, REMOVED, compare_privileged_cli_prune,
)
from runtime_executable_surface_inventory import (
    EXCLUDED_TOP_LEVEL, DOCKER_INJECTED, snapshot,
)


def evidence():
    row = fixture()
    a_scan = copy.deepcopy(row[1])
    a_sbom = copy.deepcopy(row[3])
    a_inspect = copy.deepcopy(row[7])
    native = copy.deepcopy(row[8])
    candidate_id = "sha256:" + "e" * 64
    a_inspect["Id"] = PINNED_BASE_ID
    a_inspect["RootFS"]["Layers"] = [
        "sha256:" + "a" * 64, "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
    ]
    a_sbom["metadata"]["component"]["name"] = BASE
    a_sbom["metadata"]["component"]["properties"][0]["value"] = PINNED_BASE_ID
    a_scan["ArtifactName"] = BASE
    b_scan = copy.deepcopy(a_scan)
    b_scan["ArtifactName"] = CANDIDATE
    b_sbom = copy.deepcopy(a_sbom)
    b_sbom["metadata"]["component"]["name"] = CANDIDATE
    b_sbom["metadata"]["component"]["properties"][0]["value"] = candidate_id
    b_inspect = copy.deepcopy(a_inspect)
    b_inspect["Id"] = candidate_id
    b_inspect["RootFS"]["Layers"][0] = "sha256:" + "b" * 64
    paths = {
        "/": {"kind": "directory", "mode": "0o755"},
        "/usr": {"kind": "directory", "mode": "0o755"},
        "/usr/bin": {"kind": "directory", "mode": "0o755"},
        "/usr/sbin": {"kind": "directory", "mode": "0o755"},
        "/srv": {"kind": "directory", "mode": "0o755"},
        "/srv/folio-inspector": {"kind": "directory", "mode": "0o755"},
        "/srv/folio-inspector/inspector.py": {
            "kind": "file", "mode": "0o644", "sha256": "9" * 64,
        },
    }
    for path, mode in SUID_SGID_MODES.items():
        paths[path] = {"kind": "file", "mode": mode, "sha256": "4" * 64}
    for path in NON_PRIVILEGED_CLI:
        paths[path] = {"kind": "file", "mode": "0o755", "sha256": "5" * 64}
    paths[SYMLINK] = {"kind": "symlink", "mode": "0o777", "target": "newgrp"}
    def manifest(files):
        return {
            "schema": "folio-r148-complete-runtime-filesystem-v1",
            "excluded_top_level": sorted(EXCLUDED_TOP_LEVEL),
            "excluded_docker_injected": sorted(DOCKER_INJECTED),
            "paths": files,
        }
    return [
        a_scan, b_scan, a_sbom, b_sbom, a_inspect, b_inspect,
        native, copy.deepcopy(native), manifest(paths),
        manifest({k: copy.deepcopy(v) for k, v in paths.items() if k not in REMOVED}),
        PINNED_BASE_ID, candidate_id,
    ]


class PrivilegedCLIReductionTests(unittest.TestCase):
    def test_valid_prune_removes_only_fifteen_and_keeps_all_cve(self):
        outcome = compare_privileged_cli_prune(*evidence())
        self.assertEqual(outcome["removed_entrypoint_count"], 15)
        self.assertEqual(outcome["removed_suid_sgid_regular_files"], 9)
        self.assertEqual(outcome["remaining_suid_sgid_regular_files"], 0)
        self.assertEqual(outcome["util_linux_high_after"], 32)
        self.assertFalse(outcome["cve_remediated"])
        self.assertFalse(outcome["release_authorized"])
        self.assertEqual(outcome["scanner_gate"], "blocked")

    def test_rejects_missing_reintroduced_or_modified_files(self):
        cases = [
            lambda a: a[9]["paths"].__setitem__(
                "/usr/bin/nsenter", copy.deepcopy(a[8]["paths"]["/usr/bin/nsenter"])
            ),
            lambda a: a[8]["paths"].pop("/usr/bin/unshare"),
            lambda a: a[9]["paths"].update({
                "/usr/bin/unexpected": {"kind": "file", "mode": "0o755", "sha256": "7" * 64}
            }),
            lambda a: a[9]["paths"]["/srv/folio-inspector/inspector.py"].update(
                sha256="7" * 64
            ),
            lambda a: a[8]["paths"]["/usr/bin/su"].update(mode="0o0755"),
            lambda a: a[8]["paths"]["/usr/bin/sg"].update(target="passwd"),
            lambda a: a[8]["paths"]["/usr/bin/expiry"].update(mode="0o4755"),
            lambda a: a[9]["paths"]["/srv/folio-inspector/inspector.py"].update(
                mode="0o4755"
            ),
            lambda a: a[8].update(excluded_top_level=["/"]),
            lambda a: a[9]["paths"]["/srv/folio-inspector/inspector.py"].pop(
                "sha256"
            ),
        ]
        for change in cases:
            rows = evidence()
            change(rows)
            with self.subTest(case=change), self.assertRaises((ValueError, TypeError)):
                compare_privileged_cli_prune(*rows)

    def test_rejects_scanner_cve_and_package_tampering(self):
        cases = [
            lambda a: a[1]["Results"][0]["Vulnerabilities"].pop(0),
            lambda a: a[1]["Results"][0]["Vulnerabilities"][0].update(
                Severity="LOW"
            ),
            lambda a: a[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "clamav", "InstalledVersion": "1.5.5",
                "VulnerabilityID": "CVE-2026-EXTRA", "Severity": "HIGH",
            }),
            lambda a: a[3]["components"].pop(-2),
            lambda a: a[3]["components"][0].update(version="2.41.5"),
            lambda a: a[3]["metadata"]["component"]["properties"][0].update(
                value="wrong"
            ),
        ]
        for change in cases:
            rows = evidence()
            change(rows)
            with self.subTest(case=change), self.assertRaises((ValueError, TypeError)):
                compare_privileged_cli_prune(*rows)

    def test_rejects_image_config_layer_native_tamper(self):
        cases = [
            lambda a: a[5]["Config"].update(User="0:0"),
            lambda a: a[5]["RootFS"]["Layers"].__setitem__(
                0, a[4]["RootFS"]["Layers"][0]
            ),
            lambda a: a[5].update(Id="sha256:" + "f" * 64),
            lambda a: a[7]["components"][0].update(sha256="f" * 64),
        ]
        for change in cases:
            rows = evidence()
            change(rows)
            with self.subTest(case=change), self.assertRaises(ValueError):
                compare_privileged_cli_prune(*rows)
        rows = evidence()
        rows[10] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            compare_privileged_cli_prune(*rows)

    def test_cli_returns_two_for_valid_and_three_for_tamper(self):
        rows = evidence()
        keys = (
            "before-scan", "after-scan", "before-sbom", "after-sbom",
            "before-inspect", "after-inspect", "before-native", "after-native",
            "before-fs", "after-fs",
        )
        with tempfile.TemporaryDirectory() as d:
            cli = [sys.executable, "apps/inspector/privileged_cli_prune_audit.py"]
            files = {}
            for index, name in enumerate(keys):
                p = Path(d) / (name + ".json")
                p.write_text(json.dumps(rows[index]))
                cli.extend(("--" + name, str(p)))
                files[name] = p
            cli.extend(("--before-id", rows[10], "--after-id", rows[11]))
            correct = subprocess.run(
                cli, cwd=ROOT, text=True, capture_output=True, timeout=12,
            )
            self.assertEqual(correct.returncode, 2, correct.stderr)
            self.assertFalse(json.loads(correct.stdout)["release_authorized"])
            files["after-fs"].write_text("{}")
            altered = subprocess.run(
                cli, cwd=ROOT, text=True, capture_output=True, timeout=12,
            )
            self.assertEqual(altered.returncode, 3)
            self.assertFalse(json.loads(altered.stdout)["release_authorized"])

    def test_snapshot_hashes_files_symlinks_and_excludes_docker_injections(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "usr/bin").mkdir(parents=True)
            sample = root / "usr/bin/research-command"
            sample.write_bytes(b"only local fixture")
            (root / "usr/bin/shortcut").symlink_to("research-command")
            (root / "etc").mkdir()
            (root / "etc/hosts").write_text("dynamic container entry")
            (root / "tmp").mkdir()
            (root / "tmp/payload").write_bytes(b"temporary")
            result = snapshot(root)
            inventory = result["paths"]
            self.assertEqual(
                inventory["/usr/bin/research-command"]["sha256"],
                hashlib.sha256(b"only local fixture").hexdigest(),
            )
            self.assertEqual(
                inventory["/usr/bin/shortcut"]["target"], "research-command"
            )
            self.assertNotIn("/etc/hosts", inventory)
            self.assertNotIn("/tmp", inventory)
            self.assertNotIn("/tmp/payload", inventory)

    def test_scripts_preserve_security_gate_and_reject_extra_arguments(self):
        dockerfile = (
            ROOT / "apps/inspector/Dockerfile.privileged-cli-research"
        ).read_text()
        self.assertIn("FROM scratch", dockerfile)
        self.assertIn("COPY --from=pruner / /", dockerfile)
        self.assertIn("test ! -e /usr/bin/mount", dockerfile)
        self.assertIn("rm --", dockerfile)
        for name in (
            "build_privileged_cli_research.sh",
            "scan_privileged_cli_research.sh",
            "compare_privileged_cli_quality.sh",
        ):
            content = (ROOT / "apps/inspector" / name).read_text()
            self.assertIn("set -euo pipefail", content)
            self.assertIn(PINNED_BASE_ID, content)
            for unsafe in (
                "--ignore-unfixed", "--ignorefile", "wrangler deploy",
                "docker push", "docker system prune", "--force-depends",
            ):
                self.assertNotIn(unsafe, "\n".join(
                    row for row in content.splitlines()
                    if not row.lstrip().startswith("#")
                ))
            invalid = subprocess.run(
                ["bash", "apps/inspector/" + name, "--unsupported"],
                cwd=ROOT, text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(invalid.returncode, 3)

    def test_snapshot_rejects_a_symlink_as_root(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "not-root"
            path.symlink_to(Path(d))
            with self.assertRaises(ValueError):
                snapshot(path)


if __name__ == "__main__":
    unittest.main()
