"""R1.45: flattened GnuPG pruning must preserve every unrelated byte identity."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps" / "inspector"))

from test_runtime_pruning import fixtures as existing_fixtures
from test_advisory_inventory import source_inventory as native_fixture
from gnupg_flat_prune_comparison import (
    BASE, CANDIDATE, PINNED_BASE_ID, EMPTY_LAYER, compare_flat_prune,
)


def evidence():
    rows = list(copy.deepcopy(existing_fixtures()))
    rows[0]["ArtifactName"] = BASE
    rows[1]["ArtifactName"] = CANDIDATE
    rows[2]["metadata"]["component"]["name"] = BASE
    rows[3]["metadata"]["component"]["name"] = CANDIDATE
    before_id = PINNED_BASE_ID
    after_id = "sha256:" + "b" * 64
    rows[2]["metadata"]["component"]["properties"][0]["value"] = before_id
    rows[3]["metadata"]["component"]["properties"][0]["value"] = after_id
    rows[4:6] = [before_id, after_id]
    config = {
        "User": "65534:65534",
        "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
        "Entrypoint": None, "WorkingDir": "/srv/folio-inspector",
        "Env": ["PATH=/opt/folio-poppler/bin:/opt/folio-ocr/bin"],
        "ExposedPorts": {"8789/tcp": {}},
    }
    old = {"Id": before_id, "RootFS": {"Type": "layers", "Layers": [
        "sha256:" + "c" * 64, EMPTY_LAYER]}, "Config": config}
    new = copy.deepcopy(old)
    new["Id"] = after_id
    new["RootFS"]["Layers"][0] = "sha256:" + "d" * 64
    native = native_fixture()
    return [*rows, old, new, native, copy.deepcopy(native)]


class GnupgFlatPruneTests(unittest.TestCase):
    def test_only_disallowed_gnupg_packages_disappear_and_release_stays_blocked(self):
        report = compare_flat_prune(*evidence())
        self.assertEqual(report["source_image_id"], PINNED_BASE_ID)
        self.assertEqual(report["removed_high"], 7)
        self.assertEqual(report["high_after"], 1)
        self.assertEqual(report["unknown_after"], 1)
        self.assertEqual(report["source_elf_identity"], "unchanged")
        self.assertEqual(report["nonempty_base_layers_reused"], 0)
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["scanner_gate"], "blocked")

    def test_altered_elf_or_ocr_models_are_rejected(self):
        for change in (
            lambda e: e[9]["components"][0].update(library_sha256="f" * 64),
            lambda e: e[9]["components"][1]["tool_sha256"].update(pdfinfo="f" * 64),
            lambda e: e[9]["components"][0]["model_sha256"].update(eng="f" * 64),
            lambda e: e[8]["components"].clear(),
        ):
            with self.subTest(change=change):
                data = evidence()
                change(data)
                with self.assertRaises(ValueError):
                    compare_flat_prune(*data)

    def test_image_metadata_and_layers_are_bound_to_immutable_ids(self):
        changes = (
            lambda e: e[6].update(Id="sha256:" + "f" * 64),
            lambda e: e[7]["Config"].update(User="root"),
            lambda e: e[7]["Config"]["Cmd"].append("--unsafe"),
            lambda e: e[7]["RootFS"]["Layers"].__setitem__(0, e[6]["RootFS"]["Layers"][0]),
            lambda e: e[7]["RootFS"]["Layers"].append("sha256:" + "e" * 64),
            lambda e: e[7]["RootFS"].update(Type="overlay"),
        )
        for change in changes:
            data = evidence()
            change(data)
            with self.subTest(change=change), self.assertRaises(ValueError):
                compare_flat_prune(*data)

    def test_extra_removed_package_or_introduced_cve_fails_closed(self):
        data = evidence()
        data[3]["components"].pop(-2)
        with self.assertRaises(ValueError):
            compare_flat_prune(*data)
        data = evidence()
        data[1]["Results"][0]["Vulnerabilities"].append({
            "PkgName": "clamav", "InstalledVersion": "1.5.5-1",
            "VulnerabilityID": "CVE-2026-NEW", "Severity": "HIGH",
        })
        with self.assertRaises(ValueError):
            compare_flat_prune(*data)

    def test_cli_valid_evidence_exits_two_and_corruption_exits_three(self):
        rows = evidence()
        names = (
            "before-scan", "after-scan", "before-sbom", "after-sbom",
            "before-inspect", "after-inspect", "before-native", "after-native",
        )
        with tempfile.TemporaryDirectory() as directory:
            cmd = [sys.executable, "apps/inspector/gnupg_flat_prune_comparison.py"]
            paths = {}
            for index, name in enumerate(names):
                path = Path(directory) / (name + ".json")
                path.write_text(json.dumps(rows[index if index < 4 else index + 2]))
                paths[name] = path
                cmd.extend(("--" + name, str(path)))
            cmd.extend(("--before-id", rows[4], "--after-id", rows[5]))
            passed = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(passed.returncode, 2, passed.stderr)
            self.assertFalse(json.loads(passed.stdout)["release_authorized"])
            paths["after-sbom"].write_text("{}")
            refused = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(refused.returncode, 3)
            self.assertEqual(json.loads(refused.stdout)["status"], "error")

    def test_scripts_never_push_or_deploy_and_reject_options(self):
        scripts = ("build_gnupg_flat_research.sh", "scan_gnupg_flat_research.sh")
        for name in scripts:
            code = (ROOT / "apps/inspector" / name).read_text()
            self.assertIn("set -euo pipefail", code)
            self.assertIn("a68bce319afff0a0f50d50f5a717e077061dbe1eb93c9465910d7f002ba23f18", code)
            self.assertIn("docker image inspect", code)
            self.assertIn("--network none", code)
            self.assertIn("--read-only", code)
            self.assertIn("--cap-drop ALL", code)
            executable = "\n".join(
                line for line in code.splitlines()
                if not line.lstrip().startswith("#")
            )
            for forbidden in ("--ignore-unfixed", "--ignorefile", "docker push", "wrangler deploy", "docker system prune"):
                self.assertNotIn(forbidden, executable)
            invalid = subprocess.run(
                ["bash", "apps/inspector/" + name, "--bad"], cwd=ROOT,
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(invalid.returncode, 3)
        scanner = (ROOT / "apps/inspector/scan_gnupg_flat_research.sh").read_text()
        self.assertIn("--download-db-only", scanner)
        self.assertIn("--skip-db-update", scanner)
        self.assertIn("gnupg_flat_prune_comparison.py", scanner)
        builder = (ROOT / "apps/inspector/build_gnupg_flat_research.sh").read_text()
        self.assertIn("smoke_real_engines.py", builder)
        self.assertIn("smoke_http_real.py", builder)
        self.assertIn("smoke_signature_freshness.py", builder)

    def test_build_is_held_to_source_digest_and_never_authorizes_release(self):
        dockerfile = (ROOT / "apps/inspector/Dockerfile.gnupg-prune-research").read_text()
        self.assertIn("FROM scratch", dockerfile)
        self.assertIn("COPY --from=pruner / /", dockerfile)
        self.assertIn("apt-get -s purge", dockerfile)
        self.assertIn("gnupg gnupg-l10n gpg", dockerfile)
        self.assertIn("libgpgme11t64", dockerfile)
        self.assertIn("libgpgmepp6t64", dockerfile)
        self.assertIn("ClamAV 1.5.5", dockerfile)
        for forbidden in (
            "apt-get autoremove", "--ignore-unfixed", "--ignorefile",
            "docker push", "wrangler deploy", "--allow-remove-essential",
        ):
            self.assertNotIn(forbidden, dockerfile)


if __name__ == "__main__":
    unittest.main()
