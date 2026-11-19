import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def parse_jsonc(path: Path) -> dict:
    # Our checked-in Wrangler examples use full-line comments only.
    raw = "\n".join(
        line for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("//")
    )
    return json.loads(raw)


class DeploymentActivationGates(unittest.TestCase):
    def test_standard_configs_cannot_allocate_containers_or_queues(self):
        for relative in (
            "apps/api/wrangler.jsonc",
            "apps/processor/wrangler.jsonc",
            "apps/inspector-gateway/wrangler.jsonc"
        ):
            with self.subTest(path=relative):
                config = parse_jsonc(ROOT / relative)
                self.assertFalse(config.get("workers_dev", True))
                self.assertFalse(config.get("preview_urls", True))
                for key in ("containers", "durable_objects", "exports",
                            "queues", "triggers", "services"):
                    self.assertNotIn(key, config)
                self.assertNotIn("INSPECTOR_HMAC_KEY", config.get("vars", {}))

    def test_approved_template_is_private_and_references_exact_docker_build_context(self):
        directory = ROOT / "apps" / "inspector-gateway"
        config = parse_jsonc(directory / "wrangler.container.example.jsonc")
        self.assertFalse(config["workers_dev"])
        self.assertFalse(config["preview_urls"])
        self.assertEqual(config["containers"][0]["class_name"], "InspectorContainer")
        self.assertEqual(config["containers"][0]["scheduling_policy"], "durable_object")
        self.assertEqual(config["durable_objects"]["bindings"][0]["name"], "INSPECTOR_CONTAINER")
        self.assertEqual(config["exports"]["InspectorContainer"]["storage"], "sqlite")
        image = config["containers"][0]["images"]["base"]
        self.assertTrue((directory / image["dockerfile"]).is_file())
        self.assertTrue((directory / image["build_context"]).is_dir())
        self.assertNotIn("vars", config)
        self.assertNotIn("routes", config)

    def test_dockerfile_requires_vendor_signature_and_patched_clamav(self):
        text=(ROOT / "apps/inspector/Dockerfile").read_text(encoding="utf-8")
        for value in (
            "ARG CLAMAV_VERSION=1.5.5",
            "clamav-${CLAMAV_VERSION}.linux.x86_64.deb",
            "clamav-${CLAMAV_VERSION}.linux.x86_64.deb.sig",
            "5BADCA2665EF59DCF8A23D8B707F0DB480836771",
            "gpg", "--verify", "verify_clamav_version",
        ):
            with self.subTest(value=value):
                self.assertIn(value,text)
        self.assertNotIn("clamav-freshclam qpdf",text)
        self.assertLess(text.index("--verify"),text.index("dpkg -i"))
        self.assertIn("5BADCA2665EF59DCF8A23D8B707F0DB480836771",text)

    def test_local_real_engine_runner_requires_preflight_and_is_offline(self):
        runner=(ROOT / "apps/inspector/validate_real_engines.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("set -euo pipefail", runner)
        preflight=runner.index("python3 apps/inspector/preflight.py --mode build")
        build=runner.index("docker build")
        run=runner.index("docker run")
        self.assertLess(preflight, build)
        self.assertLess(build, run)
        for expected in ("--network none", "--read-only", "--cap-drop ALL",
                         "--security-opt no-new-privileges", "--memory 4g",
                         "--memory-swap 4g", "--tmpfs /tmp:", "--rm"):
            with self.subTest(flag=expected):
                self.assertIn(expected, runner)
        self.assertNotIn("--publish", runner)
        self.assertNotIn("docker system prune", runner)
        dockerfile=(ROOT / "apps/inspector/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("--datadir=/opt/clamdb", dockerfile)
        self.assertIn("smoke_real_engines.py", dockerfile)
        self.assertIn("fixtures.py", dockerfile)
        self.assertIn("smoke_http_real.py", dockerfile)
        self.assertEqual(runner.count("--network none"), 2)
        self.assertIn("/srv/folio-inspector/smoke_http_real.py", runner)

    def test_private_container_process_never_receives_hmac_signing_key(self):
        source=(ROOT / "apps/inspector-gateway/src/index.ts").read_text(encoding="utf-8")
        self.assertIn('FOLIO_INSPECTOR_OUTPUT_MODE:"unsigned"', source)
        self.assertNotIn('FOLIO_INSPECTOR_HMAC_KEY:', source)
        self.assertIn('enableInternet:false', source)


if __name__ == "__main__":
    unittest.main()
