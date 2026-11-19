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

    def test_private_container_process_never_receives_hmac_signing_key(self):
        source=(ROOT / "apps/inspector-gateway/src/index.ts").read_text(encoding="utf-8")
        self.assertIn('FOLIO_INSPECTOR_OUTPUT_MODE:"unsigned"', source)
        self.assertNotIn('FOLIO_INSPECTOR_HMAC_KEY:', source)
        self.assertIn('enableInternet:false', source)


if __name__ == "__main__":
    unittest.main()
