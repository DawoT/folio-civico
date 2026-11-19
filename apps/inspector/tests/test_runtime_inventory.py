"""Contract tests for local-only native dependency inventory."""
from pathlib import Path
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtime_inventory


class RuntimeInventoryTests(unittest.TestCase):
    def test_installed_package_ownership_uses_real_and_original_paths(self):
        def run(argv, **_kwargs):
            self.assertEqual(argv[:2], ["dpkg-query", "-S"])
            if argv[2].endswith("/real/libfoo.so"):
                return subprocess.CompletedProcess(argv, 1, stdout="")
            return subprocess.CompletedProcess(argv, 0, stdout="libfoo:amd64: " + argv[2] + "\n")

        with patch.object(runtime_inventory.os.path, "realpath",
                          return_value="/usr/lib/real/libfoo.so"), \
             patch.object(runtime_inventory.subprocess, "run", side_effect=run):
            self.assertEqual(runtime_inventory.installed_owner("/usr/lib/libfoo.so"),
                             "libfoo")

    def test_real_engines_include_executable_and_dynamic_library_owners(self):
        def runner(argv, **_kwargs):
            self.assertEqual(argv[0], "ldd")
            data = (
                "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x123)\n"
                + ("libxml2.so.2 => /lib/x86_64-linux-gnu/libxml2.so.2 (0x456)\n"
                   if argv[1].endswith("tesseract") else "")
            )
            return subprocess.CompletedProcess(argv, 0, stdout=data)
        def owner(path):
            if path.endswith("libc.so.6"):
                return "libc6"
            if path.endswith("libxml2.so.2"):
                return "libxml2"
            if path.endswith("tesseract"):
                return "tesseract-ocr"
            return "test-engine"

        with patch.object(runtime_inventory.shutil, "which",
                          side_effect=lambda name: "/usr/bin/" + name), \
             patch.object(runtime_inventory.subprocess, "run", side_effect=runner), \
             patch.object(runtime_inventory, "installed_owner", side_effect=owner):
            report = runtime_inventory.inventory()

        self.assertEqual(report["source"], "ldd-dpkg-query")
        self.assertEqual(set(report["engines"]), set(runtime_inventory.ENGINE_NAMES))
        self.assertEqual(report["engines"]["tesseract"],
                         ["libc6", "libxml2", "tesseract-ocr"])
        self.assertEqual(report["unmapped_libraries"], {})
        self.assertNotIn("/usr/bin", json.dumps(report))

    def test_unmapped_libraries_are_counted_not_dismissed(self):
        def runner(argv, **_kwargs):
            return subprocess.CompletedProcess(
                argv, 0,
                stdout="libprivate.so => /usr/lib/libprivate.so (0x123)\n"
            )
        with patch.object(runtime_inventory.shutil, "which",
                          side_effect=lambda name: "/usr/bin/" + name), \
             patch.object(runtime_inventory.subprocess, "run", side_effect=runner), \
             patch.object(runtime_inventory, "installed_owner",
                          side_effect=lambda p: "test-engine" if p.startswith("/usr/bin/") else None):
            report = runtime_inventory.inventory()
        self.assertTrue(all(n == 1 for n in report["unmapped_libraries"].values()))

    def test_missing_engine_and_unresolved_elf_dependency_fail_closed(self):
        with patch.object(runtime_inventory.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "engine missing"):
                runtime_inventory.inventory()
        with patch.object(runtime_inventory.shutil, "which", return_value="/usr/bin/fake"), \
             patch.object(runtime_inventory.subprocess, "run",
                          return_value=subprocess.CompletedProcess(
                              ["ldd"], 0, stdout="libsecret.so => not found\n")):
            with self.assertRaisesRegex(RuntimeError, "native libraries unavailable"):
                runtime_inventory.inventory()

    def test_main_emits_only_error_reason_not_private_paths(self):
        with patch.object(runtime_inventory, "inventory",
                          side_effect=RuntimeError("/tmp/private-original.pdf")), \
             patch("builtins.print") as emitted:
            self.assertEqual(runtime_inventory.main(), 3)
            self.assertEqual(json.loads(emitted.call_args.args[0]), {
                "status": "error", "reason": "runtime_inventory_unavailable"
            })


if __name__ == "__main__":
    unittest.main()
